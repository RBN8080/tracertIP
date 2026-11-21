using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.System;
using WinRT.Interop;

namespace TracertIP.Desktop;

public sealed partial class MainWindow : Window
{
    private enum View { Live, History, Captures }

    private const string PreferenceFile = "node.txt";
    private readonly string preferences = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "tracertIP");
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(4) };
    private CancellationTokenSource session = new();
    private MonitorApi? api;
    private View view;
    private bool polling, settingTargets;
    private int historyRevision, hopRefresh;
    private string? target, loadedTarget, savedId;
    private Round[] rounds = [];
    private RouteEvent[] events = [];
    private History? history;

    public MainWindow(string? requestedNode)
    {
        InitializeComponent();
        AppWindow.Resize(new Windows.Graphics.SizeInt32(1330, 830));
        timer.Tick += async (_, _) =>
        {
            ShowFreshness();
            await Poll();
        };
        Closed += (_, _) =>
        {
            timer.Stop();
            session.Cancel();
            session.Dispose();
        };
        Root.ActualThemeChanged += (_, _) => DrawCharts();
        SetDates(DateTimeOffset.Now.AddMinutes(-15), DateTimeOffset.Now);
        Node.Text = requestedNode ?? ReadNode();
        Root.Loaded += async (_, _) =>
        {
            timer.Start();
            if (api == null && Node.Text.Length != 0)
                await Connect(remember: requestedNode == null);
        };
    }

    private string ReadNode()
    {
        try
        {
            var file = Path.Combine(preferences, PreferenceFile);
            return File.Exists(file) ? File.ReadAllText(file).Trim() : "";
        }
        catch (IOException) { return ""; }
        catch (UnauthorizedAccessException) { return ""; }
    }

    private async Task Connect(bool remember = true, Uri? current = null)
    {
        var text = current?.GetLeftPart(UriPartial.Authority) ?? Node.Text.Trim();
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")
            || uri.Host.Length == 0 || uri.UserInfo.Length != 0 || uri.AbsolutePath != "/" || uri.Query.Length != 0 || uri.Fragment.Length != 0)
        {
            Message("Escribe la dirección base HTTP o HTTPS del nodo, incluido el puerto si corresponde.");
            return;
        }

        session.Cancel();
        session.Dispose();
        session = new();
        api = new MonitorApi(uri, PublicView.IsChecked == true);
        Node.Text = uri.GetLeftPart(UriPartial.Authority);
        try
        {
            if (remember)
            {
                Directory.CreateDirectory(preferences);
                File.WriteAllText(Path.Combine(preferences, PreferenceFile), Node.Text);
            }
            Message("");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Message("La dirección quedó activa para esta sesión.");
        }

        ++historyRevision;
        target = loadedTarget = savedId = null;
        rounds = [];
        events = [];
        history = null;
        LiveTargets.ItemsSource = null;
        LiveEvents.ItemsSource = null;
        SavedCaptures.ItemsSource = null;
        HistoryTarget.ItemsSource = null;
        HistoryEvents.ItemsSource = null;
        ComparedHops.ItemsSource = null;
        HistorySamples.ItemsSource = null;
        CaptureNote.Text = "";
        Note.Text = "";
        Hops.ItemsSource = null;
        LiveSamples.ItemsSource = null;
        HealthTargets.ItemsSource = null;
        Instrument.Text = "";
        HistoryResult.Visibility = Visibility.Collapsed;
        ConsultButton.IsEnabled = true;
        Connection.Text = "Conectando";
        Origin.Text = api.PublicView ? "Nodo de medición · Vista pública" : "Nodo de medición · " + uri.Authority;
        ShowLive(null);
        await Poll();
        if (view != View.Live)
            await OpenView(view);
    }

    private async Task Poll()
    {
        if (polling || api is not { } client)
            return;
        polling = true;
        var token = session.Token;
        try
        {
            var healthTask = client.Health(token);
            var targetTask = client.Targets(token);
            await Task.WhenAll(healthTask, targetTask);
            if (token.IsCancellationRequested)
                return;

            var health = await healthTask;
            Connection.Text = "En línea";
            ToolTipService.SetToolTip(Connection, null);
            SetTargets((await targetTask).Select(x => x.Address).ToArray());
            ShowHealth(health);
            if (view != View.Live || target is not { } active)
                return;

            var fullWindow = loadedTarget != active || rounds.Length == 0 || DateTimeOffset.UtcNow - rounds[^1].Start > TimeSpan.FromMinutes(2);
            var freshTask = client.Rounds(active, fullWindow ? 900 : 90, token);
            var eventTask = client.Events(token);
            await Task.WhenAll(freshTask, eventTask);
            if (active != target || token.IsCancellationRequested)
                return;
            var fresh = await freshTask;
            rounds = fullWindow ? fresh : rounds.Concat(fresh).DistinctBy(r => (r.Start, r.N)).OrderBy(r => r.Start).TakeLast(900).ToArray();
            events = (await eventTask).Where(e => e.Target == active).OrderBy(e => e.Time).ToArray();
            var changed = loadedTarget != active;
            loadedTarget = active;
            LiveEvents.ItemsSource = events.Reverse().Take(30).ToArray();
            ShowLive(health.Targets.FirstOrDefault(t => t.Target == active));
            if (changed || ++hopRefresh % 3 == 0)
                await RefreshHops(client, active, token);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception ex) when (ex is HttpRequestException or InvalidDataException or System.Text.Json.JsonException or OperationCanceledException)
        {
            if (!token.IsCancellationRequested)
            {
                Connection.Text = "Reconectando";
                if (rounds.Length > 0)
                    LastMeasurement.Text = $"Datos sin actualizar · {rounds[^1].Start.ToLocalTime():HH:mm:ss}";
                ToolTipService.SetToolTip(Connection, ex.Message);
            }
        }
        finally
        {
            polling = false;
        }
    }

    private async Task RefreshHops(MonitorApi client, string active, CancellationToken token)
    {
        try
        {
            var hops = await client.Hops(active, token);
            if (!token.IsCancellationRequested && active == target)
                Hops.ItemsSource = hops.Select(h => h.Label).ToArray();
        }
        catch (HttpRequestException) when (!token.IsCancellationRequested)
        {
            if (active == target)
                Hops.ItemsSource = new[] { "El detalle de los saltos se actualizará al volver a estar disponible." };
        }
    }

    private void SetTargets(string[] items)
    {
        if (LiveTargets.ItemsSource is string[] old && old.SequenceEqual(items))
            return;
        var next = items.Contains(target) ? target : items.FirstOrDefault();
        settingTargets = true;
        LiveTargets.ItemsSource = items;
        LiveTargets.SelectedItem = next;
        settingTargets = false;
        SetTarget(next);
    }

    private void SetTarget(string? next)
    {
        if (target == next)
            return;
        target = next;
        rounds = [];
        events = [];
        loadedTarget = null;
        Hops.ItemsSource = null;
        LiveEvents.ItemsSource = null;
        LiveSamples.ItemsSource = null;
        ShowLive(null);
    }

    private void ShowHealth(HealthView health)
    {
        var node = health.Node;
        Instrument.Text = $"{node.Version} · {(node.ClockSynced ? "Reloj sincronizado" : "Reloj sin sincronizar")}"
            + (node.TempC is double temperature ? $" · {temperature:0.0} °C" : "")
            + (node.DiskFreeMb is long free ? $" · {free / 1024.0:0.0} GiB libres" : "");
        HealthTargets.ItemsSource = health.Targets.Select(t =>
            $"{t.Target} · {Display.HealthState(t.State)}\n{t.Rounds} rondas · {t.Replied} respuestas · {t.NoReply} sin respuesta · {t.SendErrors} sin envío").ToArray();
    }

    private void ShowLive(TargetHealth? health)
    {
        LiveDestination.Text = target ?? "—";
        LiveState.Text = Display.HealthState(health?.State);
        InspectLive.IsEnabled = StopTrace.IsEnabled = target != null;
        var rtts = rounds.Select(r => r.Rtt).OfType<double>().Order().ToArray();
        var sent = rounds.Count(r => r.Sent);
        Median.Text = Display.Rtt(rtts.Length != 0 ? rtts[(rtts.Length - 1) / 2] : null);
        Percentile.Text = "Percentil 95 " + Display.Rtt(rtts.Length >= 59 ? rtts[(95 * rtts.Length + 99) / 100 - 1] : null);
        ReplyRate.Text = sent > 0 ? $"{100.0 * rtts.Length / sent:0} %" : "—";
        ShowFreshness();
        LiveChartSummary.Text = rounds.Length == 0 ? "Las rondas aparecerán al comenzar la medición."
            : $"{rtts.Length} de {sent} rondas con envío respondieron · {rounds.Length - sent} sin envío";
        if (LiveSamples.Parent is Expander { IsExpanded: true })
            LiveSamples.ItemsSource = rounds.Reverse().Select(r => r.Label).ToArray();
        DrawCharts();
    }

    private void ShowFreshness()
    {
        if (rounds.Length == 0)
        {
            LastMeasurement.Text = "Esperando muestras";
            return;
        }
        var last = rounds[^1].Start;
        var label = DateTimeOffset.UtcNow - last > TimeSpan.FromSeconds(15) || Connection.Text != "En línea"
            ? "Datos sin actualizar" : "Última muestra";
        LastMeasurement.Text = $"{label} · {last.ToLocalTime():HH:mm:ss}";
    }

    private async Task OpenView(View next, string? preferred = null)
    {
        view = next;
        LiveTab.IsChecked = next == View.Live;
        HistoryTab.IsChecked = next == View.History;
        CapturesTab.IsChecked = next == View.Captures;
        LivePanel.Visibility = next == View.Live ? Visibility.Visible : Visibility.Collapsed;
        HistoryPanel.Visibility = next == View.History ? Visibility.Visible : Visibility.Collapsed;
        CapturesPanel.Visibility = next == View.Captures ? Visibility.Visible : Visibility.Collapsed;
        PageScroll.ChangeView(null, 0, null, true);
        Message("");
        if (next == View.Live)
        {
            DrawCharts();
            await Poll();
        }
        else if (next == View.History)
        {
            await Run(async (client, token) =>
            {
                var targets = await client.HistoricalTargets(token);
                if (token.IsCancellationRequested || view != next)
                    return;
                var previous = preferred ?? HistoryTarget.SelectedItem as string ?? target;
                if (!client.PublicView)
                    targets = targets.Concat(LiveTargets.ItemsSource as string[] ?? []).Concat(previous == null ? [] : [previous]).Distinct().Order().ToArray();
                HistoryTarget.ItemsSource = targets;
                HistoryTarget.SelectedItem = targets.Contains(previous) ? previous : targets.FirstOrDefault();
            });
            DrawCharts();
        }
        else
        {
            await Run(async (client, token) =>
            {
                var captures = await client.Captures(token);
                if (token.IsCancellationRequested || view != next)
                    return;
                SavedCaptures.ItemsSource = captures;
                if (captures.Length == 0)
                    Message("Aún no hay capturas guardadas en esta vista.");
            });
        }
    }

    private void SetDates(DateTimeOffset from, DateTimeOffset to)
    {
        from = from.ToLocalTime();
        to = to.ToLocalTime();
        FromDate.Date = from.Date;
        ToDate.Date = to.Date;
        FromTime.SelectedTime = from.TimeOfDay;
        ToTime.SelectedTime = to.TimeOfDay;
    }

    private static DateTimeOffset LocalDate(CalendarDatePicker date, TimePicker time)
    {
        if (date.Date is not { } day || time.SelectedTime is not { } clock)
            throw new InvalidDataException("Completa la fecha y la hora del intervalo.");
        var local = day.Date + clock;
        if (TimeZoneInfo.Local.IsInvalidTime(local))
            throw new InvalidDataException("Esa hora local no existe por el cambio de horario.");
        return new DateTimeOffset(local, TimeZoneInfo.Local.GetUtcOffset(local));
    }

    private async Task Inspect(string address, RouteEvent? selected = null)
    {
        var now = DateTimeOffset.Now;
        SetDates(selected?.FirstObserved.AddMinutes(-5) ?? now.AddMinutes(-15), selected?.FirstObserved.AddMinutes(5) ?? now);
        await OpenView(View.History, address);
        if (view == View.History && HistoryTarget.SelectedItem as string == address)
            await Consult(selected);
    }

    private async Task Consult(RouteEvent? selected = null)
    {
        if (HistoryTarget.SelectedItem is not string address)
        {
            Message("Selecciona un destino.");
            return;
        }
        if (api == null)
        {
            Message("Conecta primero con el nodo de medición.");
            return;
        }
        var revision = ++historyRevision;
        ConsultButton.IsEnabled = false;
        Message("Leyendo registros del nodo…");
        await Run(async (client, token) =>
        {
            var from = LocalDate(FromDate, FromTime);
            var to = LocalDate(ToDate, ToTime);
            if (to <= from || to - from > TimeSpan.FromHours(1))
                throw new InvalidDataException("Elige un intervalo de hasta 60 minutos.");
            var data = await client.Read(new Query(address, from, to), token);
            if (token.IsCancellationRequested || revision != historyRevision || view != View.History)
                return;
            ShowHistory(data, selected: selected);
            Message(data.Rounds.Length + data.Events.Length == 0 ? "Sin registros en ese intervalo. Revisa la fecha o la retención." : "");
        }, clear: false);
        if (revision == historyRevision)
            ConsultButton.IsEnabled = true;
    }

    private void ShowHistory(History data, string? id = null, string? note = null, RouteEvent? selected = null)
    {
        history = data;
        savedId = id;
        HistoryResult.Visibility = Visibility.Visible;
        HistoryLabel.Text = $"{(id == null ? "" : "Captura de ")}{data.Target} · {data.From.ToLocalTime():g} → {data.To.ToLocalTime():g}"
            + (data.Node is { Length: > 0 } ? " · Nodo " + data.Node : "") + (data.Public ? " · Vista pública" : "");
        CaptureNote.Text = note ?? "";
        CaptureNote.Visibility = string.IsNullOrEmpty(note) ? Visibility.Collapsed : Visibility.Visible;
        Note.Text = "";
        Note.Visibility = data.Public ? Visibility.Collapsed : Visibility.Visible;
        SavePanel.Visibility = id == null && data.Rounds.Length + data.Events.Length != 0 ? Visibility.Visible : Visibility.Collapsed;
        Downloads.Visibility = id == null ? Visibility.Collapsed : Visibility.Visible;
        var eventsByTime = data.Events.Reverse().ToArray();
        HistoryEvents.ItemsSource = eventsByTime;
        if (selected != null)
            HistoryEvents.SelectedItem = eventsByTime.FirstOrDefault(e => e.Id == selected.Id && e.Time == selected.Time && e.State == selected.State);
        HistoryChartSummary.Text = $"{data.Rounds.Length} rondas · {data.Rounds.Count(r => r.Rtt != null)} respuestas del destino · {data.Rounds.Count(r => !r.Sent)} sin envío";
        HistorySamples.ItemsSource = data.Rounds.Reverse().Select(r => r.Label).ToArray();
        Compare();
        DrawCharts();
    }

    private void Compare()
    {
        if (history is not { } data)
            return;
        if (HistoryEvents.SelectedItem is RouteEvent change)
        {
            var before = data.Rounds.LastOrDefault(r => r.Start < change.FirstObserved);
            var after = data.Rounds.FirstOrDefault(r => r.Start >= change.FirstObserved);
            ComparedHops.ItemsSource = RoundRows("Antes del cambio", before).Concat(RoundRows("Desde el cambio", after)).ToArray();
        }
        else
        {
            ComparedHops.ItemsSource = RoundRows("Última ronda disponible", data.Rounds.LastOrDefault()).ToArray();
        }
    }

    private static IEnumerable<string> RoundRows(string title, Round? round)
    {
        yield return round == null ? title + " · Sin registros" : $"{title} · {round.Start.ToLocalTime():HH:mm:ss}";
        if (round == null)
            yield break;
        foreach (var h in round.Hops)
        {
            var address = h.Addr ?? (h.RttMs.HasValue ? "Oculta" : "—");
            var state = h.Status == "send_error" ? "Sin envío" : h.RttMs == null ? "Sin respuesta" : Display.Rtt(h.RttMs);
            yield return $"TTL {h.Ttl}   {address}   {state}";
        }
    }

    private async Task Run(Func<MonitorApi, CancellationToken, Task> action, bool clear = true)
    {
        if (api is not { } client)
        {
            Message("Conecta primero con el nodo de medición.");
            return;
        }
        var token = session.Token;
        if (clear)
            Message("");
        try { await action(client, token); }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or UnauthorizedAccessException or System.Text.Json.JsonException or OperationCanceledException)
        {
            if (!token.IsCancellationRequested)
                Message(ex.Message);
        }
    }

    private async Task Add() => await Run(async (client, token) =>
    {
        var ip = TraceAddress.Text.Trim();
        if (ip.Length == 0)
            throw new InvalidDataException("Indica una dirección IPv4 o IPv6.");
        var added = await client.Add(ip, token);
        var items = await client.Targets(token);
        if (token.IsCancellationRequested)
            return;
        TraceAddress.Text = "";
        SetTargets(items.Select(t => t.Address).ToArray());
        LiveTargets.SelectedItem = added.Address;
        await OpenView(View.Live);
        Message("Traza iniciada en el nodo.");
    });

    private void Message(string text)
    {
        Notice.Text = text;
        Notice.Visibility = string.IsNullOrEmpty(text) ? Visibility.Collapsed : Visibility.Visible;
    }

    private void DrawCharts()
    {
        if (view == View.Live)
        {
            var end = rounds.Length == 0 ? DateTimeOffset.Now : rounds[^1].Start;
            var begin = rounds.Length == 0 || rounds[0].Start > end.AddMinutes(-1) ? end.AddMinutes(-1) : rounds[0].Start;
            NativeCharts.Latency(LiveChart, rounds, events, begin, end.AddSeconds(2), Root.ActualTheme);
            if (HeatExpander.IsExpanded)
                NativeCharts.Heat(HeatChart, rounds, Root.ActualTheme);
        }
        if (view == View.History && history is { } data)
            NativeCharts.Latency(HistoryChart, data.Rounds, data.Events, data.From, data.To, Root.ActualTheme, HistoryEvents.SelectedItem as RouteEvent);
    }

    private async void ConnectClick(object sender, RoutedEventArgs e) => await Connect();
    private async void NodeKeyDown(object sender, KeyRoutedEventArgs e) { if (e.Key == VirtualKey.Enter) await Connect(); }
    private async void TraceKeyDown(object sender, KeyRoutedEventArgs e) { if (e.Key == VirtualKey.Enter) await Add(); }
    private async void PrivacyClick(object sender, RoutedEventArgs e) { if (api != null) await Connect(remember: false, current: api.Node); }
    private async void AddClick(object sender, RoutedEventArgs e) => await Add();
    private async void LiveClick(object sender, RoutedEventArgs e) => await OpenView(View.Live);
    private async void HistoryClick(object sender, RoutedEventArgs e) => await OpenView(View.History);
    private async void CapturesClick(object sender, RoutedEventArgs e) => await OpenView(View.Captures);
    private async void ConsultClick(object sender, RoutedEventArgs e) => await Consult();
    private async void InspectClick(object sender, RoutedEventArgs e) { if (target is { } active) await Inspect(active); }
    private async void LiveEventClick(object sender, ItemClickEventArgs e) { if (e.ClickedItem is RouteEvent change) await Inspect(change.Target, change); }
    private void HistoryEventChanged(object sender, SelectionChangedEventArgs e) { Compare(); DrawCharts(); }
    private void ChartResized(object sender, SizeChangedEventArgs e) => DrawCharts();
    private void HeatExpanding(Expander sender, ExpanderExpandingEventArgs e) => NativeCharts.Heat(HeatChart, rounds, Root.ActualTheme);
    private void LiveSamplesExpanding(Expander sender, ExpanderExpandingEventArgs e) => LiveSamples.ItemsSource = rounds.Reverse().Select(r => r.Label).ToArray();
    private void HistorySamplesExpanding(Expander sender, ExpanderExpandingEventArgs e) =>
        HistorySamples.ItemsSource = history?.Rounds.Reverse().Select(r => r.Label).ToArray();

    private async void TargetChanged(object sender, SelectionChangedEventArgs e)
    {
        if (settingTargets)
            return;
        SetTarget(LiveTargets.SelectedItem as string);
        if (view != View.Live)
            await OpenView(View.Live);
        else
            await Poll();
    }

    private async void RemoveClick(object sender, RoutedEventArgs e)
    {
        if (target is not { } active)
            return;
        await Run(async (client, token) =>
        {
            await client.Remove(active, token);
            await Poll();
            if (!token.IsCancellationRequested)
                Message("Traza detenida. Las mediciones quedan en Historial durante su retención.");
        });
    }

    private async void SaveClick(object sender, RoutedEventArgs e)
    {
        if (history is not { } data || savedId != null)
            return;
        SaveButton.IsEnabled = false;
        var selected = HistoryEvents.SelectedItem as RouteEvent;
        await Run(async (client, token) =>
        {
            var info = await client.Save(data, Note.Text, token);
            var capture = await client.Capture(info.Id, token);
            if (!token.IsCancellationRequested && history == data)
            {
                ShowHistory(capture.History, capture.Id, capture.Note, selected);
                Message("Captura guardada en el nodo. Ya puedes descargarla.");
            }
        });
        SaveButton.IsEnabled = true;
    }

    private async void CaptureClick(object sender, ItemClickEventArgs e)
    {
        if (e.ClickedItem is not CaptureInfo info)
            return;
        await Run(async (client, token) =>
        {
            var c = await client.Capture(info.Id, token);
            if (token.IsCancellationRequested || view != View.Captures)
                return;
            SetDates(c.History.From, c.History.To);
            await OpenView(View.History, c.History.Target);
            if (!token.IsCancellationRequested && view == View.History)
                ShowHistory(c.History, c.Id, c.Note);
        });
    }

    private async void DownloadClick(object sender, RoutedEventArgs e)
    {
        if (savedId is not { } id || history is not { } data || sender is not Button { Tag: string format })
            return;
        await Run(async (client, token) =>
        {
            var picker = new FileSavePicker { SuggestedFileName = $"tracertip-{data.From:yyyyMMdd-HHmmss}" };
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));
            picker.FileTypeChoices.Add(format.ToUpperInvariant(), new List<string> { "." + format });
            var file = await picker.PickSaveFileAsync();
            if (file == null || token.IsCancellationRequested)
                return;
            var bytes = await client.Export(id, format, data.Public, token);
            token.ThrowIfCancellationRequested();
            await FileIO.WriteBytesAsync(file, bytes);
            Message("Reporte descargado · " + file.Name);
        });
    }
}
