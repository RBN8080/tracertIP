using System.Net.Http.Json;
using System.Text.Json;

namespace TracertIP.Desktop;

internal sealed class MonitorApi(Uri node, bool publicView)
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(35) };
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public Uri Node { get; } = node;
    public bool PublicView { get; } = publicView;

    public Task<HealthView> Health(CancellationToken token) => Get<HealthView>("health", token);
    public Task<Target[]> Targets(CancellationToken token) => Get<Target[]>("targets", token);
    public Task<RouteEvent[]> Events(CancellationToken token) => Get<RouteEvent[]>("events?n=250", token);
    public Task<Round[]> Rounds(string target, int count, CancellationToken token) =>
        Get<Round[]>("targets/" + Uri.EscapeDataString(target) + "/rounds?n=" + count, token);
    public Task<JudgedHop[]> Hops(string target, CancellationToken token) =>
        Get<JudgedHop[]>("targets/" + Uri.EscapeDataString(target) + "/hops", token);
    public Task<string[]> HistoricalTargets(CancellationToken token) => Get<string[]>("history/targets", token);
    public Task<History> Read(Query query, CancellationToken token) =>
        Get<History>("history?target=" + Uri.EscapeDataString(query.Target)
            + "&from=" + Uri.EscapeDataString(query.From.ToString("O"))
            + "&to=" + Uri.EscapeDataString(query.To.ToString("O")), token);
    public Task<CaptureInfo[]> Captures(CancellationToken token) => Get<CaptureInfo[]>("captures", token);
    public Task<Capture> Capture(string id, CancellationToken token) => Get<Capture>("captures/" + Uri.EscapeDataString(id), token);

    public Task<CaptureInfo> Save(History history, string note, CancellationToken token) =>
        Post<CaptureInfo>("captures", new { history.Target, history.From, history.To, Note = PublicView ? "" : note }, token);
    public Task<Target> Add(string target, CancellationToken token) => Post<Target>("targets", new { target }, token);

    public async Task Remove(string target, CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, Endpoint("targets/" + Uri.EscapeDataString(target)));
        using var response = await Http.SendAsync(request, token);
        await RequireSuccess(response, token);
    }

    public async Task<byte[]> Export(string id, string format, bool usePublic, CancellationToken token)
    {
        using var response = await Http.GetAsync(Endpoint("captures/" + Uri.EscapeDataString(id) + "/export/" + format, usePublic), token);
        await RequireSuccess(response, token);
        return await response.Content.ReadAsByteArrayAsync(token);
    }

    private async Task<T> Get<T>(string path, CancellationToken token)
    {
        using var response = await Http.GetAsync(Endpoint(path), token);
        return await ReadJson<T>(response, token);
    }

    private async Task<T> Post<T>(string path, object data, CancellationToken token)
    {
        using var response = await Http.PostAsJsonAsync(Endpoint(path), data, Json, token);
        return await ReadJson<T>(response, token);
    }

    private Uri Endpoint(string path, bool? usePublic = null)
    {
        if (usePublic ?? PublicView)
            path += path.Contains('?') ? "&public=1" : "?public=1";
        return new Uri(Node, "/v1/" + path);
    }

    private static async Task<T> ReadJson<T>(HttpResponseMessage response, CancellationToken token)
    {
        await RequireSuccess(response, token);
        return await response.Content.ReadFromJsonAsync<T>(Json, token)
            ?? throw new InvalidDataException("El nodo devolvió una respuesta vacía.");
    }

    private static async Task RequireSuccess(HttpResponseMessage response, CancellationToken token)
    {
        if (response.IsSuccessStatusCode)
            return;
        var text = (await response.Content.ReadAsStringAsync(token)).Trim();
        throw new HttpRequestException(string.IsNullOrWhiteSpace(text) ? $"HTTP {(int)response.StatusCode}" : text, null, response.StatusCode);
    }
}

internal record Query(string Target, DateTimeOffset From, DateTimeOffset To);
internal record Target(string Address)
{
    [System.Text.Json.Serialization.JsonPropertyName("target")]
    public string Address { get; init; } = Address;
}
internal record NodeHealth(string Version, bool ClockSynced, double? TempC, long? DiskFreeMb);
internal record TargetHealth(string Target, string State, string? Error, long Rounds, long Replied, long NoReply, long SendErrors);
internal record HealthView(NodeHealth Node, TargetHealth[] Targets);
internal record Sample(int Ttl, string? Addr, double? RttMs, string? Status);
internal record Round(string Target, int N, DateTimeOffset Start, Sample[] Hops)
{
    public double? Rtt => Hops.Where(h => h.Addr == Target).Min(h => h.RttMs);
    public bool Sent => Hops.Any(h => h.Status != "send_error");
    public string Label => $"{Start.ToLocalTime():g}   {Display.Rtt(Rtt)}   {(Rtt != null ? "Con respuesta" : Sent ? "Sin respuesta del destino" : "Sin envío")}";
}

internal record RouteEvent(string Target, DateTimeOffset Time, DateTimeOffset? ObservedAt, string State, long Id, int Ttl, int[]? BeforeAs, int[]? AfterAs)
{
    public DateTimeOffset FirstObserved => ObservedAt ?? Time;
    public string Label => $"{Time.ToLocalTime():HH:mm:ss}   {Display.EventState(State)}   TTL {Ttl}\n{Display.Path(BeforeAs)} → {Display.Path(AfterAs)}";
}

internal record Asn(int AsnNumber, string Name)
{
    [System.Text.Json.Serialization.JsonPropertyName("asn")]
    public int AsnNumber { get; init; } = AsnNumber;
}
internal record Exchange(string Name);
internal record HopInfo(Asn[]? As, Exchange? Ixp);
internal record HopLocation(string City, string Country, string Source, bool Weak);
internal record JudgedHop(int Ttl, string? Addr, bool Home, HopInfo? Info, HopLocation? Location, double MinRttMs, string[]? Flags)
{
    public string Label
    {
        get
        {
            var address = Home ? "Oculta" : Addr ?? "—";
            var asn = Info?.As?.FirstOrDefault();
            var network = Home ? "Red de acceso" : Info?.Ixp is { } ixp ? "IXP " + ixp.Name : asn != null ? $"AS{asn.AsnNumber} {asn.Name}" : "";
            var location = Location == null ? "" : $"{Location.City}, {Location.Country}{(Location.Weak ? "?" : "")} [{Location.Source}]";
            return $"TTL {Ttl}   {address}   {Display.Rtt(MinRttMs < 0 ? null : MinRttMs)}   {network}   {location}   {string.Join(' ', Flags ?? [])}".TrimEnd();
        }
    }
}

internal record History(string Target, DateTimeOffset From, DateTimeOffset To, string? Node, bool Public, Round[] Rounds, RouteEvent[] Events);
internal record CaptureInfo(string Id, DateTimeOffset SavedAt, string Target, DateTimeOffset From, DateTimeOffset To, string? Note, bool Public, int Rounds, int Events)
{
    public string Label => $"{Target}   {From.ToLocalTime():g} → {To.ToLocalTime():g}\n{Rounds} rondas · {Events} eventos{(Public ? " · Pública" : "")}{(string.IsNullOrWhiteSpace(Note) ? "" : "\n" + Note)}";
}
internal record Capture(string Id, string? Note, History History);

internal static class Display
{
    public static string Rtt(double? value) => value is double ms ? $"{ms:0.##} ms" : "—";
    public static string Path(int[]? path) => path is { Length: > 0 } ? string.Join(" › ", path.Select(asn => "AS" + asn)) : "—";
    public static string EventState(string state) => state switch
    {
        "confirmed" => "Confirmado",
        "provisional" => "Provisional",
        "dropped" => "Descartado",
        _ => state,
    };
    public static string HealthState(string? state) => state switch
    {
        "measuring" => "Midiendo",
        "no route" => "Sin ruta desde el nodo",
        "no socket" => "Sin socket de medición",
        "dark" => "El nodo no pudo enviar sondas",
        _ => state ?? "Esperando mediciones",
    };
}
