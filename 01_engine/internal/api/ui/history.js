"use strict";

let result = null;
let saved = null;
let selectedChange = null;
let loadSequence = 0;
let targetSequence = 0;
let listSequence = 0;

const localInput = (t) => {
  const d = new Date(t);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
};

function range(from, to) {
  $("history-from").value = localInput(from);
  $("history-to").value = localInput(to);
}

function statusAt(id, text, error = false) {
  $(id).textContent = text;
  $(id).classList.toggle("error", error);
}

range(Date.now() - 15 * 60000, Date.now());
const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
$("history-zone").textContent = "Hora local (" + zone + "). Máximo 60 minutos por consulta.";

async function historyTargets(preferred) {
  const sequence = ++targetSequence;
  const items = await api("history/targets");
  if (sequence !== targetSequence) return false;
  const select = $("history-target");
  const old = preferred || select.value || state.selected;
  const all = new Set(items);
  if (!state.public) for (const t of state.targets) all.add(t.target);
  if (preferred && !state.public) all.add(preferred);
  const options = Array.from(all, (ip) => el("option", { value: ip }, ip)).sort((a, b) => a.value.localeCompare(b.value));
  select.replaceChildren(...options);
  if (all.has(old)) select.value = old;
  if (!options.length) select.append(el("option", { value: "" }, "Sin destinos en el historial"));
  return true;
}

function queryValues() {
  const from = new Date($("history-from").value);
  const to = new Date($("history-to").value);
  const target = $("history-target").value;
  if (!target) throw new Error("Selecciona un destino.");
  if (!(to - from > 0 && to - from <= 3600000)) throw new Error("Elige un intervalo de hasta 60 minutos.");
  return { target, from: from.toISOString(), to: to.toISOString() };
}

function chartHistory() {
  if (state.view !== "history" || !result) return;
  latencyChart($("history-rtt"), result.rounds, result.events, Date.parse(result.from), Date.parse(result.to),
    selectedChange ? eventKey(selectedChange) : "");
  drawMeasurementRows("history-data", result.rounds);
}

function routePanel(title, round) {
  const group = el("section");
  group.append(el("h3", {}, title + (round ? " · " + shortTime(round.start) : "")));
  if (!round) {
    group.append(el("p", { class: "chart-note muted" }, "No hay una ronda registrada en este lado del cambio."));
    return group;
  }
  const wrap = el("div", { class: "scroll", tabindex: "0", role: "region", "aria-label": title });
  const table = el("table");
  const head = table.createTHead().insertRow();
  for (const label of ["TTL", "Dirección", "RTT", "Estado"]) head.append(el("th", { scope: "col" }, label));
  const body = table.createTBody();
  for (const p of round.hops) {
    const status = p.rtt_ms != null ? "Con respuesta" : p.status === "send_error" ? "Sin envío" : "Sin respuesta";
    body.append(tableRow([p.ttl, p.addr || (p.rtt_ms == null ? "—" : "Oculta"), fmt(p.rtt_ms), status], ["num", "address", "num", ""]));
  }
  wrap.append(table);
  group.append(wrap);
  return group;
}

function historyEvents() {
  const noEvent = !selectedChange;
  drawEvents("history-events", "history-event-count", result.events, (event) => {
    selectedChange = event;
    historyEvents();
    chartHistory();
  }, noEvent ? "" : eventKey(selectedChange));
  const observed = noEvent ? null : selectedChange.observed_at || selectedChange.time;
  const timestamp = noEvent ? null : Date.parse(observed);
  $("comparison-context").textContent = noEvent ? "Última ronda disponible. Selecciona un evento para comparar."
    : "Primera observación · " + dateTime(observed) + " · " + eventLabel[selectedChange.state] + " · " + shortTime(selectedChange.time);
  const rounds = result.rounds;
  if (noEvent) {
    $("comparison-grid").replaceChildren(routePanel("Última ronda", rounds.at(-1)));
  } else {
    const before = rounds.findLast((r) => Date.parse(r.start) < timestamp);
    const after = rounds.find((r) => Date.parse(r.start) >= timestamp);
    $("comparison-grid").replaceChildren(routePanel("Antes del cambio", before), routePanel("Desde el cambio", after));
  }
}

function showHistory(view, info = null, event = null) {
  result = view;
  saved = info;
  selectedChange = event ? view.events.find((e) => eventKey(e) === eventKey(event)) || event : null;
  $("history-result").hidden = false;
  $("history-result-title").textContent = (info ? "Captura de " : "") + view.target;
  $("history-result-meta").textContent = dateTime(view.from) + " → " + dateTime(view.to) +
    (view.node ? " · Nodo " + view.node : "") + (view.public ? " · Vista pública" : "");
  $("history-note").textContent = info?.note || "";
  $("history-note").hidden = !info?.note;
  const summary = metrics(view.rounds);
  $("history-summary").textContent = view.rounds.length + " rondas · " + summary.replies + " de " + summary.sent +
    " con respuesta del destino · mediana " + fmt(summary.p50);
  $("save-capture").hidden = Boolean(info) || !(view.rounds.length || view.events.length);
  $("note-label").hidden = view.public;
  $("note").value = "";
  statusAt("save-status", "");
  const actions = $("download-actions");
  actions.replaceChildren();
  actions.hidden = !info;
  if (info) {
    for (const format of ["pdf", "csv", "jsonl"]) {
      const href = apiURL("captures/" + encodeURIComponent(info.id) + "/export/" + format, {}, view.public);
      actions.append(el("a", { class: "action", href, download: "", "aria-label": "Descargar captura en " + format.toUpperCase() }, format.toUpperCase()));
    }
  }
  historyEvents();
  requestAnimationFrame(chartHistory);
}

async function consult(event = null) {
  const sequence = ++loadSequence;
  $("history-submit").disabled = true;
  $("history-result").hidden = true;
  statusAt("history-status", "Leyendo registros del nodo…");
  try {
    const q = queryValues();
    const data = await api("history", q);
    if (sequence !== loadSequence) return;
    statusAt("history-status", data.rounds.length || data.events.length ? "Consulta completa." : "Sin registros en ese intervalo. Revisa la fecha o la retención.");
    showHistory(data, null, event);
  } catch (err) {
    if (sequence === loadSequence) statusAt("history-status", err.message, true);
  } finally {
    if (sequence === loadSequence) $("history-submit").disabled = false;
  }
}

async function inspect(target, from, to, event) {
  switchView("history");
  range(from, to);
  try {
    if (await historyTargets(target)) await consult(event);
  } catch (err) {
    statusAt("history-status", err.message, true);
  }
}

async function listCaptures() {
  const sequence = ++listSequence;
  statusAt("captures-status", "Consultando capturas…");
  const captures = await api("captures");
  if (sequence !== listSequence) return;
  statusAt("captures-status", captures.length ? "" : "Aún no hay capturas guardadas en esta vista.");
  $("capture-list").replaceChildren(...captures.map((c) => {
    const item = el("li", { class: "panel" });
    const detail = el("div");
    detail.append(el("h2", { class: "capture-target" }, c.target));
    detail.append(el("p", { class: "muted" }, dateTime(c.from) + " → " + dateTime(c.to)));
    if (c.note) detail.append(el("p", { class: "capture-note" }, c.note));
    detail.append(el("p", { class: "muted" }, c.rounds + " rondas · " + c.events + " eventos" + (c.public ? " · Pública" : "")));
    const open = el("button", { type: "button" }, "Abrir");
    open.addEventListener("click", () => openCapture(c.id).catch((err) => statusAt("captures-status", err.message, true)));
    item.append(detail, open);
    return item;
  }));
}

async function openCapture(id) {
  const sequence = listSequence;
  const c = await api("captures/" + encodeURIComponent(id));
  if (sequence !== listSequence || state.view !== "captures") return;
  ++loadSequence;
  $("history-submit").disabled = false;
  switchView("history");
  range(Date.parse(c.from), Date.parse(c.to));
  historyTargets(c.target).catch((err) => statusAt("history-status", err.message, true));
  statusAt("history-status", "Captura guardada · " + dateTime(c.saved_at));
  showHistory(c.history, c);
}

$("history-form").addEventListener("submit", (event) => { event.preventDefault(); consult(); });
$("save-capture").addEventListener("submit", async (event) => {
  event.preventDefault();
  const epoch = state.epoch, view = result;
  if (!view || saved || view.public !== state.public) return;
  const button = $("save-button");
  button.disabled = true;
  statusAt("save-status", "Guardando captura en el nodo…");
  try {
    const info = await api("captures", {}, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: view.target, from: view.from, to: view.to, note: view.public ? "" : $("note").value }),
    });
    if (epoch !== state.epoch || view !== result) return;
    const c = await api("captures/" + encodeURIComponent(info.id));
    if (epoch !== state.epoch || view !== result) return;
    showHistory(c.history, c, selectedChange);
    statusAt("save-status", "Captura guardada. Elige PDF, CSV o JSONL para descargarla.");
    $("download-actions").querySelector("a")?.focus();
  } catch (err) {
    if (epoch === state.epoch && view === result) statusAt("save-status", err.message, true);
  } finally {
    if (epoch === state.epoch) button.disabled = false;
  }
});
$("inspect-live").addEventListener("click", () => {
  if (state.selected) inspect(state.selected, Date.now() - 15 * 60000, Date.now());
});
document.addEventListener("inspect-event", ({ detail: event }) => {
  const t = Date.parse(event.observed_at || event.time);
  inspect(event.target, t - 5 * 60000, t + 5 * 60000, event);
});
document.addEventListener("view-changed", ({ detail: view }) => {
  if (view === "history") {
    historyTargets().catch((err) => statusAt("history-status", err.message, true));
    requestAnimationFrame(chartHistory);
  }
  if (view === "captures") listCaptures().catch((err) => statusAt("captures-status", err.message, true));
});
document.addEventListener("privacy-changed", () => {
  ++loadSequence;
  ++targetSequence;
  ++listSequence;
  result = saved = selectedChange = null;
  $("history-result").hidden = true;
  $("history-target").replaceChildren();
  $("download-actions").replaceChildren();
  $("history-note").textContent = "";
  $("note").value = "";
  $("history-data").replaceChildren();
  $("history-events").replaceChildren();
  delete $("history-events").dataset.signature;
  $("comparison-grid").replaceChildren();
  $("capture-list").replaceChildren();
  $("history-submit").disabled = false;
  $("save-button").disabled = false;
  statusAt("history-status", "");
  statusAt("save-status", "");
  if (state.view === "history") historyTargets().catch((err) => statusAt("history-status", err.message, true));
  if (state.view === "captures") listCaptures().catch((err) => statusAt("captures-status", err.message, true));
});
$("history-samples").addEventListener("toggle", chartHistory);
new ResizeObserver(chartHistory).observe($("history-rtt"));
matchMedia("(prefers-color-scheme: light)").addEventListener("change", chartHistory);
