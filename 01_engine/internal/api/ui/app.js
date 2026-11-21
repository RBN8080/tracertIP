"use strict";

const KEEP = 900;
const $ = (id) => document.getElementById(id);
const state = { public: false, selected: null, targets: [], rounds: new Map(), events: [], es: null, epoch: 0, view: "live" };

try { state.public = localStorage.getItem("public") === "1"; } catch { /* storage may be blocked */ }
if (new URLSearchParams(location.search).get("public") === "1") state.public = true;
$("public").checked = state.public;

function apiURL(path, params = {}, pub = state.public) {
  const q = new URLSearchParams(params);
  if (pub) q.set("public", "1");
  return "/v1/" + path + (q.size ? "?" + q.toString() : "");
}

async function api(path, params = {}, options = {}) {
  const r = await fetch(apiURL(path, params), { cache: "no-store", ...options });
  if (!r.ok) throw new Error((await r.text()).trim() || "HTTP " + r.status);
  return r.json();
}

function el(tag, attrs = {}, content = "") {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value !== undefined) node.setAttribute(key, value);
  }
  node.textContent = content;
  return node;
}

function tableRow(values, classes = []) {
  const row = el("tr");
  values.forEach((value, i) => row.append(el("td", { class: classes[i] }, value)));
  return row;
}

const shortTime = (t) => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const dateTime = (t) => new Date(t).toLocaleString();
const fmt = (ms) => ms == null ? "—" : (ms < 10 ? ms.toFixed(2) : ms.toFixed(1)) + " ms";
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const monitorLabel = { measuring: "Midiendo", "no route": "Sin ruta desde el nodo", "no socket": "Sin socket de medición", dark: "El nodo no pudo enviar sondas" };
const eventLabel = { confirmed: "Confirmado", provisional: "Provisional", dropped: "Descartado" };
const eventKey = (e) => [e.target, e.time, e.id, e.state].join("|");

function switchView(view, focus = true) {
  state.view = view;
  for (const button of document.querySelectorAll("[data-view]")) {
    if (button.dataset.view === view) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
    $(button.dataset.view + "-view").hidden = button.dataset.view !== view;
  }
  if (focus) $(view + "-title").focus();
  document.dispatchEvent(new CustomEvent("view-changed", { detail: view }));
  if (view === "live") queueDraw();
}
for (const button of document.querySelectorAll("[data-view]")) {
  button.addEventListener("click", () => switchView(button.dataset.view));
}

function say(text, error = false) {
  $("msg").textContent = text;
  $("msg").classList.toggle("error", error);
}

function connection(text, tone) {
  const status = $("connection");
  if (status.textContent !== text) status.textContent = text;
  status.dataset.tone = tone;
}

function drawTargets() {
  const ul = $("targets");
  const signature = JSON.stringify([state.selected, state.targets]);
  if (signature === ul.dataset.signature) return;
  ul.dataset.signature = signature;
  const focused = ul.contains(document.activeElement) ? document.activeElement.dataset.key : null;
  ul.replaceChildren();
  $("target-count").textContent = state.targets.length === 1 ? "1 activo" : state.targets.length ? state.targets.length + " activos" : "";
  if (!state.targets.length) ul.append(el("li", { class: "empty" }, "Agrega una IP para iniciar una traza."));
  for (const t of state.targets) {
    const b = el("button", { type: "button", class: "pick", "aria-pressed": String(t.target === state.selected), "data-key": "pick " + t.target });
    b.append(el("strong", {}, t.target), el("small", {}, [monitorLabel[t.state] || t.state, t.last?.p50_ms != null ? fmt(t.last.p50_ms) : ""].filter(Boolean).join(" · ")));
    b.addEventListener("click", () => {
      switchView("live", false);
      select(t.target);
    });
    const x = el("button", { type: "button", class: "remove", "data-key": "remove " + t.target, "aria-label": "Detener traza de " + t.target }, "×");
    x.addEventListener("click", () => removeTarget(t.target).catch((err) => say(err.message, true)));
    const row = el("li");
    row.append(b, x);
    ul.append(row);
  }
  if (focused) Array.from(ul.querySelectorAll("button")).find((b) => b.dataset.key === focused)?.focus({ preventScroll: true });
}

async function refreshTargets(epoch = state.epoch) {
  const targets = await api("targets");
  if (epoch !== state.epoch) return;
  state.targets = targets;
  if (!targets.some((t) => t.target === state.selected)) select(targets[0]?.target || null);
  drawTargets();
}

async function refreshRounds(target, epoch) {
  const path = "targets/" + encodeURIComponent(target) + "/rounds";
  const rounds = await api(path, { n: KEEP });
  if (epoch !== state.epoch || target !== state.selected) return;
  const unique = new Map();
  for (const r of [...rounds, ...state.rounds.get(target) || []]) unique.set(r.start + "|" + r.n, r);
  state.rounds.set(target, Array.from(unique.values()).sort((a, b) => Date.parse(a.start) - Date.parse(b.start)).slice(-KEEP));
  queueDraw();
}

function select(target) {
  const changed = target !== state.selected;
  state.selected = target;
  if (changed) $("hops").tBodies[0].replaceChildren();
  drawTargets();
  queueDraw();
  if (!target) return;
  const epoch = state.epoch;
  refreshRounds(target, epoch).catch(() => {});
  refreshHops(target, epoch).catch(() => {});
}

async function refreshHops(target = state.selected, epoch = state.epoch) {
  if (!target) return;
  const recs = await api("targets/" + encodeURIComponent(target) + "/hops");
  if (epoch !== state.epoch || target !== state.selected) return;
  const rows = recs.map((r) => {
    const inf = r.info || {};
    let net = "";
    if (r.home) net = "Red de acceso";
    else if (inf.ixp) net = "IXP " + (inf.ixp.name || "");
    else if (inf.as?.length) net = "AS" + inf.as[0].asn + " " + (inf.as[0].name || "");
    else if (inf.class && inf.class !== "public") net = inf.class;
    const loc = r.location ? r.location.city + ", " + r.location.country + (r.location.weak ? "?" : "") + " [" + r.location.source + "]" : "—";
    return tableRow([r.ttl, r.home ? "Oculta" : r.addr || "—", net, loc, r.min_rtt_ms < 0 ? "—" : fmt(r.min_rtt_ms), (r.flags || []).join(" ")],
      ["num", "address", "", "loc", "num", "flags"]);
  });
  $("hops").tBodies[0].replaceChildren(...rows);
}

async function addTarget(ip) {
  const added = await api("targets", {}, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target: ip }),
  });
  $("ip").value = "";
  say("Traza iniciada. La primera ronda puede tardar unos segundos.");
  await refreshTargets();
  if (state.targets.some((t) => t.target === added.target)) {
    switchView("live", false);
    select(added.target);
  }
}

async function removeTarget(ip) {
  const r = await fetch(apiURL("targets/" + encodeURIComponent(ip)), { method: "DELETE" });
  if (!r.ok && r.status !== 404) throw new Error((await r.text()).trim());
  state.rounds.delete(ip);
  say("Traza detenida. Las mediciones siguen en Historial mientras dure su retención.");
  await refreshTargets();
}

function roundMeasurement(r) {
  let best = null;
  let sent = false;
  for (const p of r.hops) {
    sent ||= p.status !== "send_error";
    if (p.addr === r.target && p.rtt_ms != null && (best == null || p.rtt_ms < best)) best = p.rtt_ms;
  }
  return { rtt: best, sent };
}

function metrics(rounds) {
  const samples = rounds.map(roundMeasurement);
  const rtts = samples.map((s) => s.rtt).filter((v) => v != null).sort((a, b) => a - b);
  const nth = (q) => rtts[Math.ceil(q * rtts.length) - 1];
  return { samples, replies: rtts.length, sent: samples.filter((s) => s.sent).length, p50: nth(.5), p95: rtts.length >= 59 ? nth(.95) : undefined };
}

function drawMeasurementRows(id, rounds) {
  const parent = $(id);
  const details = parent.closest("details");
  if (!details.open) return;
  const rows = rounds.slice().reverse().map((r) => {
    const m = roundMeasurement(r);
    return tableRow([dateTime(r.start), fmt(m.rtt), m.rtt != null ? "Con respuesta" : m.sent ? "Sin respuesta del destino" : "Ronda sin envío"]);
  });
  if (!rows.length) rows.push(tableRow(["Sin rondas registradas", "—", "—"]));
  parent.replaceChildren(...rows);
}

function sizeCanvas(canvas) {
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return null;
  const dpr = window.devicePixelRatio || 1;
  const pixelsW = Math.round(w * dpr), pixelsH = Math.round(h * dpr);
  if (canvas.width !== pixelsW) canvas.width = pixelsW;
  if (canvas.height !== pixelsH) canvas.height = pixelsH;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  return { ctx, w, h };
}

function latencyChart(canvas, rounds, events, from, to, selectedEvent) {
  const surface = sizeCanvas(canvas);
  if (!surface) return;
  const { ctx, w, h } = surface;
  const values = rounds.map(roundMeasurement).map((s) => s.rtt);
  const valid = values.filter((v) => v != null);
  const x0 = 48, x1 = w - 17, y0 = 18, y1 = h - 30;
  const high = Math.max(5, Math.ceil(Math.max(0, ...valid) / 5) * 5);
  const x = (t) => x0 + (t - from) / Math.max(1, to - from) * (x1 - x0);
  const y = (v) => y1 - v / high * (y1 - y0);
  ctx.font = "11px system-ui";
  ctx.textAlign = "left";
  ctx.lineWidth = 1;
  ctx.fillStyle = css("--muted");
  ctx.strokeStyle = css("--grid");
  for (let i = 0; i <= 4; i++) {
    const v = i * high / 4, yy = y(v);
    ctx.beginPath(); ctx.moveTo(x0, yy); ctx.lineTo(x1, yy); ctx.stroke();
    ctx.fillText(Math.round(v) + (i === 4 ? " ms" : ""), 9, yy + 3);
  }
  for (let i = 0; i <= 4; i++) {
    const tick = i / 4, t = from + (to - from) * tick;
    ctx.textAlign = i === 0 ? "left" : i === 4 ? "right" : "center";
    ctx.fillText(new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), x(t), h - 9);
  }
  ctx.textAlign = "center";
  if (!valid.length) ctx.fillText(rounds.length ? "Sin respuestas del destino" : "Sin mediciones en el intervalo", (x0 + x1) / 2, (y0 + y1) / 2);
  for (const e of events) {
    const at = Date.parse(e.time);
    if (e.state === "dropped" || at < from || at > to) continue;
    const xx = x(at);
    ctx.strokeStyle = css(e.state === "confirmed" ? "--bad" : "--warn");
    ctx.lineWidth = eventKey(e) === selectedEvent ? 3 : 1;
    ctx.setLineDash([4, 4]);
    ctx.beginPath(); ctx.moveTo(xx, y0); ctx.lineTo(xx, y1); ctx.stroke();
  }
  ctx.setLineDash([]);
  ctx.strokeStyle = ctx.fillStyle = css("--accent");
  ctx.lineWidth = 1.7;
  let previous = 0;
  let pen = false;
  ctx.beginPath();
  values.forEach((v, i) => {
    const t = Date.parse(rounds[i].start);
    if (v == null) { pen = false; return; }
    const xx = x(t), yy = y(v);
    if (pen && t - previous < 7000) ctx.lineTo(xx, yy);
    else { ctx.moveTo(xx, yy); ctx.lineTo(xx + 1, yy); }
    pen = true;
    previous = t;
  });
  ctx.stroke();
}

const HEAT = [[68, 1, 84], [59, 82, 139], [33, 145, 140], [94, 201, 98], [253, 231, 37]];
function heatColor(ms) {
  const pos = Math.max(0, Math.min(1, Math.log10(Math.max(1, ms)) / Math.log10(400))) * (HEAT.length - 1);
  const i = Math.min(HEAT.length - 2, Math.floor(pos));
  const color = HEAT[i].map((a, j) => Math.round(a + (HEAT[i + 1][j] - a) * (pos - i)));
  return "rgb(" + color.join(",") + ")";
}

function drawHeat(rounds) {
  if (!$("heat-panel").open) return;
  const surface = sizeCanvas($("heat"));
  if (!surface || !rounds.length) return;
  const { ctx, w, h } = surface;
  let maxTTL = 1;
  for (const r of rounds) for (const p of r.hops) maxTTL = Math.max(maxTTL, p.ttl);
  const cw = (w - 33) / rounds.length, ch = h / maxTTL, gap = css("--gap");
  ctx.font = "11px system-ui";
  ctx.fillStyle = css("--muted");
  for (let t = 1; t <= maxTTL; t += Math.max(1, Math.round(maxTTL / 8))) ctx.fillText(String(t), 8, t * ch - ch / 2 + 4);
  rounds.forEach((r, i) => {
    for (const p of r.hops) {
      ctx.fillStyle = p.rtt_ms == null ? gap : heatColor(p.rtt_ms);
      ctx.fillRect(30 + i * cw, (p.ttl - 1) * ch, Math.ceil(cw), Math.ceil(ch));
    }
  });
}

function drawEvents(id, counter, events, choose, selected = "") {
  const container = $(id);
  const shown = events.slice().reverse();
  const signature = JSON.stringify([shown, selected]);
  if (container.dataset.signature === signature) return;
  container.dataset.signature = signature;
  const focused = container.contains(document.activeElement) ? document.activeElement.dataset.key : null;
  const items = shown.map((e) => {
    const key = eventKey(e);
    const button = el("button", { class: "event", type: "button", "data-key": key, "aria-pressed": selected ? String(key === selected) : undefined });
    const label = el("span", { class: "state-" + e.state }, eventLabel[e.state] || e.state);
    const change = [...(e.before_as || [])].map((n) => "AS" + n).join(" › ") + " → " + [...(e.after_as || [])].map((n) => "AS" + n).join(" › ");
    button.append(label, el("time", { datetime: e.time }, shortTime(e.time)), el("small", {}, "TTL " + e.ttl + " · " + change));
    button.addEventListener("click", () => choose(e));
    const row = el("li");
    row.append(button);
    return row;
  });
  if (!items.length) items.push(el("li", { class: "empty" }, "Sin cambios registrados."));
  container.replaceChildren(...items);
  if (focused) Array.from(container.querySelectorAll("button")).find((b) => b.dataset.key === focused)?.focus({ preventScroll: true });
  $(counter).textContent = events.length;
}

function renderLive() {
  const rounds = state.rounds.get(state.selected) || [];
  const target = state.targets.find((t) => t.target === state.selected);
  const events = state.events.filter((e) => e.target === state.selected);
  const m = metrics(rounds);
  const last = rounds.at(-1), end = last ? Date.parse(last.start) : Date.now();
  const age = last ? Math.max(0, Math.round((Date.now() - end) / 1000)) : null;
  $("live-origin").textContent = "Nodo de medición · " + (state.public ? "Vista pública" : location.host);
  $("live-target").textContent = target?.target || "—";
  $("live-state").textContent = !target ? "Selecciona un destino" : monitorLabel[target.state] || target.state;
  $("live-median").textContent = fmt(m.p50);
  $("live-p95").textContent = "Percentil 95 " + fmt(m.p95);
  $("live-reply").textContent = m.sent ? Math.round(100 * m.replies / m.sent) + " %" : "—";
  $("live-sent").textContent = m.sent ? m.replies + " de " + m.sent + " rondas con envío" : "Sin rondas con envío";
  $("live-last").textContent = last ? shortTime(last.start) : "—";
  $("live-age").textContent = age == null ? "Esperando mediciones" : age > 15 ? "Datos sin actualizar · hace " + age + " s" : "Hace " + age + " s";
  $("inspect-live").disabled = !target;
  const start = rounds.length ? Math.min(end - 60000, Date.parse(rounds[0].start)) : end - 60000;
  latencyChart($("rtt"), rounds, events, start, end + 2000);
  drawHeat(rounds);
  $("summary").textContent = !rounds.length ? "Las rondas aparecerán al comenzar la medición."
    : rounds.length + " rondas registradas · " + (rounds.length - m.sent) + " sin envío. Las líneas punteadas marcan cambios de ruta.";
  drawMeasurementRows("live-data", rounds);
  drawEvents("events", "live-event-count", events.slice(-30), (event) => document.dispatchEvent(new CustomEvent("inspect-event", { detail: event })));
}

let pending = false;
function queueDraw() {
  if (pending || state.view !== "live") return;
  pending = true;
  requestAnimationFrame(() => { pending = false; if (state.view === "live") renderLive(); });
}

function drawHealth(hv) {
  const n = hv.node || {};
  $("node").textContent = [n.version, n.clock_synced ? "Reloj sincronizado" : "Reloj sin sincronizar",
    n.temp_c ? n.temp_c.toFixed(1) + " °C" : "", n.disk_free_mb ? (n.disk_free_mb / 1024).toFixed(1) + " GiB libres" : ""].filter(Boolean).join(" · ");
  const rows = [];
  for (const t of hv.targets || []) {
    rows.push(tableRow([t.target, (monitorLabel[t.state] || t.state) + (!state.public && t.error ? " · " + t.error : ""), t.rounds,
      t.replied, t.no_reply, t.send_errors, t.sessions, Math.round(t.lag_ms) + " ms"], ["address", "", "num", "num", "num", "num", "num", "num"]));
    const entry = state.targets.find((x) => x.target === t.target);
    if (entry) entry.state = t.state;
  }
  $("health").tBodies[0].replaceChildren(...rows);
  drawTargets();
  queueDraw();
}

async function refreshLive(epoch) {
  const events = await api("events", { n: 1000 });
  if (epoch !== state.epoch) return;
  const merged = new Map();
  for (const e of [...events, ...state.events]) merged.set(eventKey(e), e);
  state.events = Array.from(merged.values()).sort((a, b) => Date.parse(a.time) - Date.parse(b.time)).slice(-1000);
  await refreshTargets(epoch);
  if (epoch === state.epoch && state.selected) select(state.selected);
  queueDraw();
}

function connect() {
  const epoch = ++state.epoch;
  state.es?.close();
  state.rounds.clear();
  state.targets = [];
  state.selected = null;
  state.events = [];
  $("hops").tBodies[0].replaceChildren();
  $("health").tBodies[0].replaceChildren();
  $("live-data").replaceChildren();
  $("events").replaceChildren();
  delete $("events").dataset.signature;
  $("node").textContent = "";
  $("live-origin").textContent = "Nodo de medición · " + (state.public ? "Vista pública" : location.host);
  drawTargets();
  queueDraw();
  connection("Conectando", "wait");
  const es = new EventSource(apiURL("stream"));
  state.es = es;
  const on = (event, fn) => es.addEventListener(event, (m) => { if (epoch === state.epoch) fn(m); });
  on("open", () => {
    connection("En línea", "ok");
    refreshLive(epoch).catch((err) => { if (epoch === state.epoch) say(err.message, true); });
  });
  on("round", (m) => {
    const r = JSON.parse(m.data);
    if (!state.rounds.has(r.target)) state.rounds.set(r.target, []);
    const list = state.rounds.get(r.target);
    if (list.at(-1)?.start !== r.start || list.at(-1)?.n !== r.n) list.push(r);
    if (list.length > KEEP) list.shift();
    if (r.target === state.selected) queueDraw();
  });
  on("event", (m) => {
    state.events.push(JSON.parse(m.data));
    if (state.events.length > 1000) state.events.shift();
    queueDraw();
  });
  on("health", (m) => drawHealth(JSON.parse(m.data)));
  on("targets", () => refreshTargets(epoch).catch(() => {}));
  on("error", () => connection(es.readyState === EventSource.CLOSED ? "Desconectado" : "Reconectando", "error"));
  refreshLive(epoch).catch((e) => {
    if (epoch === state.epoch) say(e.message, true);
  });
}

$("search").addEventListener("submit", (event) => {
  event.preventDefault();
  const ip = $("ip").value.trim();
  if (ip) addTarget(ip).catch((err) => say(err.message, true));
});
$("public").addEventListener("change", (event) => {
  state.public = event.target.checked;
  try { localStorage.setItem("public", state.public ? "1" : "0"); } catch { /* storage may be blocked */ }
  say("");
  connect();
  document.dispatchEvent(new Event("privacy-changed"));
});
$("heat-panel").addEventListener("toggle", queueDraw);
$("live-samples").addEventListener("toggle", queueDraw);
new ResizeObserver(queueDraw).observe($("rtt"));
matchMedia("(prefers-color-scheme: light)").addEventListener("change", queueDraw);
setInterval(queueDraw, 1000);
setInterval(() => {
  refreshHops().catch(() => {});
  refreshTargets().catch(() => {});
}, 12000);
connect();
