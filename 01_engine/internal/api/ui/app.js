// tracertIP live view: reads /v1 and the event stream; draws with Canvas.
"use strict";

const KEEP = 900;          // rounds kept per target: 30 min at one round every 2 s
const SPACING_MS = 40;     // probe spacing between TTLs (engine default)
const HOPS_EVERY = 10000;  // the judged path is refreshed this often
const $ = (id) => document.getElementById(id);

const state = { public: false, selected: null, targets: [], rounds: {}, events: [], lat: [], es: null };

try { state.public = localStorage.getItem("public") === "1"; } catch (e) { /* storage may be blocked */ }
if (new URLSearchParams(location.search).get("public") === "1") state.public = true; // a shareable public link
$("public").checked = state.public;

function url(path, params = {}) {
  const q = new URLSearchParams(params);
  if (state.public) q.set("public", "1");
  const s = q.toString();
  return "/v1/" + path + (s ? "?" + s : "");
}

async function getJSON(path, params) {
  const r = await fetch(url(path, params), { cache: "no-store" });
  if (!r.ok) throw new Error((await r.text()).trim() || path + ": " + r.status);
  return r.json();
}

const fmt = (ms) => (ms === undefined || ms === null ? "—" : ms < 10 ? ms.toFixed(2) + " ms" : ms.toFixed(1) + " ms");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const local = (t) => new Date(t).toLocaleTimeString();

function el(tag, attrs = {}, html = "") {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  e.innerHTML = html;
  return e;
}

// --- targets -------------------------------------------------------------

function drawTargets() {
  const ul = $("targets");
  ul.replaceChildren();
  for (const t of state.targets) {
    const last = t.last || {};
    const b = el("button", { type: "button", "aria-pressed": String(t.target === state.selected) },
      `<span class="dot ${esc((t.state || "").replace(" ", "-"))}"></span>${esc(t.target)}<br>` +
      `<span class="small">min ${fmt(last.min_ms)} · p50 ${fmt(last.p50_ms)} · p95 ${fmt(last.p95_ms)} · loss ${last.loss_pct === undefined ? "—" : last.loss_pct.toFixed(0) + " %"}</span>`);
    b.addEventListener("click", () => select(t.target));
    const li = el("li");
    li.append(b);
    ul.append(li);
  }
}

async function refreshTargets() {
  state.targets = (await getJSON("targets")) || [];
  if (!state.selected && state.targets.length) state.selected = state.targets[0].target;
  drawTargets();
}

async function select(target) {
  state.selected = target;
  drawTargets();
  state.rounds[target] = (await getJSON(`targets/${encodeURIComponent(target)}/rounds`, { n: KEEP })) || [];
  await refreshHops();
  draw();
}

// --- judged path ---------------------------------------------------------

async function refreshHops() {
  if (!state.selected) return;
  const recs = await getJSON(`targets/${encodeURIComponent(state.selected)}/hops`);
  const tb = $("hops").tBodies[0];
  tb.replaceChildren();
  for (const r of recs) {
    const inf = r.info || {};
    let net = "";
    if (r.home) net = "[home]";
    else if (inf.ixp) net = "IXP " + (inf.ixp.name || "");
    else if (inf.as && inf.as.length) net = "AS" + inf.as[0].asn + " " + (inf.as[0].name || "");
    else if (inf.class && inf.class !== "public") net = inf.class;
    const loc = r.location ? `${r.location.city}, ${r.location.country}${r.location.weak ? "?" : ""} [${r.location.source}]` : "";
    tb.append(el("tr", {}, `<td class="num">${r.ttl}</td><td>${esc(r.home ? "" : r.addr || "*")}</td><td>${esc(net)}</td>` +
      `<td class="loc">${esc(loc)}</td><td class="num">${r.min_rtt_ms < 0 ? "*" : fmt(r.min_rtt_ms)}</td><td class="flags">${esc((r.flags || []).join(" "))}</td>`));
  }
}

// --- canvases ------------------------------------------------------------

function sized(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.height / (canvas.dataset.dpr || 1);
  canvas.dataset.dpr = dpr;
  canvas.width = Math.round(w * dpr);
  canvas.height = Math.round(h * dpr);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w, h };
}

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

// Perceptual ramp (viridis stops); t in [0, 1].
const STOPS = [[68, 1, 84], [59, 82, 139], [33, 145, 140], [94, 201, 98], [253, 231, 37]];
function ramp(t) {
  t = Math.max(0, Math.min(1, t)) * (STOPS.length - 1);
  const i = Math.min(STOPS.length - 2, Math.floor(t)), f = t - i;
  const c = STOPS[i].map((v, k) => Math.round(v + (STOPS[i + 1][k] - v) * f));
  return `rgb(${c[0]},${c[1]},${c[2]})`;
}
const rttColor = (ms) => ramp(Math.log10(Math.max(1, ms)) / Math.log10(400));

function drawHeat() {
  const rounds = state.rounds[state.selected] || [];
  const { ctx, w, h } = sized($("heat"));
  ctx.clearRect(0, 0, w, h);
  if (!rounds.length) return;
  let maxTTL = 1;
  for (const r of rounds) for (const p of r.hops) maxTTL = Math.max(maxTTL, p.ttl);
  const left = 28, cw = (w - left) / rounds.length, ch = h / maxTTL;
  ctx.fillStyle = css("--muted");
  ctx.font = "11px system-ui";
  for (let t = 1; t <= maxTTL; t += Math.max(1, Math.round(maxTTL / 8))) ctx.fillText(String(t), 2, t * ch - ch / 2 + 4);
  rounds.forEach((r, i) => {
    for (const p of r.hops) {
      ctx.fillStyle = p.rtt_ms === undefined ? css("--gap") : rttColor(p.rtt_ms);
      ctx.fillRect(left + i * cw, (p.ttl - 1) * ch, Math.ceil(cw), Math.ceil(ch));
    }
  });
}

function targetRTT(r) {
  let best;
  for (const p of r.hops) if (p.addr === r.target && p.rtt_ms !== undefined && (best === undefined || p.rtt_ms < best)) best = p.rtt_ms;
  return best;
}

function drawRTT() {
  const rounds = state.rounds[state.selected] || [];
  const { ctx, w, h } = sized($("rtt"));
  ctx.clearRect(0, 0, w, h);
  const ys = rounds.map(targetRTT);
  const vals = ys.filter((v) => v !== undefined);
  if (!vals.length) { $("summary").textContent = "no reply from the target in this window"; return; }
  let lo = Math.min(...vals), hi = Math.max(...vals);
  if (hi - lo < 1) { lo -= 0.5; hi += 0.5; }
  const pad = 18, x = (i) => (i / Math.max(1, rounds.length - 1)) * (w - 50) + 45, y = (v) => h - pad - ((v - lo) / (hi - lo)) * (h - 2 * pad);
  ctx.fillStyle = css("--muted");
  ctx.font = "11px system-ui";
  ctx.fillText(fmt(hi), 2, pad);
  ctx.fillText(fmt(lo), 2, h - pad);
  // route changes of this target in the window
  const t0 = rounds.length ? Date.parse(rounds[0].start) : 0, t1 = rounds.length ? Date.parse(rounds[rounds.length - 1].start) : 0;
  for (const e of state.events) {
    const t = Date.parse(e.time);
    if (e.target !== state.selected || e.state === "dropped" || t < t0 || t > t1 || t1 === t0) continue;
    const xe = 45 + ((t - t0) / (t1 - t0)) * (w - 50);
    ctx.strokeStyle = e.state === "confirmed" ? css("--bad") : css("--warn");
    ctx.setLineDash([4, 3]);
    ctx.beginPath(); ctx.moveTo(xe, 0); ctx.lineTo(xe, h); ctx.stroke();
    ctx.setLineDash([]);
  }
  ctx.strokeStyle = css("--accent");
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  let pen = false;
  ys.forEach((v, i) => {
    if (v === undefined) { pen = false; return; } // a gap stays a gap, never 0
    pen ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v));
    pen = true;
  });
  ctx.stroke();
  const s = [...vals].sort((a, b) => a - b), q = (p) => s[Math.max(0, Math.ceil(p * s.length) - 1)];
  $("summary").textContent = `${vals.length} of ${rounds.length} rounds answered · min ${fmt(s[0])} · median ${fmt(q(0.5))}` +
    (s.length >= 59 ? ` · p95 ${fmt(q(0.95))}` : " · p95 needs 59 samples");
}

let pending = false;
function draw() {
  if (pending) return;
  pending = true;
  requestAnimationFrame(() => { pending = false; drawHeat(); drawRTT(); });
}

// --- events and health ---------------------------------------------------

function drawEvents() {
  const ol = $("events");
  ol.replaceChildren();
  const shown = state.events.slice(-50).reverse();
  if (!shown.length) ol.append(el("li", { class: "muted" }, "none yet"));
  for (const e of shown) {
    const rtt = e.rtt_before_ms !== undefined || e.rtt_after_ms !== undefined ? ` · RTT ${fmt(e.rtt_before_ms)} → ${fmt(e.rtt_after_ms)}` : "";
    ol.append(el("li", {}, `${esc(local(e.time))} <b>${esc(e.target)}</b> <span class="state-${esc(e.state)}">${esc(e.state)}</span>` +
      ` at TTL ${e.ttl}: AS ${esc((e.before_as || []).join(" › "))} → ${esc((e.after_as || []).join(" › "))}${rtt}`));
  }
}

function drawHealth(hv) {
  const n = hv.node || {};
  $("node").textContent = `node ${n.version || "?"} · clock ${n.clock_synced ? "synced" : "NOT synced"}` +
    (n.temp_c ? ` · ${n.temp_c.toFixed(1)} °C` : "") + (n.disk_free_mb ? ` · ${(n.disk_free_mb / 1024).toFixed(0)} GiB free` : "") +
    (n.rss_mb ? ` · ${n.rss_mb} MB in memory` : "");
  const tb = $("health").tBodies[0];
  tb.replaceChildren();
  for (const t of hv.targets || []) {
    tb.append(el("tr", {}, `<td>${esc(t.target)}</td><td><span class="dot ${esc(t.state.replace(" ", "-"))}"></span>${esc(t.state)}` +
      `${t.error ? ' <span class="small">' + esc(t.error) + "</span>" : ""}</td><td class="num">${t.rounds}</td><td class="num">${t.replied}</td>` +
      `<td class="num">${t.no_reply}</td><td class="num">${t.send_errors}</td><td class="num">${t.sessions}</td><td class="num">${Math.round(t.lag_ms)} ms</td>`));
    const tt = state.targets.find((x) => x.target === t.target);
    if (tt) tt.state = t.state;
  }
}

// Screen latency: from the last reply of a round (send time estimated from
// the TTL and the spacing, plus its RTT) to now.
function noteLatency(r) {
  let lastReply = 0;
  const t0 = Date.parse(r.start);
  for (const p of r.hops) if (p.rtt_ms !== undefined) lastReply = Math.max(lastReply, t0 + (p.ttl - 1) * SPACING_MS + p.rtt_ms);
  if (!lastReply) return;
  state.lat.push((Date.now() - lastReply) / 1000);
  if (state.lat.length > 150) state.lat.shift();
  const s = [...state.lat].sort((a, b) => a - b);
  $("latency").textContent = `· on screen ${s[Math.floor(s.length / 2)].toFixed(1)} s after the last reply (median of ${s.length}; max ${s[s.length - 1].toFixed(1)} s)`;
}

// --- stream --------------------------------------------------------------

function connect() {
  if (state.es) state.es.close();
  state.es = new EventSource(url("stream"));
  state.es.addEventListener("round", (m) => {
    const r = JSON.parse(m.data);
    const buf = (state.rounds[r.target] ||= []);
    buf.push(r);
    if (buf.length > KEEP) buf.shift();
    if (r.target === state.selected) { noteLatency(r); draw(); }
  });
  state.es.addEventListener("event", (m) => {
    state.events.push(JSON.parse(m.data));
    if (state.events.length > 1000) state.events.shift();
    drawEvents();
    draw();
  });
  state.es.addEventListener("health", (m) => drawHealth(JSON.parse(m.data)));
  state.es.onerror = () => { $("node").textContent = "stream lost; the browser reconnects…"; };
}

async function start() {
  state.rounds = {};
  state.lat = [];
  await refreshTargets();
  state.events = (await getJSON("events", { n: 1000 })) || [];
  drawEvents();
  drawHealth(await getJSON("health"));
  connect();
  if (state.selected) await select(state.selected);
}

$("public").addEventListener("change", (e) => {
  state.public = e.target.checked;
  try { localStorage.setItem("public", state.public ? "1" : "0"); } catch (err) { /* blocked */ }
  start().catch(failed);
});
window.addEventListener("resize", draw);
setInterval(() => { refreshHops().catch(() => {}); refreshTargets().catch(() => {}); }, HOPS_EVERY);
const failed = (e) => { $("node").textContent = "cannot load: " + e.message; };
start().catch(failed);
