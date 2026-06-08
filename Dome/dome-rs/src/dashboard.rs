/// Admin dashboard – axum routes + embedded HTML/JS UI.
///
/// Served on a separate port (default 9000) from the WAF proxy.
/// Routes:
///   GET  /               → dashboard HTML (single-page app)
///   GET  /api/stats      → JSON: counters snapshot
///   GET  /api/events     → JSON: last N events (newest first)
///   GET  /api/top-ips    → JSON: top blocked IPs
///   GET  /api/top-rules  → JSON: top fired rules
///   POST /api/mode       → switch WAF mode at runtime (block/detect)
///   GET  /health         → 200 OK

use axum::{
    Router,
    routing::{get, post},
    extract::State,
    response::{Html, Json, IntoResponse},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::stats::Stats;

// ── Dashboard state ───────────────────────────────────────────────────────────

pub struct DashState {
    pub stats: Arc<Stats>,
    /// Current WAF mode – can be changed at runtime
    pub mode:  Arc<RwLock<String>>,
}

// ── Router factory ────────────────────────────────────────────────────────────

pub fn router(state: Arc<DashState>) -> Router {
    Router::new()
        .route("/",              get(index))
        .route("/health",        get(health))
        .route("/api/stats",     get(api_stats))
        .route("/api/events",    get(api_events))
        .route("/api/top-ips",   get(api_top_ips))
        .route("/api/top-rules", get(api_top_rules))
        .route("/api/mode",      post(api_set_mode))
        .with_state(state)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn health() -> &'static str { "OK" }

async fn index() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn api_stats(State(s): State<Arc<DashState>>) -> impl IntoResponse {
    let snap = s.stats.snapshot();
    let mode = s.mode.read().await.clone();

    #[derive(Serialize)]
    struct Resp {
        total: u64, allowed: u64, blocked: u64,
        logged: u64, challenged: u64, errors: u64,
        mode: String,
    }
    Json(Resp {
        total: snap.total, allowed: snap.allowed, blocked: snap.blocked,
        logged: snap.logged, challenged: snap.challenged, errors: snap.errors,
        mode,
    })
}

async fn api_events(State(s): State<Arc<DashState>>) -> impl IntoResponse {
    let mut events = s.stats.recent_events(200);
    events.reverse(); // newest first
    Json(events)
}

async fn api_top_ips(State(s): State<Arc<DashState>>) -> impl IntoResponse {
    #[derive(Serialize)]
    struct Row { ip: String, count: u64 }
    let rows: Vec<Row> = s.stats.top_ips(20)
        .into_iter().map(|(ip, c)| Row { ip, count: c }).collect();
    Json(rows)
}

async fn api_top_rules(State(s): State<Arc<DashState>>) -> impl IntoResponse {
    #[derive(Serialize)]
    struct Row { rule: String, count: u64 }
    let rows: Vec<Row> = s.stats.top_rules(20)
        .into_iter().map(|(r, c)| Row { rule: r, count: c }).collect();
    Json(rows)
}

#[derive(Deserialize)]
struct ModeBody { mode: String }

async fn api_set_mode(
    State(s): State<Arc<DashState>>,
    Json(body): Json<ModeBody>,
) -> impl IntoResponse {
    let m = body.mode.to_lowercase();
    if m != "block" && m != "detect" {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"mode must be block or detect"}))).into_response();
    }
    *s.mode.write().await = m.clone();
    tracing::info!("WAF mode changed to {m} via dashboard");
    (StatusCode::OK, Json(serde_json::json!({"mode": m}))).into_response()
}

// ── Embedded single-file dashboard HTML ──────────────────────────────────────

static DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dome WAF Dashboard</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
    --blue: #58a6ff; --purple: #bc8cff; --text: #c9d1d9;
    --dim: #6e7681; --radius: 8px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
  header { background: var(--panel); border-bottom: 1px solid var(--border); padding: 14px 24px; display:flex; align-items:center; gap:12px; }
  header h1 { font-size:18px; font-weight:600; letter-spacing:.5px; }
  header .badge { background:#21262d; border:1px solid var(--border); border-radius:20px; padding:3px 10px; font-size:12px; }
  #mode-badge { font-weight:700; }
  #mode-badge.block  { color: var(--red); border-color: var(--red); }
  #mode-badge.detect { color: var(--yellow); border-color: var(--yellow); }
  .mode-btn { margin-left:auto; background:#21262d; border:1px solid var(--border); color:var(--text); padding:5px 14px; border-radius:6px; cursor:pointer; font-size:13px; }
  .mode-btn:hover { background:#30363d; }

  main { padding: 20px 24px; max-width: 1400px; margin: 0 auto; }
  .grid-4 { display:grid; grid-template-columns: repeat(4,1fr); gap:14px; margin-bottom:20px; }
  .grid-2 { display:grid; grid-template-columns: 1fr 1fr; gap:14px; margin-bottom:20px; }

  .card { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 18px; }
  .card h3 { font-size:12px; color:var(--dim); text-transform:uppercase; letter-spacing:.8px; margin-bottom:10px; }

  .stat-val { font-size:32px; font-weight:700; line-height:1; }
  .stat-val.green   { color: var(--green); }
  .stat-val.red     { color: var(--red); }
  .stat-val.yellow  { color: var(--yellow); }
  .stat-val.blue    { color: var(--blue); }
  .stat-val.purple  { color: var(--purple); }
  .stat-val.dim     { color: var(--dim); }

  table { width:100%; border-collapse:collapse; font-size:13px; }
  thead th { color:var(--dim); font-weight:500; padding:6px 8px; text-align:left; border-bottom:1px solid var(--border); font-size:11px; text-transform:uppercase; }
  tbody tr { border-bottom:1px solid #21262d; }
  tbody tr:hover { background:#1c2128; }
  td { padding:7px 8px; font-family: monospace; white-space: nowrap; overflow:hidden; text-overflow:ellipsis; max-width:260px; }
  .tag { display:inline-block; padding:2px 7px; border-radius:4px; font-size:11px; font-weight:600; }
  .tag.BLOCK     { background:#3d1111; color:#f85149; }
  .tag.LOG       { background:#2d2500; color:#d29922; }
  .tag.ALLOW     { background:#0d2e1a; color:#3fb950; }
  .tag.CHALLENGE { background:#1a1a3d; color:#58a6ff; }
  .tag.DLP       { background:#2d1a3d; color:#bc8cff; }
  .tag.ERROR     { background:#2d2d2d; color:#8b949e; }

  .bar-row { display:flex; align-items:center; gap:8px; margin-bottom:6px; }
  .bar-label { width:160px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:12px; font-family:monospace; }
  .bar-track { flex:1; background:#21262d; border-radius:3px; height:10px; overflow:hidden; }
  .bar-fill { height:100%; border-radius:3px; transition:width .4s; }
  .bar-fill.red    { background: var(--red); }
  .bar-fill.blue   { background: var(--blue); }
  .bar-count { width:40px; text-align:right; font-size:11px; color:var(--dim); }

  #refresh-info { color:var(--dim); font-size:11px; margin-left:auto; }
  .section-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; }
  .section-title { font-weight:600; font-size:15px; }
  .dot { display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--green); margin-right:6px; animation:pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1}50%{opacity:.3} }
</style>
</head>
<body>

<header>
  <span>🛡️</span>
  <h1>Dome WAF</h1>
  <span class="badge">v1.0.0 · Rust</span>
  <span class="badge" id="mode-badge">—</span>
  <button class="mode-btn" onclick="toggleMode()">Toggle Mode</button>
  <span id="refresh-info">Refreshing…</span>
</header>

<main>
  <!-- Counters -->
  <div class="grid-4">
    <div class="card"><h3>Total Requests</h3><div class="stat-val blue" id="s-total">—</div></div>
    <div class="card"><h3>Blocked</h3>        <div class="stat-val red"    id="s-blocked">—</div></div>
    <div class="card"><h3>Flagged (LOG)</h3>  <div class="stat-val yellow" id="s-logged">—</div></div>
    <div class="card"><h3>Allowed</h3>        <div class="stat-val green"  id="s-allowed">—</div></div>
  </div>
  <div class="grid-4">
    <div class="card"><h3>Challenged</h3><div class="stat-val purple" id="s-chal">—</div></div>
    <div class="card"><h3>Errors</h3>    <div class="stat-val dim"    id="s-errors">—</div></div>
    <div class="card"><h3>Block Rate</h3><div class="stat-val red"    id="s-blockrate">—</div></div>
    <div class="card"><h3>Threat Rate</h3><div class="stat-val yellow" id="s-threatrate">—</div></div>
  </div>

  <!-- Top IPs + Top Rules -->
  <div class="grid-2">
    <div class="card">
      <div class="section-header">
        <span class="section-title">Top Threat IPs</span>
      </div>
      <div id="top-ips"></div>
    </div>
    <div class="card">
      <div class="section-header">
        <span class="section-title">Top Fired Rules</span>
      </div>
      <div id="top-rules"></div>
    </div>
  </div>

  <!-- Recent Events -->
  <div class="card">
    <div class="section-header">
      <span class="section-title"><span class="dot"></span>Recent Events</span>
      <span style="color:var(--dim);font-size:12px">Last 200 • live feed</span>
    </div>
    <div style="overflow-x:auto">
    <table>
      <thead>
        <tr>
          <th>Time</th><th>Action</th><th>IP</th>
          <th>Method</th><th>Path</th><th>Score</th>
          <th>Rules</th><th>Status</th><th>ms</th>
        </tr>
      </thead>
      <tbody id="events-body"></tbody>
    </table>
    </div>
  </div>
</main>

<script>
const fmt = n => Number(n).toLocaleString();
const pct = (a, b) => b > 0 ? ((a/b)*100).toFixed(1)+'%' : '0%';

function ts(unix) {
  const d = new Date(unix * 1000);
  return d.toLocaleTimeString();
}

async function fetchStats() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    document.getElementById('s-total').textContent    = fmt(d.total);
    document.getElementById('s-blocked').textContent  = fmt(d.blocked);
    document.getElementById('s-logged').textContent   = fmt(d.logged);
    document.getElementById('s-allowed').textContent  = fmt(d.allowed);
    document.getElementById('s-chal').textContent     = fmt(d.challenged);
    document.getElementById('s-errors').textContent   = fmt(d.errors);
    document.getElementById('s-blockrate').textContent  = pct(d.blocked, d.total);
    document.getElementById('s-threatrate').textContent = pct(d.blocked + d.logged + d.challenged, d.total);

    const mb = document.getElementById('mode-badge');
    mb.textContent = d.mode.toUpperCase();
    mb.className = '';
    mb.classList.add(d.mode);
  } catch(e) { console.error('stats', e); }
}

async function fetchEvents() {
  try {
    const r = await fetch('/api/events');
    const events = await r.json();
    const tbody = document.getElementById('events-body');
    tbody.innerHTML = events.slice(0, 100).map(e => `
      <tr>
        <td>${ts(e.ts)}</td>
        <td><span class="tag ${e.action}">${e.action}</span></td>
        <td>${e.ip}</td>
        <td>${e.method}</td>
        <td title="${e.path}">${e.path}</td>
        <td>${e.score > 0 ? '<span style="color:var(--red)">'+e.score+'</span>' : '<span style="color:var(--dim)">0</span>'}</td>
        <td style="color:var(--yellow);max-width:200px" title="${e.rules}">${e.rules || '—'}</td>
        <td>${e.status}</td>
        <td>${e.elapsed_ms.toFixed(1)}</td>
      </tr>`).join('');
  } catch(e) { console.error('events', e); }
}

function renderBars(containerId, data, colorClass) {
  const max = data.length > 0 ? data[0].count : 1;
  document.getElementById(containerId).innerHTML = data.map(r => {
    const label = r.ip || r.rule;
    const pct = Math.max(4, (r.count / max) * 100);
    return `<div class="bar-row">
      <div class="bar-label" title="${label}">${label}</div>
      <div class="bar-track"><div class="bar-fill ${colorClass}" style="width:${pct}%"></div></div>
      <div class="bar-count">${fmt(r.count)}</div>
    </div>`;
  }).join('');
}

async function fetchTopIPs() {
  try {
    const r = await fetch('/api/top-ips');
    renderBars('top-ips', await r.json(), 'red');
  } catch(e) {}
}

async function fetchTopRules() {
  try {
    const r = await fetch('/api/top-rules');
    renderBars('top-rules', await r.json(), 'blue');
  } catch(e) {}
}

async function toggleMode() {
  const mb = document.getElementById('mode-badge');
  const cur = mb.textContent.toLowerCase();
  const next = cur === 'block' ? 'detect' : 'block';
  try {
    await fetch('/api/mode', {
      method: 'POST',
      headers: {'content-type':'application/json'},
      body: JSON.stringify({mode: next})
    });
    await fetchStats();
  } catch(e) {}
}

async function refresh() {
  await Promise.all([fetchStats(), fetchEvents(), fetchTopIPs(), fetchTopRules()]);
  document.getElementById('refresh-info').textContent =
    'Updated ' + new Date().toLocaleTimeString();
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"#;
