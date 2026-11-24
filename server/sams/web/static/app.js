// SAMS dashboard: vanilla JS, no build step, no third-party code.
// Everything rendered goes through `html` which escapes interpolated values:
// agent, log and probe data is untrusted and must never become markup.
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const TOKEN_KEY = "sams_admin_token";
let token = (() => { try { return localStorage.getItem(TOKEN_KEY) || ""; } catch { return ""; } })();

class Raw { constructor(s) { this.s = s; } toString() { return this.s; } }
const raw = (s) => new Raw(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function html(strings, ...vals) {
  let out = strings[0];
  vals.forEach((v, i) => {
    if (Array.isArray(v)) out += v.map((x) => (x instanceof Raw ? x.s : esc(x))).join("");
    else out += v instanceof Raw ? v.s : esc(v);
    out += strings[i + 1];
  });
  return raw(out);
}

async function api(path, opts = {}) {
  const headers = { Authorization: `Bearer ${token}`, ...(opts.headers || {}) };
  let body = opts.body;
  if (body && typeof body === "object" && !(body instanceof Blob) && !(body instanceof ArrayBuffer)) {
    body = JSON.stringify(body); headers["Content-Type"] = "application/json";
  }
  const r = await fetch(path, { ...opts, headers, body });
  if (r.status === 401) { showLogin(); throw new Error("unauthorized"); }
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.detail) || r.statusText);
  return data;
}

function toast(msg, ms = 3500) {
  const t = $("#toast"); t.textContent = msg; t.classList.remove("hidden");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add("hidden"), ms);
}
const sev = (s) => html`<span class="sev ${s}">${s}</span>`;
const fmtTime = (t) => (t ? new Date(t).toLocaleString() : "–");
const pct = (x) => `${Math.round((x || 0) * 100)}%`;
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function render(content) { $("#main").innerHTML = String(content); }
function drawer(content) {
  closeDrawer();
  const bg = document.createElement("div"); bg.className = "drawer-bg"; bg.onclick = closeDrawer;
  const d = document.createElement("div"); d.className = "drawer";
  d.innerHTML = String(html`<button class="secondary close" aria-label="Close">✕</button>`) + String(content);
  d.querySelector(".close").onclick = closeDrawer;
  document.body.append(bg, d);
  return d;
}
function closeDrawer() { document.querySelectorAll(".drawer, .drawer-bg").forEach((e) => e.remove()); }
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

// ------------------------------------------------------------------ login
function showLogin() { $("#app").classList.add("hidden"); $("#login").classList.remove("hidden"); }
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  token = $("#token-input").value.trim();
  try { await api("/api/v1/status"); try { localStorage.setItem(TOKEN_KEY, token); } catch {} start(); }
  catch (err) { $("#login-error").textContent = "Invalid token"; }
});
$("#logout").onclick = () => { try { localStorage.removeItem(TOKEN_KEY); } catch {} token = ""; showLogin(); };

// ------------------------------------------------------------------ pages
const pages = {
  async overview() {
    const [st, posture, paths, plan, alerts] = await Promise.all([
      api("/api/v1/status"), api("/api/v1/posture"), api("/api/v1/graph/paths?k=5"),
      api("/api/v1/remediation/plan?limit=6"), api("/api/v1/alerts?status=open&limit=6")]);
    const c = st.counts.severity || {};
    render(html`
      <div class="page-head"><div><h1>Security posture</h1><div class="muted">${st.counts.assets} assets · ${st.agents} agents · ${st.probes} external probes · ${st.firewalls} firewalls</div></div></div>
      <div class="grid kpis">
        <div class="card kpi"><div class="label">Posture</div><div class="row" style="margin-top:6px"><span class="grade ${st.grade}">${st.grade}</span><span class="value">${st.score}</span></div></div>
        <div class="card kpi"><div class="label">Critical</div><div class="value" style="color:var(--crit)">${c.critical || 0}</div></div>
        <div class="card kpi"><div class="label">High</div><div class="value" style="color:var(--high)">${c.high || 0}</div></div>
        <div class="card kpi"><div class="label">Internet attack paths</div><div class="value">${st.internet_attack_paths}</div></div>
        <div class="card kpi"><div class="label">Open alerts</div><div class="value">${st.open_alerts}</div></div>
      </div>
      <div class="grid two">
        <div class="card"><h2>Top attack paths from the internet</h2>
          ${paths.length ? paths.map((p) => html`<div style="margin-bottom:10px"><a href="#/paths" data-target="${p.target}">${p.target_label}</a>
            <div class="row"><div class="bar" style="flex:1"><span style="width:${pct(p.likelihood)}"></span></div><span class="mono">${pct(p.likelihood)}</span><span class="muted">${p.edges.length} steps</span></div></div>`)
            : html`<div class="empty">No internet attack paths found. 🎉</div>`}
        </div>
        <div class="card"><h2>Fix these first</h2>
          ${plan.items.length ? html`<table>${plan.items.map((i) => html`<tr><td>${sev(i.severity)}</td><td>${i.title}<div class="muted">${i.asset_names.join(", ")}</div></td><td class="mono">${i.risk_reduction_pct ? `−${i.risk_reduction_pct}%` : ""}</td></tr>`)}</table>`
            : html`<div class="empty">Nothing to fix.</div>`}
          <p><a href="#/plan">Full remediation plan →</a></p>
        </div>
        <div class="card"><h2>Least secure hosts</h2>
          <table>${posture.hosts.slice(0, 8).map((h) => html`<tr class="click" data-asset="${h.asset_id}"><td><span class="grade ${h.grade}" style="width:28px;height:28px;font-size:14px;border-radius:8px">${h.grade}</span></td><td>${h.name}<div class="muted">${h.kind}</div></td><td class="mono">${h.score}</td><td>${SEV_ORDER.filter((s) => h.counts[s]).map((s) => html`<span class="pill">${h.counts[s]} ${s}</span>`)}</td></tr>`)}</table>
        </div>
        <div class="card"><h2>Recent alerts</h2>
          ${alerts.length ? html`<table>${alerts.map((a) => html`<tr class="click" data-alert="${a.id}"><td>${sev(a.severity)}</td><td>${a.title}<div class="muted">${a.host} · ${fmtTime(a.created_at)}</div></td></tr>`)}</table>`
            : html`<div class="empty">No open alerts.</div>`}
        </div>
      </div>`);
    bindRowLinks();
  },

  async assets() {
    const assets = await api("/api/v1/assets");
    render(html`<div class="page-head"><div><h1>Assets</h1><div class="muted">Hosts with agents, firewalls, and external targets. Set criticality to mark crown jewels.</div></div></div>
      <div class="card table-wrap"><table><thead><tr><th>Name</th><th>Kind</th><th>Criticality</th><th>Score</th><th>Findings</th><th>Details</th><th>Last seen</th></tr></thead><tbody>
      ${assets.map((a) => html`<tr class="click" data-asset="${a.id}"><td><b>${a.name}</b><div class="muted mono">${a.id}</div></td><td>${a.kind}</td>
        <td>${"★".repeat(a.criticality)}<span class="muted">${"★".repeat(5 - a.criticality)}</span></td>
        <td>${a.posture ? html`<span class="grade ${a.posture.grade}" style="width:28px;height:28px;font-size:14px;border-radius:8px">${a.posture.grade}</span> <span class="mono">${a.posture.score}</span>` : ""}</td>
        <td>${a.posture ? SEV_ORDER.filter((s) => a.posture.counts[s]).map((s) => html`<span class="pill">${a.posture.counts[s]} ${s}</span>`) : ""}</td>
        <td class="muted">${a.data.os || a.data.vendor || ""} ${(a.data.ips || a.data.wan_addresses || []).join(", ")}</td><td class="muted">${fmtTime(a.last_seen)}</td></tr>`)}
      </tbody></table>${assets.length ? "" : html`<div class="empty">No assets yet. Enroll an agent from the Agents page, import a firewall, or run <code>sams demo</code>.</div>`}</div>`);
    bindRowLinks();
  },

  async findings(params) {
    const q = new URLSearchParams(params || {});
    const fs = await api(`/api/v1/findings?${q}`);
    render(html`<div class="page-head"><div><h1>Findings</h1><div class="muted">${fs.length} ${q.get("status") || "open"} findings</div></div></div>
      <div class="filters">
        <select id="f-sev"><option value="">All severities</option>${SEV_ORDER.map((s) => html`<option ${q.get("severity") === s ? raw("selected") : ""}>${s}</option>`)}</select>
        <select id="f-cat"><option value="">All categories</option>${["vulnerability", "hardening", "credential", "exposure", "firewall", "external", "attack_path", "detection"].map((s) => html`<option ${q.get("category") === s ? raw("selected") : ""}>${s}</option>`)}</select>
        <select id="f-status">${["open", "accepted", "fixed", "false_positive"].map((s) => html`<option ${(q.get("status") || "open") === s ? raw("selected") : ""}>${s}</option>`)}</select>
      </div>
      <div class="card table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Asset</th><th>Last seen</th></tr></thead><tbody>
      ${fs.map((f) => html`<tr class="click" data-finding="${f.key}"><td>${sev(f.severity)}</td><td>${f.title}</td><td>${f.category}</td><td class="mono">${f.asset_id || "–"}</td><td class="muted">${fmtTime(f.last_seen)}</td></tr>`)}
      </tbody></table>${fs.length ? "" : html`<div class="empty">No findings match.</div>`}</div>`);
    const go = () => { const p = {}; const s = $("#f-sev").value, c = $("#f-cat").value, st = $("#f-status").value; if (s) p.severity = s; if (c) p.category = c; if (st) p.status = st; pages.findings(p); };
    ["#f-sev", "#f-cat", "#f-status"].forEach((id) => ($(id).onchange = go));
    bindRowLinks();
  },

  async paths(params) {
    const assets = await api("/api/v1/assets?kind=host");
    render(html`<div class="page-head"><div><h1>Attack paths</h1><div class="muted">Evidence-based routes an attacker can take, scored by likelihood. Pick a starting point to see its blast radius.</div></div></div>
      <div class="card" style="margin-bottom:16px"><div class="row">
        <label>Start from</label><select id="p-src"><option value="internet">🌐 The internet</option>${assets.map((a) => html`<option value="${a.id}">💻 ${a.name} (fully compromised)</option>`)}</select>
        <button id="p-go">Analyze</button></div></div>
      <div id="p-out"></div>`);
    const run = async () => {
      const src = $("#p-src").value; const out = $("#p-out"); out.innerHTML = '<div class="loading">Computing…</div>';
      if (src === "internet") {
        const paths = await api(`/api/v1/graph/paths?source=internet&k=10`);
        out.innerHTML = String(paths.length ? html`${paths.map((p, i) => pathCard(p, i))}` : html`<div class="empty">No paths from the internet to critical assets. Import your firewall config and run an external scan to be sure.</div>`);
      } else {
        const br = await api(`/api/v1/graph/blast-radius/${encodeURIComponent(src)}`);
        out.innerHTML = String(blastRadiusView(br));
      }
    };
    $("#p-go").onclick = run; run();
  },

  async plan() {
    const plan = await api("/api/v1/remediation/plan?limit=200");
    const s = plan.summary;
    render(html`<div class="page-head"><div><h1>Remediation plan</h1><div class="muted">Ordered by how much attack-path risk each fix removes. Total risk ${s.total_risk} (external ${s.external_risk}).</div></div></div>
      <div class="card table-wrap"><table><thead><tr><th>#</th><th>Severity</th><th>Action</th><th>Assets</th><th>Risk removed</th><th></th></tr></thead><tbody>
      ${plan.items.map((i) => html`<tr><td class="mono">${i.rank}</td><td>${sev(i.severity)}</td>
        <td><b>${i.title}</b><div class="muted">${i.kind} · ${i.reason === "attack_path" ? "breaks attack paths" : "hygiene"}</div>
          ${i.remediation.commands && i.remediation.commands.length ? html`<details><summary class="muted">How</summary>${i.remediation.details ? html`<p>${i.remediation.details}</p>` : ""}<pre>${i.remediation.commands.join("\n")}</pre></details>` : i.remediation.details ? html`<details><summary class="muted">How</summary><p>${i.remediation.details}</p></details>` : ""}</td>
        <td>${i.asset_names.join(", ")}</td>
        <td>${i.risk_reduction_pct ? html`<div class="row"><div class="bar"><span style="width:${Math.min(100, i.risk_reduction_pct)}%"></span></div><span class="mono">${i.risk_reduction_pct}%</span></div>` : html`<span class="muted">–</span>`}</td>
        <td>${i.automatable && i.finding_keys.length ? html`<button class="secondary" data-patch="${i.finding_keys[0]}">Patch via agent</button>` : ""}</td></tr>`)}
      </tbody></table></div>`);
    document.querySelectorAll("[data-patch]").forEach((b) => (b.onclick = async () => {
      try { const t = await api(`/api/v1/findings/${encodeURIComponent(b.dataset.patch)}/task?dry_run=true`, { method: "POST" });
        toast(`Dry-run task ${t.id} created. Approve it on the Agents page.`); }
      catch (e) { toast(e.message); }
    }));
  },

  async siem(params) {
    const q = new URLSearchParams(params || {});
    const [alerts, events, stats] = await Promise.all([api("/api/v1/alerts?limit=100"), api(`/api/v1/events?limit=200&${q}`), api("/api/v1/events/stats?group_by=action")]);
    render(html`<div class="page-head"><div><h1>SIEM</h1><div class="muted">Agents ship auth logs; firewalls and other devices send syslog to UDP/TCP 5514.</div></div></div>
      <div class="grid two">
        <div class="card"><h2>Alerts</h2>${alerts.length ? html`<table>${alerts.map((a) => html`<tr class="click" data-alert="${a.id}"><td>${sev(a.severity)}</td><td>${a.title}<div class="muted">${a.host || ""} · ${fmtTime(a.created_at)} · ${a.status}</div></td><td>${(a.mitre || []).map((m) => html`<span class="pill">${m}</span>`)}</td></tr>`)}</table>` : html`<div class="empty">No alerts.</div>`}</div>
        <div class="card"><h2>Activity (24h)</h2>${Object.keys(stats).length ? html`<table>${Object.entries(stats).slice(0, 14).map(([k, v]) => html`<tr><td>${k || "(none)"}</td><td class="mono">${v}</td></tr>`)}</table>` : html`<div class="empty">No events yet.</div>`}</div>
      </div>
      <div class="card" style="margin-top:16px"><h2>Events</h2>
        <form id="ev-form" class="filters"><input name="q" placeholder="search text" value="${q.get("q") || ""}"><input name="host" placeholder="host" value="${q.get("host") || ""}"><input name="src_ip" placeholder="source IP" value="${q.get("src_ip") || ""}"><input name="action" placeholder="action" value="${q.get("action") || ""}"><button>Search</button></form>
        <div class="table-wrap"><table><thead><tr><th>Time</th><th>Host</th><th>Action</th><th>User</th><th>Source</th><th>Message</th></tr></thead><tbody>
        ${events.map((e) => html`<tr><td class="muted mono">${fmtTime(e.timestamp)}</td><td>${e.host}</td><td>${e.action} <span class="muted">${e.outcome}</span></td><td>${e.user}</td><td class="mono">${e.src_ip}</td><td class="mono" style="max-width:520px">${e.message.slice(0, 240)}</td></tr>`)}
        </tbody></table></div></div>`);
    $("#ev-form").onsubmit = (e) => { e.preventDefault(); const p = {}; new FormData(e.target).forEach((v, k) => { if (v) p[k] = v; }); pages.siem(p); };
    bindRowLinks();
  },

  async firewalls() {
    const fws = await api("/api/v1/firewalls");
    render(html`<div class="page-head"><div><h1>Firewalls</h1><div class="muted">Import pfSense / OPNsense <code>config.xml</code> or a UniFi export, or connect to the device API to sync automatically.</div></div></div>
      <div class="grid two">
        <div class="card"><h2>Devices</h2>${fws.length ? html`<table>${fws.map((f) => html`<tr class="click" data-asset="fw:${f.id}"><td><b>${f.name}</b><div class="muted">${f.vendor} · ${f.summary.rules} rules · ${f.summary.port_forwards} port forwards</div><div class="muted">${f.summary.networks.join(" · ")}</div></td><td class="muted">${fmtTime(f.fetched_at)}</td><td>${f.connection && f.connection.url ? html`<button class="secondary" data-sync="${f.id}">Sync</button>` : ""}</td></tr>`)}</table>` : html`<div class="empty">No firewalls yet.</div>`}</div>
        <div class="card"><h2>Import a config</h2>
          <div class="row" style="margin-bottom:8px"><input id="fw-id" placeholder="device id, e.g. edge-fw" style="flex:1"><input id="fw-file" type="file" accept=".xml,.json"></div>
          <button id="fw-import">Import & analyze</button>
          <h3>Or connect to the API</h3>
          <p class="muted">Credentials stay in environment variables on the server. Reference them by name.</p>
          <div class="row" style="margin-bottom:8px"><input id="fwc-id" placeholder="id"><input id="fwc-name" placeholder="name"><select id="fwc-vendor"><option value="unifi">UniFi</option><option value="pfsense_api">pfSense (REST API)</option><option value="opnsense_api">OPNsense</option></select></div>
          <div class="row" style="margin-bottom:8px"><input id="fwc-url" placeholder="https://192.168.1.1" style="flex:1"><input id="fwc-env" placeholder="API key env var, e.g. UNIFI_API_KEY"></div>
          <button id="fwc-add" class="secondary">Add device</button>
        </div>
      </div>`);
    $("#fw-import").onclick = async () => {
      const id = $("#fw-id").value.trim(), f = $("#fw-file").files[0];
      if (!id || !f) return toast("Pick an id and a file");
      try { const r = await api(`/api/v1/firewalls/${encodeURIComponent(id)}/import`, { method: "POST", body: await f.text(), headers: { "Content-Type": "text/plain" } }); toast(`Imported: ${r.new} new findings`); pages.firewalls(); }
      catch (e) { toast(e.message); }
    };
    $("#fwc-add").onclick = async () => {
      const vendor = $("#fwc-vendor").value; const conn = { url: $("#fwc-url").value.trim() };
      conn[vendor === "opnsense_api" ? "key_env" : "api_key_env"] = $("#fwc-env").value.trim();
      try { await api("/api/v1/firewalls", { method: "POST", body: { id: $("#fwc-id").value.trim(), name: $("#fwc-name").value.trim(), vendor, connection: conn } }); toast("Added. Click Sync to fetch."); pages.firewalls(); }
      catch (e) { toast(e.message); }
    };
    document.querySelectorAll("[data-sync]").forEach((b) => (b.onclick = async (ev) => {
      ev.stopPropagation(); b.disabled = true;
      try { const r = await api(`/api/v1/firewalls/${encodeURIComponent(b.dataset.sync)}/sync`, { method: "POST" }); toast(`Synced: ${r.new} new, ${r.resolved} resolved`); pages.firewalls(); }
      catch (e) { toast(e.message); b.disabled = false; }
    }));
    bindRowLinks();
  },

  async external() {
    const [t, jobs, fs] = await Promise.all([api("/api/v1/external/targets"), api("/api/v1/external/jobs"), api("/api/v1/findings?category=external")]);
    render(html`<div class="page-head"><div><h1>External view</h1><div class="muted">Probes run outside your network (a cheap VPS is perfect) and scan only the public assets listed here.</div></div></div>
      <div class="grid two">
        <div class="card"><h2>Scope</h2>
          <table>${t.targets.map((x) => html`<tr><td class="mono">${x.value}</td><td>${x.kind}</td><td class="muted">${x.note}</td><td><button class="secondary" data-del="${x.id}">Remove</button></td></tr>`)}</table>
          ${t.suggested.length ? html`<p class="muted">Suggested from firewall WAN addresses: ${t.suggested.map((s) => html`<button class="secondary" data-add="${s}">+ ${s}</button> `)}</p>` : ""}
          <div class="row"><input id="ext-v" placeholder="203.0.113.5, 203.0.113.0/28 or vpn.example.com" style="flex:1"><button id="ext-add">Add</button></div>
          <p class="muted">Only add assets you own or are authorized to test.</p>
          <div class="row"><input id="ext-ports" placeholder="ports: top100 (default), top1000, 1-1024"><button id="ext-scan">Queue scan</button></div>
        </div>
        <div class="card"><h2>Scan jobs</h2>${jobs.length ? html`<table>${jobs.map((j) => html`<tr><td class="mono">${j.id}</td><td>${j.status}</td><td class="muted">${fmtTime(j.created_at)}</td><td class="muted">${j.claimed_by || ""}</td></tr>`)}</table>` : html`<div class="empty">No scans yet. Enroll a probe on the Agents page, then queue a scan.</div>`}</div>
      </div>
      <div class="card" style="margin-top:16px"><h2>What the internet sees</h2>${fs.length ? html`<table>${fs.map((f) => html`<tr class="click" data-finding="${f.key}"><td>${sev(f.severity)}</td><td>${f.title}</td><td>${(f.tags || []).map((x) => html`<span class="pill">${x}</span>`)}</td></tr>`)}</table>` : html`<div class="empty">No external findings.</div>`}</div>`);
    const add = async (v) => { try { await api("/api/v1/external/targets", { method: "POST", body: { value: v } }); pages.external(); } catch (e) { toast(e.message); } };
    $("#ext-add").onclick = () => add($("#ext-v").value.trim());
    document.querySelectorAll("[data-add]").forEach((b) => (b.onclick = () => add(b.dataset.add)));
    document.querySelectorAll("[data-del]").forEach((b) => (b.onclick = async () => { await api(`/api/v1/external/targets/${b.dataset.del}`, { method: "DELETE" }); pages.external(); }));
    $("#ext-scan").onclick = async () => { try { const r = await api("/api/v1/external/jobs", { method: "POST", body: { ports: $("#ext-ports").value.trim() || null } }); toast(`Queued ${r.job_id}`); pages.external(); } catch (e) { toast(e.message); } };
    bindRowLinks();
  },

  async agents() {
    const [agents, tasks] = await Promise.all([api("/api/v1/agents"), api("/api/v1/tasks")]);
    render(html`<div class="page-head"><div><h1>Agents & probes</h1></div></div>
      <div class="grid two">
        <div class="card"><h2>Enroll</h2>
          <div class="row"><select id="tok-kind"><option value="host">Host agent (inside the network)</option><option value="probe">External probe (outside, internet only)</option></select><button id="tok-go">Create enrollment token</button></div>
          <div id="tok-out"></div>
        </div>
        <div class="card"><h2>Tasks</h2>${tasks.length ? html`<table>${tasks.map((t) => html`<tr><td class="mono">${t.id}</td><td>${t.action} ${t.dry_run ? html`<span class="pill">dry run</span>` : ""}<div class="muted mono">${JSON.stringify(t.params)}</div></td><td>${t.status}</td><td>${t.status === "pending" ? html`<button data-approve="${t.id}">Approve</button> <button class="secondary" data-reject="${t.id}">Reject</button>` : t.result && t.result.output ? html`<details><summary>output</summary><pre>${t.result.output.slice(-4000)}</pre></details>` : ""}</td></tr>`)}</table>` : html`<div class="empty">No tasks.</div>`}</div>
      </div>
      <div class="card" style="margin-top:16px"><h2>Enrolled</h2><table><thead><tr><th>Name</th><th>Kind</th><th>Version</th><th>Asset</th><th>Last seen</th><th></th></tr></thead>
        ${agents.map((a) => html`<tr><td>${a.name}<div class="muted mono">${a.id}</div></td><td>${a.kind}</td><td>${a.version}</td><td class="mono">${a.asset_id || ""}</td><td class="muted">${fmtTime(a.last_seen)}</td><td>${a.revoked ? "revoked" : html`<button class="secondary" data-revoke="${a.id}">Revoke</button>`}</td></tr>`)}</table></div>`);
    $("#tok-go").onclick = async () => {
      const r = await api("/api/v1/tokens", { method: "POST", body: { kind: $("#tok-kind").value } });
      $("#tok-out").innerHTML = String(html`<p class="muted">Single-use, expires in ${r.expires_in_hours}h. Run on the ${r.kind === "probe" ? "external host" : "machine to protect"}:</p><pre>${r.command}</pre><p class="muted">Server signing key (pinned by the agent): <code>${r.server_public_key}</code></p>`);
    };
    document.querySelectorAll("[data-approve]").forEach((b) => (b.onclick = async () => { try { await api(`/api/v1/tasks/${b.dataset.approve}/approve`, { method: "POST" }); toast("Approved and signed"); pages.agents(); } catch (e) { toast(e.message); } }));
    document.querySelectorAll("[data-reject]").forEach((b) => (b.onclick = async () => { await api(`/api/v1/tasks/${b.dataset.reject}/reject`, { method: "POST" }); pages.agents(); }));
    document.querySelectorAll("[data-revoke]").forEach((b) => (b.onclick = async () => { if (confirm("Revoke this agent? It will no longer be able to report.")) { await api(`/api/v1/agents/${b.dataset.revoke}/revoke`, { method: "POST" }); pages.agents(); } }));
  },

  async analyst() {
    let providers = [];
    try { providers = (await api("/api/v1/ai/providers")).providers; } catch (e) { /* AI extra not installed */ }
    const history = pages.analyst.history || (pages.analyst.history = []);
    render(html`<div class="page-head"><div><h1>AI analyst</h1><div class="muted">Asks questions over your SAMS data with read-only tools. Cloud providers get identifiers pseudonymized unless you allow otherwise.</div></div>
        <div class="row"><select id="ai-provider">${providers.map((p) => html`<option value="${p.name}">${p.name} · ${p.model} (${p.locality})</option>`)}</select></div></div>
      ${providers.length ? "" : html`<div class="empty">No AI provider configured. Add one under <code>ai.providers</code> in sams.yaml. See docs/AI.md (Anthropic, OpenAI, Ollama, any OpenAI-compatible endpoint).</div>`}
      <div class="chat" id="chat">${history.map((m) => html`<div class="msg ${m.role}">${m.content}${m.tools ? html`<div class="tools">tools: ${m.tools.join(", ")}</div>` : ""}</div>`)}</div>
      <form id="ai-form" class="row" style="margin-top:16px"><input id="ai-q" style="flex:1" placeholder="e.g. What is the fastest way an attacker reaches our database, and what should I fix first?" ${providers.length ? "" : raw("disabled")}><button ${providers.length ? "" : raw("disabled")}>Ask</button></form>
      <div class="row" style="margin-top:8px">${["Give me an executive summary of our security posture", "If the web server is compromised, what is at risk?", "Triage the most recent alert"].map((s) => html`<button class="secondary" data-suggest="${s}">${s}</button>`)}</div>`);
    const ask = async (q) => {
      history.push({ role: "user", content: q }); pages.analyst();
      try {
        const r = await api("/api/v1/ai/ask", { method: "POST", body: { question: q, provider: $("#ai-provider") && $("#ai-provider").value, history: history.slice(0, -1).map(({ role, content }) => ({ role, content })) } });
        history.push({ role: "assistant", content: r.text, tools: (r.tool_calls || []).map((t) => t.name) });
      } catch (e) { history.push({ role: "assistant", content: `Error: ${e.message}` }); }
      pages.analyst();
    };
    $("#ai-form").onsubmit = (e) => { e.preventDefault(); const q = $("#ai-q").value.trim(); if (q) ask(q); };
    document.querySelectorAll("[data-suggest]").forEach((b) => (b.onclick = () => ask(b.dataset.suggest)));
  },
};

// ------------------------------------------------------------------ shared views
function pathCard(p, i) {
  return html`<div class="card" style="margin-bottom:12px"><div class="row" style="justify-content:space-between"><h2 style="margin:0">#${i + 1} → ${p.target_label}</h2><span class="row"><span class="pill">criticality ${p.target_criticality}</span><span class="mono">${pct(p.likelihood)} likely</span></span></div>
    <div class="path" style="margin-top:12px">${p.nodes.map((n, j) => html`<div class="step"><div class="dot"></div><div><div class="node">${n.label}</div>${p.edges[j] ? html`<div class="edge"><b>${p.edges[j].technique}</b> · ${p.edges[j].description} <span class="mono">(${pct(p.edges[j].likelihood)})</span></div>` : ""}</div></div>`)}</div>
    ${graphSvg(p.nodes, p.edges)}</div>`;
}

function blastRadiusView(br) {
  const s = br.summary;
  return html`<div class="grid kpis">
      <div class="card kpi"><div class="label">Other hosts reached</div><div class="value">${s.hosts}</div></div>
      <div class="card kpi"><div class="label">…as root</div><div class="value">${s.hosts_root}</div></div>
      <div class="card kpi"><div class="label">Datastores</div><div class="value">${s.datastores}</div></div>
      <div class="card kpi"><div class="label">Credentials</div><div class="value">${s.credentials}</div></div>
      <div class="card kpi"><div class="label">Cloud access</div><div class="value">${s.cloud}</div></div></div>
    <div class="grid two">
      <div class="card"><h2>If ${br.start_label} is compromised…</h2>${br.reachable.length ? html`<table>${br.reachable.filter((r) => r.kind !== "netpos").slice(0, 40).map((r) => html`<tr><td class="mono">${pct(r.likelihood)}</td><td>${r.label}<div class="muted">${r.kind} · ${r.hops} steps · ${r.path.map((e) => e.technique).join(" → ")}</div></td><td>${r.criticality >= 4 ? html`<span class="sev critical">crown jewel</span>` : ""}</td></tr>`)}</table>` : html`<div class="empty">Nothing else reachable. Good containment.</div>`}</div>
      <div class="card"><h2>Contain it</h2><p class="muted">Fixes that cut off the most of this blast radius:</p>${br.containment.length ? html`<ol>${br.containment.map((c) => html`<li style="margin-bottom:6px">${c.title}</li>`)}</ol>` : html`<div class="empty">No containment actions needed.</div>`}</div>
    </div>`;
}

function graphSvg(nodes, edges) {
  const W = Math.max(640, nodes.length * 170), H = 120, gap = W / nodes.length;
  const color = { internet: "#d7263d", foothold: "#6b4dff", data: "#e0a100", cred: "#2e86ab", cloud: "#1b9e5a", ext: "#8a94a6", netpos: "#8a94a6" };
  const pos = nodes.map((n, i) => [gap * i + gap / 2, 50]);
  return html`<svg class="graph" viewBox="0 0 ${W} ${H}" role="img" aria-label="attack path diagram" style="margin-top:12px">
    <defs><marker id="arr" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="currentColor"/></marker></defs>
    ${edges.map((e, i) => html`<line class="edge-line" x1="${pos[i][0] + 16}" y1="50" x2="${pos[i + 1][0] - 18}" y2="50" stroke-width="${1 + 3 * e.likelihood}" marker-end="url(#arr)"/><text x="${(pos[i][0] + pos[i + 1][0]) / 2}" y="40" text-anchor="middle">${e.technique}</text>`)}
    ${nodes.map((n, i) => html`<circle cx="${pos[i][0]}" cy="50" r="14" fill="${color[n.kind] || "#888"}"/><text x="${pos[i][0]}" y="84" text-anchor="middle">${n.label.length > 26 ? n.label.slice(0, 25) + "…" : n.label}</text>`)}
  </svg>`;
}

async function showAsset(id) {
  const a = await api(`/api/v1/assets/${encodeURIComponent(id)}`);
  const inv = a.inventory;
  const d = drawer(html`<h1>${a.name}</h1><div class="muted mono">${a.id} · ${a.kind}</div>
    <div class="row" style="margin:12px 0"><label>Criticality</label><select id="crit">${[1, 2, 3, 4, 5].map((c) => html`<option value="${c}" ${a.criticality === c ? raw("selected") : ""}>${c}${c >= 4 ? " (crown jewel)" : ""}</option>`)}</select>
      ${a.kind === "host" ? html`<button class="secondary" id="br-btn">Blast radius</button><button class="secondary" id="scan-btn">Rescan vulnerabilities</button>` : ""}</div>
    ${inv ? html`<h3>System</h3><p>${inv.host.os.pretty || inv.host.os.name} · kernel ${inv.host.kernel} · ${inv.ips.join(", ")}<br><span class="muted">${inv.packages} packages · ${inv.users} users · admins: ${inv.admins.join(", ") || "–"} · collected ${fmtTime(inv.collected_at)}</span></p>
      <h3>Network listeners</h3><table>${inv.listeners.map((l) => html`<tr><td class="mono">${l.proto}/${l.port}</td><td>${l.process}</td><td class="muted">${l.user}</td><td class="muted mono">${l.address}</td></tr>`)}</table>
      ${inv.credentials.length ? html`<h3>Credentials found on disk</h3><table>${inv.credentials.map((c) => html`<tr><td>${c.kind}</td><td>${c.owner}</td><td class="mono">${c.path}</td><td>${c.encrypted === false ? html`<span class="sev high">unencrypted</span>` : ""}</td></tr>`)}</table>` : ""}` : ""}
    <div id="br-out"></div>
    <h3>Findings (${a.findings.length})</h3>${a.findings.map((f) => html`<div class="click" data-finding="${f.key}" style="padding:6px 0;border-bottom:1px solid var(--border);cursor:pointer">${sev(f.severity)} ${f.title}</div>`)}`);
  $("#crit", d).onchange = async (e) => { await api(`/api/v1/assets/${encodeURIComponent(id)}`, { method: "PATCH", body: { criticality: +e.target.value } }); toast("Criticality updated"); };
  if ($("#br-btn", d)) $("#br-btn", d).onclick = async () => { $("#br-out", d).innerHTML = String(blastRadiusView(await api(`/api/v1/graph/blast-radius/${encodeURIComponent(id)}`))); };
  if ($("#scan-btn", d)) $("#scan-btn", d).onclick = async () => { await api(`/api/v1/assets/${encodeURIComponent(id)}/scan`, { method: "POST" }); toast("Vulnerability scan queued"); };
  bindRowLinks(d);
}

async function showFinding(key) {
  const f = await api(`/api/v1/findings/${encodeURIComponent(key)}`);
  const r = f.remediation;
  const vulns = (f.evidence && f.evidence.vulns) || [];
  const d = drawer(html`${sev(f.severity)} <span class="pill">${f.category}</span><h1 style="margin-top:8px">${f.title}</h1>
    <p>${f.description}</p>
    ${r ? html`<div class="card"><h2>Remediation</h2><p><b>${r.summary}</b></p>${r.details ? html`<p>${r.details}</p>` : ""}${r.commands && r.commands.length ? html`<pre>${r.commands.join("\n")}</pre>` : ""}
      ${r.automatable ? html`<button id="mk-task">Create patch task (dry run)</button>` : ""}</div>` : ""}
    ${vulns.length ? html`<h3>Vulnerabilities</h3><table>${vulns.slice(0, 60).map((v) => html`<tr><td class="mono"><a href="https://osv.dev/vulnerability/${encodeURIComponent(v.id)}" target="_blank" rel="noopener noreferrer">${v.id}</a></td><td>${v.cvss_score ?? ""}</td><td>${v.kev ? html`<span class="sev critical">KEV</span>` : ""} ${v.attack_vector || ""}</td><td class="muted">${(v.summary || "").slice(0, 140)}</td></tr>`)}</table>` : ""}
    <h3>Status</h3><div class="row">${["open", "accepted", "false_positive", "fixed"].map((s) => html`<button class="${f.status === s ? "" : "secondary"}" data-status="${s}">${s}</button>`)}</div>
    <h3>Evidence</h3><pre>${JSON.stringify(f.evidence, null, 2).slice(0, 20000)}</pre>`);
  d.querySelectorAll("[data-status]").forEach((b) => (b.onclick = async () => { await api(`/api/v1/findings/${encodeURIComponent(key)}/status`, { method: "POST", body: { status: b.dataset.status } }); toast(`Marked ${b.dataset.status}`); closeDrawer(); route(); }));
  if ($("#mk-task", d)) $("#mk-task", d).onclick = async () => { try { const t = await api(`/api/v1/findings/${encodeURIComponent(key)}/task?dry_run=true`, { method: "POST" }); toast(`Task ${t.id} created. Approve it on the Agents page.`); } catch (e) { toast(e.message); } };
}

async function showAlert(id) {
  const a = await api(`/api/v1/alerts/${id}`);
  const br = a.context && a.context.blast_radius;
  const d = drawer(html`${sev(a.severity)} ${(a.mitre || []).map((m) => html`<a class="pill" href="https://attack.mitre.org/techniques/${m.replace(".", "/")}/" target="_blank" rel="noopener noreferrer">${m}</a>`)}
    <h1 style="margin-top:8px">${a.title}</h1><p>${a.description}</p><p class="muted">${a.host} · ${fmtTime(a.created_at)} · rule ${a.rule_id}</p>
    ${br ? html`<div class="card"><h2>If this host is compromised</h2><p>${br.hosts} other hosts (${br.hosts_root} as root), ${br.datastores} datastores, ${br.credentials} credentials, ${br.cloud} cloud identities are reachable.</p>
      ${(a.context.containment || []).length ? html`<p><b>Containment:</b></p><ol>${a.context.containment.map((c) => html`<li>${c.title}</li>`)}</ol>` : ""}</div>` : ""}
    <div class="row" style="margin:12px 0">${["acknowledged", "closed", "open"].map((s) => html`<button class="secondary" data-st="${s}">${s}</button>`)}</div>
    <h3>Events</h3><pre>${a.events.map((e) => e.raw || e.message).join("\n")}</pre>`);
  d.querySelectorAll("[data-st]").forEach((b) => (b.onclick = async () => { await api(`/api/v1/alerts/${id}/status`, { method: "POST", body: { status: b.dataset.st } }); closeDrawer(); route(); }));
}

function bindRowLinks(root = document) {
  root.querySelectorAll("[data-asset]").forEach((el) => (el.onclick = () => showAsset(el.dataset.asset)));
  root.querySelectorAll("[data-finding]").forEach((el) => (el.onclick = () => showFinding(el.dataset.finding)));
  root.querySelectorAll("[data-alert]").forEach((el) => (el.onclick = () => showAlert(el.dataset.alert)));
}

// ------------------------------------------------------------------ router
async function route() {
  const page = (location.hash.replace(/^#\//, "") || "overview").split("?")[0];
  document.querySelectorAll(".sidebar a").forEach((a) => a.classList.toggle("active", a.dataset.page === page));
  closeDrawer();
  render(html`<div class="loading">Loading…</div>`);
  try { await (pages[page] || pages.overview)(); }
  catch (e) { if (e.message !== "unauthorized") render(html`<div class="empty error">Error: ${e.message}</div>`); }
}
window.addEventListener("hashchange", route);

async function start() {
  $("#login").classList.add("hidden"); $("#app").classList.remove("hidden"); route();
}
(async () => {
  if (!token) return showLogin();
  try { await api("/api/v1/status"); start(); } catch { showLogin(); }
})();
