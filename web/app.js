/* CSPM product web app — dependency-free SPA. */
"use strict";

const API = "/api/v1/cspm";
const SEVS = ["critical", "high", "medium", "low", "info"];
const SEV_COLORS = {
  critical: "#b14bff", high: "#ff5d5d", medium: "#ffb020", low: "#4f8cff", info: "#8a97b1",
};
const FRAMEWORKS = ["cis_aws_v2", "soc2", "iso27001", "pci_dss_v4"];
const FRAMEWORK_LABELS = {
  cis_aws_v2: "CIS AWS v2", soc2: "SOC 2", iso27001: "ISO 27001", pci_dss_v4: "PCI DSS v4",
};

/* ---------- state / auth ---------- */
const store = {
  get session() { try { return JSON.parse(localStorage.getItem("cspm_session")); } catch { return null; } },
  set session(v) { v ? localStorage.setItem("cspm_session", JSON.stringify(v)) : localStorage.removeItem("cspm_session"); },
};

function authHeaders() {
  const s = store.session || {};
  if (s.mode === "token") return { Authorization: `Bearer ${s.token}` };
  if (s.mode === "apikey") return { Authorization: `Bearer ${s.apikey}` };
  return { "X-Org-Id": s.org, "X-Role": s.role || "admin", "X-User-Id": "web-ui" };
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    ...opts,
    headers: { "Content-Type": "application/json", ...authHeaders(), ...(opts.headers || {}) },
  });
  if (res.status === 401) { logout(); throw new Error("Session expired — please sign in."); }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try { detail = (await res.json()).detail || detail; } catch {}
    throw new Error(detail);
  }
  if (res.status === 204) return null;
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

/* ---------- tiny DOM helpers ---------- */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
function el(html) { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstElementChild; }
function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }

function toast(msg, kind = "") {
  const t = el(`<div class="toast ${kind}">${esc(msg)}</div>`);
  $("#toasts").appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; setTimeout(() => t.remove(), 300); }, 3200);
}

function modal(title, bodyHtml, onMount) {
  const root = $("#modal-root");
  const back = el(`<div class="modal-backdrop"><div class="modal"><h2>${esc(title)}</h2><div class="mbody">${bodyHtml}</div></div></div>`);
  back.addEventListener("click", (e) => { if (e.target === back) back.remove(); });
  root.appendChild(back);
  const close = () => back.remove();
  if (onMount) onMount($(".mbody", back), close);
  return close;
}

/* ---------- canvas charts ---------- */
function donut(canvas, segments, centerText) {
  const dpr = window.devicePixelRatio || 1;
  const size = 160; canvas.width = size * dpr; canvas.height = size * dpr;
  canvas.style.width = size + "px"; canvas.style.height = size + "px";
  const ctx = canvas.getContext("2d"); ctx.scale(dpr, dpr);
  const cx = size / 2, cy = size / 2, r = 62, lw = 20;
  const total = segments.reduce((a, s) => a + s.value, 0) || 1;
  let start = -Math.PI / 2;
  ctx.lineWidth = lw;
  segments.forEach((s) => {
    const ang = (s.value / total) * Math.PI * 2;
    ctx.beginPath(); ctx.strokeStyle = s.color;
    ctx.arc(cx, cy, r, start, start + ang); ctx.stroke(); start += ang;
  });
  if (total === 1 && segments.every((s) => !s.value)) {
    ctx.beginPath(); ctx.strokeStyle = getVar("--pass"); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.stroke();
  }
  ctx.fillStyle = getVar("--text"); ctx.textAlign = "center"; ctx.textBaseline = "middle";
  ctx.font = "700 26px sans-serif"; ctx.fillText(centerText.main, cx, cy - 6);
  ctx.fillStyle = getVar("--muted"); ctx.font = "600 11px sans-serif";
  ctx.fillText(centerText.sub, cx, cy + 16);
}

function lineChart(canvas, points, opts = {}) {
  const dpr = window.devicePixelRatio || 1;
  const w = opts.w || 520, h = opts.h || 180, pad = 28;
  canvas.width = w * dpr; canvas.height = h * dpr; canvas.style.width = "100%"; canvas.style.height = h + "px";
  const ctx = canvas.getContext("2d"); ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  const xs = points.map((_, i) => i), ys = points.map((p) => p.y);
  const maxY = 100, minY = 0;
  const X = (i) => pad + (i / Math.max(1, xs.length - 1)) * (w - pad * 2);
  const Y = (v) => h - pad - ((v - minY) / (maxY - minY)) * (h - pad * 2);
  // gridlines
  ctx.strokeStyle = getVar("--border"); ctx.lineWidth = 1; ctx.fillStyle = getVar("--muted"); ctx.font = "10px sans-serif";
  [0, 25, 50, 75, 100].forEach((g) => { const y = Y(g); ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w - pad, y); ctx.stroke(); ctx.fillText(g + "%", 4, y + 3); });
  if (points.length < 2) { ctx.fillStyle = getVar("--muted"); ctx.textAlign = "center"; ctx.fillText("Not enough data yet — run more scans", w / 2, h / 2); return; }
  // area + line
  ctx.beginPath(); ctx.moveTo(X(0), Y(ys[0]));
  ys.forEach((v, i) => ctx.lineTo(X(i), Y(v)));
  ctx.strokeStyle = getVar("--accent"); ctx.lineWidth = 2.5; ctx.stroke();
  ctx.lineTo(X(xs.length - 1), h - pad); ctx.lineTo(X(0), h - pad); ctx.closePath();
  ctx.fillStyle = "rgba(79,140,255,.12)"; ctx.fill();
  ys.forEach((v, i) => { ctx.beginPath(); ctx.fillStyle = getVar("--accent"); ctx.arc(X(i), Y(v), 3, 0, Math.PI * 2); ctx.fill(); });
}

function bars(container, data) {
  const max = Math.max(1, ...data.map((d) => d.value));
  container.innerHTML = data.map((d) => `
    <div style="display:flex;align-items:center;gap:.6rem;margin:.35rem 0">
      <span style="width:70px;font-size:.75rem;color:var(--muted);text-transform:uppercase">${d.label}</span>
      <div style="flex:1;background:var(--bg-2);border-radius:6px;height:16px;overflow:hidden">
        <div style="width:${(d.value / max) * 100}%;height:100%;background:${d.color}"></div>
      </div>
      <span style="width:28px;text-align:right;font-weight:700">${d.value}</span>
    </div>`).join("");
}

function getVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

/* ---------- data helpers ---------- */
async function loadAll() {
  const [accounts, findings, drift] = await Promise.all([
    api("/accounts"), api("/findings?limit=200"), api("/drift?limit=200"),
  ]);
  const compliance = {};
  await Promise.all(FRAMEWORKS.map(async (f) => {
    try { compliance[f] = await api(`/compliance/${f}`); } catch { compliance[f] = null; }
  }));
  return { accounts, findings, drift, compliance };
}

function scoreClass(v) { return v >= 80 ? "good" : v >= 50 ? "warn" : "bad"; }

/* ---------- views ---------- */
const views = {};

views.overview = async (mount) => {
  mount.innerHTML = skeletonGrid();
  const d = await loadAll();
  const open = d.findings.filter((f) => f.status === "open");
  const sevCounts = SEVS.map((s) => ({ label: s, value: open.filter((f) => f.severity === s).length, color: SEV_COLORS[s] }));
  const total = open.length;
  const avgScore = FRAMEWORKS.reduce((a, f) => a + (d.compliance[f]?.score ?? 100), 0) / FRAMEWORKS.length;

  mount.innerHTML = `
    <div class="grid cols-4">
      ${kpi(avgScore.toFixed(0) + "%", "Avg compliance", scoreClass(avgScore))}
      ${kpi(total, "Open findings", total ? "bad" : "good")}
      ${kpi(d.accounts.length, "Cloud accounts")}
      ${kpi(d.drift.filter((x) => x.status === "pending_review").length, "Pending drift")}
    </div>
    <div class="grid cols-2" style="margin-top:1rem">
      <div class="card"><h3>Findings by severity</h3>
        <div class="donut-wrap">
          <canvas id="c-donut"></canvas>
          <div class="legend" id="donut-legend"></div>
        </div>
      </div>
      <div class="card"><h3>Severity breakdown</h3><div id="c-bars"></div></div>
    </div>
    <div class="grid cols-4" style="margin-top:1rem">
      ${FRAMEWORKS.map((f) => complianceMini(f, d.compliance[f])).join("")}
    </div>
    <div class="section-title"><h2>Top open findings</h2><a class="btn ghost sm" href="#/findings">View all →</a></div>
    <div class="card">${findingsTable(open.slice(0, 8))}</div>`;

  donut($("#c-donut"), sevCounts, { main: String(total), sub: "open" });
  $("#donut-legend").innerHTML = sevCounts.map((s) =>
    `<div><span class="dot" style="background:${s.color}"></span>${s.label} <b>${s.value}</b></div>`).join("");
  bars($("#c-bars"), sevCounts);
  wireFindingRows(mount, () => views.overview(mount));
};

views.accounts = async (mount) => {
  mount.innerHTML = skeletonGrid();
  const accounts = await api("/accounts");
  mount.innerHTML = `
    <div class="section-title"><h2>Cloud Accounts</h2>
      <div class="row">
        <button class="btn ghost" id="seed">✨ Load demo data</button>
        <button class="btn" data-connect="aws">+ AWS</button>
        <button class="btn" data-connect="gcp">+ GCP</button>
        <button class="btn" data-connect="azure">+ Azure</button>
      </div>
    </div>
    <div class="card">
      ${accounts.length ? `<table><thead><tr><th>Label</th><th>Provider</th><th>Status</th><th>Last validated</th><th></th></tr></thead>
      <tbody>${accounts.map((a) => `
        <tr>
          <td><b>${esc(a.label || a.provider)}</b></td>
          <td><span class="cloud-tag">${a.provider}</span></td>
          <td><span class="pill ${a.status}">${a.status}</span></td>
          <td class="mono">${a.last_validated_at ? new Date(a.last_validated_at).toLocaleString() : "—"}</td>
          <td class="row" style="justify-content:flex-end">
            <button class="btn sm primary" data-scan="${a.id}">Scan</button>
            <button class="btn sm danger" data-del="${a.id}">Remove</button>
          </td>
        </tr>`).join("")}</tbody></table>` : `<div class="empty">No accounts connected. Add one to start scanning.</div>`}
    </div>`;

  $("#seed", mount).onclick = async (e) => {
    e.target.disabled = true; e.target.textContent = "Seeding…";
    try { const r = await api("/dev/seed", { method: "POST" }); toast(`Demo data loaded — ${r.findings} findings`, "success"); views.accounts(mount); }
    catch (err) { toast(err.message, "error"); e.target.disabled = false; e.target.textContent = "✨ Load demo data"; }
  };
  $$("[data-connect]", mount).forEach((b) => b.onclick = () => connectModal(b.dataset.connect, () => views.accounts(mount)));
  $$("[data-scan]", mount).forEach((b) => b.onclick = async () => {
    b.disabled = true; b.textContent = "Scanning…";
    try { const s = await api(`/accounts/${b.dataset.scan}/scan`, { method: "POST" });
      toast(`Scan complete — ${s.findings_count} findings`, "success"); views.accounts(mount);
    } catch (e) { toast(e.message, "error"); b.disabled = false; b.textContent = "Scan"; }
  });
  $$("[data-del]", mount).forEach((b) => b.onclick = async () => {
    if (!confirm("Disconnect this account?")) return;
    try { await api(`/accounts/${b.dataset.del}`, { method: "DELETE" }); toast("Account removed", "success"); views.accounts(mount); }
    catch (e) { toast(e.message, "error"); }
  });
};

views.findings = async (mount) => {
  mount.innerHTML = skeletonGrid();
  const findings = await api("/findings?limit=200");
  const render = (list) => { $("#f-table").innerHTML = findingsTable(list); wireFindingRows(mount, () => views.findings(mount)); };
  mount.innerHTML = `
    <div class="section-title"><h2>Findings</h2>
      <div class="row">
        <select id="f-sev" style="width:auto;margin:0"><option value="">All severities</option>${SEVS.map((s) => `<option>${s}</option>`).join("")}</select>
        <select id="f-status" style="width:auto;margin:0"><option value="">All statuses</option><option>open</option><option>accepted_risk</option><option>resolved</option></select>
        <a class="btn ghost sm" href="${API}/reports/findings.csv" id="csv">⬇ CSV</a>
      </div>
    </div>
    <div class="card" id="f-table">${findingsTable(findings)}</div>`;
  const apply = () => {
    const sev = $("#f-sev").value, st = $("#f-status").value;
    render(findings.filter((f) => (!sev || f.severity === sev) && (!st || f.status === st)));
  };
  $("#f-sev").onchange = apply; $("#f-status").onchange = apply;
  // CSV needs auth headers → fetch as blob
  $("#csv").onclick = async (e) => { e.preventDefault(); try {
    const txt = await api("/reports/findings.csv");
    const url = URL.createObjectURL(new Blob([txt], { type: "text/csv" }));
    const a = document.createElement("a"); a.href = url; a.download = "cspm-findings.csv"; a.click();
  } catch (err) { toast(err.message, "error"); } };
  wireFindingRows(mount, () => views.findings(mount));
};

views.compliance = async (mount) => {
  mount.innerHTML = skeletonGrid();
  const compliance = {}, trends = {};
  await Promise.all(FRAMEWORKS.map(async (f) => {
    try { compliance[f] = await api(`/compliance/${f}`); } catch { compliance[f] = null; }
    try { trends[f] = (await api(`/compliance/${f}/trend`)).series; } catch { trends[f] = []; }
  }));
  mount.innerHTML = `
    <div class="grid cols-4">${FRAMEWORKS.map((f) => complianceMini(f, compliance[f])).join("")}</div>
    <div class="grid cols-2" style="margin-top:1rem">
      ${FRAMEWORKS.map((f) => `<div class="card"><h3>${FRAMEWORK_LABELS[f]} — trend</h3><canvas class="trend" data-f="${f}"></canvas></div>`).join("")}
    </div>`;
  $$(".trend", mount).forEach((c) => {
    const series = (trends[c.dataset.f] || []).map((p) => ({ y: p.score }));
    lineChart(c, series);
  });
};

views.drift = async (mount) => {
  mount.innerHTML = skeletonGrid();
  const drift = await api("/drift?limit=200");
  mount.innerHTML = `
    <div class="section-title"><h2>Configuration Drift</h2></div>
    <div class="card">${drift.length ? `<table>
      <thead><tr><th>Resource</th><th>Type</th><th>Change</th><th>Status</th><th></th></tr></thead>
      <tbody>${drift.map((e) => `<tr>
        <td class="mono">${esc(e.resource_id)}</td>
        <td>${esc(e.resource_type)}</td>
        <td><span class="pill">${esc(e.drift_type)}</span></td>
        <td><span class="pill ${e.status}">${esc(e.status)}</span></td>
        <td class="row" style="justify-content:flex-end">${e.status === "pending_review" ? `
          <button class="btn sm" data-approve="${e.id}">Approve</button>
          <button class="btn sm danger" data-reject="${e.id}">Violation</button>` : ""}</td>
      </tr>`).join("")}</tbody></table>` : `<div class="empty">No drift detected. Baselines are clean. 🎉</div>`}</div>`;
  $$("[data-approve]", mount).forEach((b) => b.onclick = async () => {
    try { await api(`/drift/${b.dataset.approve}/approve`, { method: "POST" }); toast("Drift approved — baseline updated", "success"); views.drift(mount); }
    catch (e) { toast(e.message, "error"); } });
  $$("[data-reject]", mount).forEach((b) => b.onclick = async () => {
    try { await api(`/drift/${b.dataset.reject}/reject`, { method: "POST" }); toast("Marked as violation — finding created", "success"); views.drift(mount); }
    catch (e) { toast(e.message, "error"); } });
};

views.apikeys = async (mount) => {
  mount.innerHTML = skeletonGrid();
  let keys = [];
  try { keys = await api("/apikeys"); } catch (e) { mount.innerHTML = `<div class="card empty">${esc(e.message)} (admin only)</div>`; return; }
  mount.innerHTML = `
    <div class="section-title"><h2>API Keys</h2><button class="btn primary" id="new-key">+ New key</button></div>
    <div class="card">${keys.length ? `<table><thead><tr><th>Name</th><th>Prefix</th><th>Role</th><th></th></tr></thead>
      <tbody>${keys.map((k) => `<tr><td>${esc(k.name)}</td><td class="mono">${esc(k.prefix)}…</td><td><span class="pill">${k.role}</span></td>
      <td style="text-align:right"><button class="btn sm danger" data-revoke="${k.id}">Revoke</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="empty">No API keys yet.</div>`}</div>`;
  $("#new-key").onclick = () => modal("Create API key", `
    <label>Name</label><input id="k-name" placeholder="ci-pipeline" />
    <label>Role</label><select id="k-role"><option>analyst</option><option>viewer</option><option>admin</option></select>
    <div class="actions"><button class="btn" data-x>Cancel</button><button class="btn primary" id="k-create">Create</button></div>`,
    (body, close) => {
      $("[data-x]", body).onclick = close;
      $("#k-create", body).onclick = async () => {
        try { const r = await api("/apikeys", { method: "POST", body: JSON.stringify({ name: $("#k-name", body).value || "key", role: $("#k-role", body).value }) });
          close(); modal("API key created", `<p>Copy this now — it won't be shown again:</p><pre class="snippet">${esc(r.key)}</pre>
            <div class="actions"><button class="btn primary" data-x>Done</button></div>`, (b2, c2) => $("[data-x]", b2).onclick = () => { c2(); views.apikeys(mount); });
        } catch (e) { toast(e.message, "error"); }
      };
    });
  $$("[data-revoke]", mount).forEach((b) => b.onclick = async () => {
    try { await api(`/apikeys/${b.dataset.revoke}`, { method: "DELETE" }); toast("Key revoked", "success"); views.apikeys(mount); }
    catch (e) { toast(e.message, "error"); } });
};

/* ---------- shared view fragments ---------- */
function kpi(value, label, cls = "") {
  return `<div class="card kpi"><div class="value ${cls}">${esc(String(value))}</div><div class="label">${esc(label)}</div></div>`;
}
function complianceMini(f, data) {
  const score = data ? data.score : null;
  const cls = score == null ? "" : scoreClass(score);
  return `<div class="card kpi"><div class="value ${cls}">${score == null ? "—" : score + "%"}</div>
    <div class="label">${FRAMEWORK_LABELS[f]}</div>
    <div style="color:var(--muted);font-size:.75rem;margin-top:.3rem">${data ? `${data.checks_passed}/${data.checks_applicable} controls` : ""}</div></div>`;
}
function findingsTable(list) {
  if (!list.length) return `<div class="empty">No findings. 🎉</div>`;
  return `<table><thead><tr><th>Severity</th><th>Finding</th><th>Resource</th><th>Status</th><th></th></tr></thead>
    <tbody>${list.map((f) => `<tr data-fid="${f.id}">
      <td><span class="sev ${f.severity}">${f.severity}</span></td>
      <td>${esc(f.description || f.check_id)}</td>
      <td class="mono">${esc(f.resource)}</td>
      <td><span class="pill ${f.status}">${f.status}</span></td>
      <td style="text-align:right"><button class="btn sm" data-fix="${f.id}">Details</button></td>
    </tr>`).join("")}</tbody></table>`;
}
function wireFindingRows(mount, refresh) {
  $$("[data-fix]", mount).forEach((b) => b.onclick = () => findingModal(b.dataset.fix, refresh));
}

async function findingModal(id, refresh) {
  let rem;
  try { rem = await api(`/findings/${id}/remediation`); } catch (e) { toast(e.message, "error"); return; }
  const snip = rem.snippets || {};
  modal("Finding details", `
    <p><b>${esc(rem.check_id)}</b></p>
    <p class="mono">${esc(rem.resource)}</p>
    <p style="color:var(--muted)">${esc(rem.guidance || "")}</p>
    ${snip.terraform ? `<label>Terraform</label><pre class="snippet">${esc(snip.terraform)}</pre>` : ""}
    ${snip.cli ? `<label>CLI</label><pre class="snippet">${esc(snip.cli)}</pre>` : ""}
    ${snip.docs ? `<p><a href="${esc(snip.docs)}" target="_blank" rel="noopener">📚 Documentation</a></p>` : ""}
    <label>Update status</label>
    <select id="fs"><option value="open">open</option><option value="accepted_risk">accepted_risk</option><option value="resolved">resolved</option></select>
    <div class="actions"><button class="btn" data-x>Close</button><button class="btn primary" id="fsave">Save</button></div>`,
    (body, close) => {
      $("[data-x]", body).onclick = close;
      $("#fsave", body).onclick = async () => {
        try { await api(`/findings/${id}`, { method: "PATCH", body: JSON.stringify({ status: $("#fs", body).value }) });
          toast("Finding updated", "success"); close(); refresh && refresh();
        } catch (e) { toast(e.message, "error"); }
      };
    });
}

function connectModal(provider, refresh) {
  const forms = {
    aws: `<label>Label</label><input id="c-label" placeholder="prod" />
          <label>Role ARN</label><input id="c-arn" placeholder="arn:aws:iam::123:role/Track2CSPMAudit" />
          <label>External ID (optional)</label><input id="c-ext" placeholder="auto-generated" />`,
    gcp: `<label>Label</label><input id="c-label" placeholder="prod-project" />
          <label>Service account JSON</label><textarea id="c-sa" rows="5" placeholder='{"type":"service_account",...}'></textarea>`,
    azure: `<label>Label</label><input id="c-label" placeholder="prod-sub" />
          <label>Tenant ID</label><input id="c-tenant" /><label>Client ID</label><input id="c-client" />
          <label>Client secret</label><input id="c-secret" type="password" /><label>Subscription ID</label><input id="c-sub" />`,
  };
  modal(`Connect ${provider.toUpperCase()} account`, forms[provider] +
    `<div class="actions"><button class="btn" data-x>Cancel</button><button class="btn primary" id="c-go">Validate & connect</button></div>`,
    (body, close) => {
      $("[data-x]", body).onclick = close;
      $("#c-go", body).onclick = async () => {
        const label = $("#c-label", body)?.value;
        let payload = { provider, label };
        if (provider === "aws") payload = { ...payload, role_arn: $("#c-arn", body).value, external_id: $("#c-ext", body).value || null };
        if (provider === "gcp") payload = { ...payload, service_account_json: $("#c-sa", body).value };
        if (provider === "azure") payload = { ...payload, tenant_id: $("#c-tenant", body).value, client_id: $("#c-client", body).value, client_secret: $("#c-secret", body).value, subscription_id: $("#c-sub", body).value };
        const btn = $("#c-go", body); btn.disabled = true; btn.textContent = "Validating…";
        try { await api("/accounts", { method: "POST", body: JSON.stringify(payload) });
          toast("Account connected", "success"); close(); refresh && refresh();
        } catch (e) { toast(e.message, "error"); btn.disabled = false; btn.textContent = "Validate & connect"; }
      };
    });
}

function skeletonGrid() {
  return `<div class="grid cols-4">${Array(4).fill('<div class="card"><div class="skeleton" style="height:40px"></div></div>').join("")}</div>`;
}

/* ---------- router ---------- */
async function route() {
  if (!store.session) return showLogin();
  const name = (location.hash.replace("#/", "") || "overview").split("?")[0];
  const view = views[name] || views.overview;
  $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === name));
  $("#crumb").textContent = { overview: "Overview", accounts: "Cloud Accounts", findings: "Findings", compliance: "Compliance", drift: "Drift", apikeys: "API Keys" }[name] || "Overview";
  const mount = $("#view");
  try { await view(mount); } catch (e) { mount.innerHTML = `<div class="card empty">${esc(e.message)}</div>`; }
}

/* ---------- auth screens ---------- */
function showLogin() {
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
}
function showApp() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  const s = store.session;
  $("#org-badge").textContent = s.mode === "headers" ? `${s.org} · ${s.role}` : s.mode;
  if (!location.hash) location.hash = "#/overview";
  route();
}
function logout() { store.session = null; showLogin(); }

/* ---------- init ---------- */
function init() {
  // theme
  const savedTheme = localStorage.getItem("cspm_theme") || "dark";
  document.documentElement.dataset.theme = savedTheme;
  $("#theme-toggle").onclick = () => {
    const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = t; localStorage.setItem("cspm_theme", t); route();
  };

  // login mode switch
  $$(".seg-btn").forEach((b) => b.onclick = () => {
    $$(".seg-btn").forEach((x) => x.classList.remove("active")); b.classList.add("active");
    $$("[data-for]").forEach((d) => d.classList.toggle("hidden", d.dataset.for !== b.dataset.mode));
  });
  $("#login-form").onsubmit = (e) => {
    e.preventDefault();
    const mode = $(".seg-btn.active").dataset.mode;
    let s = { mode };
    if (mode === "headers") { s.org = $("#in-org").value.trim(); s.role = $("#in-role").value; if (!s.org) return toast("Enter an Org ID", "error"); }
    if (mode === "token") { s.token = $("#in-token").value.trim(); if (!s.token) return toast("Enter a token", "error"); }
    if (mode === "apikey") { s.apikey = $("#in-apikey").value.trim(); if (!s.apikey) return toast("Enter an API key", "error"); }
    store.session = s; showApp();
  };

  $("#logout").onclick = logout;
  $("#refresh").onclick = route;
  window.addEventListener("hashchange", route);

  store.session ? showApp() : showLogin();
}

document.addEventListener("DOMContentLoaded", init);
