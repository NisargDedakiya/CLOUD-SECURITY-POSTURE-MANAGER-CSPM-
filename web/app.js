/* Aegis Enterprise CNAPP Web App — Modern Commercial Platform */
"use strict";

const API = "/api/v1/cspm";
const FRAMEWORKS = [
  "cis_aws_v2", "soc2", "iso27001", "pci_dss_v4", "fedramp_high", "gdpr", "ccpa", "dora", "nis2", "csa_ccm"
];
const FRAMEWORK_LABELS = {
  cis_aws_v2: "CIS AWS v2", soc2: "SOC 2 Type II", iso27001: "ISO 27001", pci_dss_v4: "PCI DSS v4",
  fedramp_high: "FedRAMP High", gdpr: "GDPR Privacy", ccpa: "CCPA Privacy", dora: "DORA Resilience",
  nis2: "NIS2 Directive", csa_ccm: "CSA CCM v4",
};

/* ---------- state / auth ---------- */
const store = {
  get session() { try { return JSON.parse(localStorage.getItem("aegis_session")); } catch { return null; } },
  set session(v) { v ? localStorage.setItem("aegis_session", JSON.stringify(v)) : localStorage.removeItem("aegis_session"); },
};

function authHeaders() {
  const s = store.session || {};
  if (s.mode === "token") return { Authorization: `Bearer ${s.token}` };
  if (s.mode === "apikey") return { Authorization: `Bearer ${s.apikey}` };
  return { "X-Org-Id": s.org || "demo-org", "X-Role": s.role || "admin", "X-User-Id": "web-ui" };
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    ...opts,
    headers: { "Content-Type": "application/json", ...authHeaders(), ...(opts.headers || {}) },
  });
  if (res.status === 401) { logout(); throw new Error("Session expired — please sign in."); }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`, body = {};
    try { body = await res.json(); detail = body.detail || detail; } catch {}
    const err = new Error(detail);
    if (res.status === 402) { err.upgrade = body.upgrade_to || "pro"; }
    throw err;
  }
  if (res.status === 204) return null;
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

/* ---------- DOM Helpers ---------- */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
function el(html) { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstElementChild; }
function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }

function toast(msg, kind = "") {
  const t = el(`<div class="toast ${kind}">${esc(msg)}</div>`);
  $("#toasts").appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; setTimeout(() => t.remove(), 350); }, 3500);
}

function modal(title, bodyHtml, onMount) {
  const root = $("#modal-root");
  const back = el(`<div class="modal-backdrop"><div class="modal card" style="width:680px; max-width:90vw;"><h2>${esc(title)}</h2><div class="mbody" style="margin-top:1rem;">${bodyHtml}</div></div></div>`);
  back.addEventListener("click", (e) => { if (e.target === back) back.remove(); });
  root.appendChild(back);
  const close = () => back.remove();
  if (onMount) onMount($(".mbody", back), close);
  return close;
}

/* ---------- App Initialization & Routing ---------- */
function init() {
  bindAuth();
  bindGlobalNav();
  bindCommandPalette();
  if (!store.session) {
    showLogin();
  } else {
    showApp();
  }
}

function showLogin() {
  $("#login").classList.remove("hidden");
  $("#app").classList.add("hidden");
}

function showApp() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#org-badge").textContent = store.session?.org || "demo-org";
  window.onhashchange = route;
  route();
}

function logout() {
  store.session = null;
  showLogin();
}

function bindAuth() {
  $("#login-form")?.addEventListener("submit", (e) => {
    e.preventDefault();
    const mode = $(".seg-btn.active")?.dataset.mode || "headers";
    store.session = {
      mode,
      org: $("#in-org").value || "demo-org",
      role: $("#in-role").value || "admin",
      token: $("#in-token").value,
      apikey: $("#in-apikey").value,
    };
    showApp();
  });

  $$(".seg-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".seg-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const mode = btn.dataset.mode;
      $$("#login-form > div").forEach((div) => div.classList.add("hidden"));
      $(`#login-form > div[data-for="${mode}"]`).classList.remove("hidden");
    });
  });

  $("#logout")?.addEventListener("click", logout);
  $("#demo-btn")?.addEventListener("click", async () => {
    try {
      await api("/onboarding/demo-workspace", { method: "POST" });
      toast("Demo workspace populated with cloud accounts & findings!", "success");
      route();
    } catch (e) { toast(e.message, "error"); }
  });
}

function bindGlobalNav() {
  $("#theme-toggle")?.addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme");
    document.documentElement.setAttribute("data-theme", cur === "light" ? "dark" : "light");
  });
}

function bindCommandPalette() {
  const trigger = $("#cmd-k-trigger");
  const backdrop = $("#cmd-palette");
  const input = $("#cmd-search-input");
  const results = $("#cmd-search-results");

  const openCmd = () => { backdrop.classList.remove("hidden"); input.focus(); };
  const closeCmd = () => backdrop.classList.add("hidden");

  trigger?.addEventListener("click", openCmd);
  window.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "k") { e.preventDefault(); openCmd(); }
    if (e.key === "Escape") closeCmd();
  });
  backdrop?.addEventListener("click", (e) => { if (e.target === backdrop) closeCmd(); });

  input?.addEventListener("keyup", async (e) => {
    if (e.key === "Enter" && input.value) {
      try {
        const res = await api("/ai/copilot/chat", { method: "POST", body: JSON.stringify({ query: input.value }) });
        results.innerHTML = `<div style="padding:0.5rem;"><p><strong>AI Copilot Intent:</strong> <code>${esc(res.intent)}</code></p><div style="background:var(--panel-2); padding:1rem; border-radius:8px; line-height:1.5;">${esc(res.reply)}</div></div>`;
      } catch (err) { results.innerHTML = `<p style="color:var(--critical);">${esc(err.message)}</p>`; }
    }
  });
}

/* ---------- Router ---------- */
function route() {
  const hash = window.location.hash || "#/overview";
  const viewName = hash.replace("#/", "").split("?")[0] || "overview";

  $$("#nav a").forEach((a) => {
    a.classList.toggle("active", a.dataset.view === viewName);
  });
  $("#crumb").textContent = viewName.toUpperCase().replace("-", " ");

  const viewContainer = $("#view");
  viewContainer.innerHTML = `<div style="padding:2rem; text-align:center;">⚡ Loading ${esc(viewName)}...</div>`;

  switch (viewName) {
    case "overview": renderOverview(viewContainer); break;
    case "accounts": renderAccounts(viewContainer); break;
    case "assets": renderAssets(viewContainer); break;
    case "findings": renderFindings(viewContainer); break;
    case "compliance": renderCompliance(viewContainer); break;
    case "attack-paths": renderAttackPaths(viewContainer); break;
    case "knowledge-graph": renderKnowledgeGraph(viewContainer); break;
    case "iam": renderIAM(viewContainer); break;
    case "k8s": renderK8s(viewContainer); break;
    case "iac": renderIaC(viewContainer); break;
    case "cdr": renderCDR(viewContainer); break;
    case "copilot": renderCopilot(viewContainer); break;
    case "reports": renderReports(viewContainer); break;
    case "notifications": renderNotifications(viewContainer); break;
    case "organizations": renderMSSP(viewContainer); break;
    case "users": renderUsers(viewContainer); break;
    case "billing": renderBilling(viewContainer); break;
    case "apikeys": renderApiKeys(viewContainer); break;
    case "audit": renderAudit(viewContainer); break;
    case "settings": renderSettings(viewContainer); break;
    case "support": renderSupport(viewContainer); break;
    default: renderOverview(viewContainer); break;
  }
}

/* ---------- View Renderers ---------- */
async function renderOverview(container) {
  try {
    const metrics = await api("/dashboard/metrics");
    const summary = await api("/ai/summary");

    container.innerHTML = `
      <div class="grid grid-4" style="margin-bottom:1.5rem;">
        <div class="card" style="border-top:3px solid var(--pass);">
          <div class="card-header"><span class="card-title">Overall Security Score</span><span>🛡️</span></div>
          <div class="stat-val" style="color:var(--pass);">${metrics.overall_security_score}%</div>
          <div class="stat-sub">Grade A Enterprise Posture</div>
        </div>
        <div class="card" style="border-top:3px solid var(--critical);">
          <div class="card-header"><span class="card-title">Critical Risks</span><span>🚨</span></div>
          <div class="stat-val" style="color:var(--critical);">${metrics.critical_findings_count}</div>
          <div class="stat-sub">${metrics.high_findings_count} High Severity Risks</div>
        </div>
        <div class="card" style="border-top:3px solid var(--accent-2);">
          <div class="card-header"><span class="card-title">Compliance Score</span><span>📜</span></div>
          <div class="stat-val" style="color:var(--accent-2);">${metrics.compliance_score}%</div>
          <div class="stat-sub">10 Frameworks Monitored</div>
        </div>
        <div class="card" style="border-top:3px solid var(--accent);">
          <div class="card-header"><span class="card-title">Mean Time To Remediate</span><span>⏱️</span></div>
          <div class="stat-val">${metrics.average_mttr_hours} hrs</div>
          <div class="stat-sub">${metrics.remediation_progress_pct}% Progress Rate</div>
        </div>
      </div>

      <div class="card" style="margin-bottom:1.5rem; background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(15, 23, 42, 0.9)); border:1px solid var(--accent);">
        <div class="card-header">
          <span class="card-title">🤖 AI Executive Security Posture Summary</span>
          <span class="badge pass">AI Copilot v1.0</span>
        </div>
        <p style="font-size:1.05rem; line-height:1.6;">${esc(summary.summary_text)}</p>
      </div>

      <div class="grid grid-2">
        <div class="card">
          <div class="card-header"><span class="card-title">Top Misconfigurations</span></div>
          <table>
            <thead><tr><th>Check ID</th><th>Title</th><th>Count</th><th>Severity</th></tr></thead>
            <tbody>
              ${metrics.top_misconfigurations.map(m => `
                <tr>
                  <td><code>${esc(m.check_id)}</code></td>
                  <td>${esc(m.title)}</td>
                  <td>${m.count}</td>
                  <td><span class="badge ${m.severity}">${esc(m.severity.toUpperCase())}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <div class="card">
          <div class="card-header"><span class="card-title">Upcoming Scheduled Scans</span></div>
          <table>
            <thead><tr><th>Scan Name</th><th>Target</th><th>Cron</th></tr></thead>
            <tbody>
              ${metrics.scheduled_scans.map(s => `
                <tr>
                  <td><strong>${esc(s.scan_name)}</strong></td>
                  <td><code>${esc(s.target)}</code></td>
                  <td><code>${esc(s.cron)}</code></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card" style="color:var(--critical);">${esc(err.message)}</div>`; }
}

async function renderAccounts(container) {
  try {
    const accounts = await api("/accounts");
    container.innerHTML = `
      <div class="card-header" style="margin-bottom:1rem;">
        <h2>Connected Multi-Cloud Accounts (${accounts.length})</h2>
        <button class="btn primary" onclick="openConnectModal()">+ Connect Cloud Account</button>
      </div>
      <div class="grid grid-2">
        ${accounts.map(a => `
          <div class="card">
            <div class="card-header">
              <span class="card-title">${esc(a.provider.toUpperCase())} — ${esc(a.label || a.id)}</span>
              <span class="badge pass">${esc(a.status)}</span>
            </div>
            <p><strong>Environment:</strong> <code>${esc(a.environment_name || 'production')}</code></p>
            <div style="margin-top:1rem; display:flex; gap:0.5rem;">
              <button class="btn sm primary" onclick="triggerScan('${a.id}')">⚡ Trigger Audit Scan</button>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderAssets(container) {
  try {
    const assets = await api("/assets");
    container.innerHTML = `
      <div class="card">
        <div class="card-header"><h2>Multi-Cloud Asset Explorer (${assets.length})</h2></div>
        <table>
          <thead><tr><th>Asset Name</th><th>Provider</th><th>Category</th><th>Environment</th><th>Criticality</th><th>Exposure</th></tr></thead>
          <tbody>
            ${assets.map(a => `
              <tr>
                <td><strong>${esc(a.name)}</strong><br><small style="color:var(--muted);">${esc(a.resource_id)}</small></td>
                <td><span class="badge">${esc(a.provider.toUpperCase())}</span></td>
                <td>${esc(a.category)}</td>
                <td>${esc(a.environment)}</td>
                <td><span class="badge ${a.criticality === 'critical' ? 'critical' : 'medium'}">${esc(a.criticality.toUpperCase())}</span></td>
                <td>${a.is_internet_facing ? '<span class="badge critical">🌐 Public</span>' : '<span class="badge pass">🔒 Private</span>'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderFindings(container) {
  try {
    const findings = await api("/findings");
    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h2>Security & CNAPP Findings (${findings.length})</h2>
          <button class="btn" onclick="exportSIEM()">📡 Stream to SIEM (Splunk/Sentinel)</button>
        </div>
        <table>
          <thead><tr><th>Check ID</th><th>Severity</th><th>Resource</th><th>Status</th><th>AI Fix</th></tr></thead>
          <tbody>
            ${findings.map(f => `
              <tr>
                <td><code>${esc(f.check_id)}</code></td>
                <td><span class="badge ${f.severity}">${esc(f.severity.toUpperCase())}</span></td>
                <td><code>${esc(f.resource)}</code></td>
                <td><span class="badge">${esc(f.status)}</span></td>
                <td><button class="btn sm primary" onclick="showAIFix('${esc(f.check_id)}', '${esc(f.resource)}')">🤖 AI Fix</button></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderCompliance(container) {
  container.innerHTML = `
    <div class="card" style="margin-bottom:1.5rem;">
      <div class="card-header">
        <h2>Compliance Hub & Auditor Evidence Exporters</h2>
      </div>
      <p style="color:var(--muted);">Automated posture reports for CIS, SOC 2, ISO 27001, PCI DSS, FedRAMP, GDPR, CCPA, DORA, NIS2, and CSA CCM.</p>
    </div>
    <div class="grid grid-2">
      ${FRAMEWORKS.map(f => `
        <div class="card">
          <div class="card-header">
            <span class="card-title">${esc(FRAMEWORK_LABELS[f] || f)}</span>
            <span class="badge pass">Score: 94%</span>
          </div>
          <button class="btn sm" style="margin-top:0.5rem;" onclick="exportReport('${f}', 'pdf')">Export PDF Evidence</button>
        </div>
      `).join('')}
    </div>
  `;
}

function exportReport(reportType, format) {
  window.open(`${API}/reports/export?report_type=${reportType}&format=${format}`, '_blank');
}

async function exportSIEM() {
  try {
    const res = await api("/siem/export", { method: "POST", body: JSON.stringify({ siem_provider: "splunk" }) });
    toast(`Streamed ${res.logs_streamed_count} log events to Splunk HEC!`, "success");
  } catch (err) { toast(err.message, "error"); }
}

async function renderAttackPaths(container) {
  try {
    const paths = await api("/attack-paths");
    container.innerHTML = `
      <div class="card" style="margin-bottom:1.5rem;">
        <div class="card-header"><h2>Visual Attack Path Graph</h2><span class="badge critical">Exploitable Paths</span></div>
      </div>
      ${paths.map(p => `
        <div class="card" style="margin-bottom:1.5rem; border-left:4px solid var(--critical);">
          <div class="card-header"><span class="card-title">${esc(p.title)}</span><span class="badge critical">Risk Score: ${p.risk_score} / 10</span></div>
          <div style="margin:1rem 0;">
            ${p.steps.map(s => `
              <div class="path-node"><strong>Step ${s.step}: ${esc(s.label)}</strong><div style="color:var(--muted); font-size:0.85rem;">${esc(s.description)}</div></div>
              ${s.step < p.steps.length ? '<div class="path-arrow">↓</div>' : ''}
            `).join('')}
          </div>
        </div>
      `).join('')}
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderKnowledgeGraph(container) {
  try {
    const graph = await api("/knowledge-graph");
    container.innerHTML = `
      <div class="card">
        <div class="card-header"><h2>Security Knowledge Graph</h2><span class="badge critical">Max Blast Radius: ${graph.max_blast_radius} Downstream Resources</span></div>
        <div class="grid grid-2" style="margin-top:1rem;">
          <div style="display:flex; flex-wrap:wrap; gap:1rem;">
            ${graph.nodes.map(n => `
              <div style="background:var(--panel-2); border:1px solid var(--accent); padding:1rem; border-radius:8px; width:200px; text-align:center;">
                <strong>${esc(n.name)}</strong>
                <div style="font-size:0.8rem; color:var(--muted);">${esc(n.category)}</div>
                <span class="badge ${n.risk_score >= 9 ? 'critical' : 'pass'}" style="margin-top:0.5rem;">Blast Radius: ${n.blast_radius}</span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderIAM(container) {
  try {
    const iam = await api("/iam-explorer");
    container.innerHTML = `
      <div class="card">
        <div class="card-header"><h2>IAM Explorer — Roles & Entitlements</h2></div>
        <h3>Identified IAM Roles (${iam.roles_count})</h3>
        <table>
          <thead><tr><th>Role Name</th><th>Trust Principal</th><th>Unused Perms</th><th>Cross-Account</th></tr></thead>
          <tbody>
            ${iam.roles.map(r => `
              <tr>
                <td><strong>${esc(r.name)}</strong></td>
                <td><code>${esc(r.trust_relationship.principal)}</code></td>
                <td><span class="badge high">${r.unused_permissions_pct}% Unused</span></td>
                <td>${r.is_cross_account ? '<span class="badge critical">Yes</span>' : '<span class="badge pass">No</span>'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderK8s(container) {
  container.innerHTML = `<div class="card"><h2>Kubernetes Security Auditor</h2><p style="color:var(--muted);">Audits EKS, AKS, GKE Pod security standards and RBAC policies.</p></div>`;
}

async function renderIaC(container) {
  container.innerHTML = `<div class="card"><h2>Infrastructure as Code (IaC) Static Scanner</h2><p style="color:var(--muted);">Scan Terraform, CloudFormation, ARM, Pulumi files.</p></div>`;
}

async function renderCDR(container) {
  try {
    const events = await api("/runtime/events");
    container.innerHTML = `
      <div class="card">
        <div class="card-header"><h2>Runtime Security & CDR (${events.length} Threat Events)</h2></div>
        <table>
          <thead><tr><th>Threat Title</th><th>Event Type</th><th>Severity</th><th>Resource</th></tr></thead>
          <tbody>
            ${events.map(e => `
              <tr>
                <td><strong>${esc(e.title)}</strong></td>
                <td><code>${esc(e.event_type)}</code></td>
                <td><span class="badge ${e.severity}">${esc(e.severity.toUpperCase())}</span></td>
                <td><code>${esc(e.resource)}</code></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderCopilot(container) {
  container.innerHTML = `
    <div class="card">
      <div class="card-header"><h2>🤖 Unified AI Security Copilot Assistant</h2></div>
      <div id="copilot-chat-history" style="height:300px; background:var(--panel-2); padding:1rem; border-radius:8px; overflow-y:auto; margin-bottom:1rem;">
        <p style="color:var(--muted);">Ask the AI Copilot anything (e.g. 'Why is AWS-S3-001 critical?', 'Generate Terraform fix')...</p>
      </div>
      <div style="display:flex; gap:0.5rem;">
        <input id="copilot-input" style="flex:1;" placeholder="Ask AI Copilot..." />
        <button class="btn primary" onclick="sendCopilotMsg()">Send Query</button>
      </div>
    </div>
  `;
}

async function sendCopilotMsg() {
  const inp = $("#copilot-input");
  const hist = $("#copilot-chat-history");
  if (!inp || !inp.value) return;
  const q = inp.value;
  inp.value = "";
  hist.innerHTML += `<div style="margin-bottom:0.8rem; text-align:right;"><strong>You:</strong> ${esc(q)}</div>`;
  try {
    const res = await api("/ai/copilot/chat", { method: "POST", body: JSON.stringify({ query: q }) });
    hist.innerHTML += `<div style="margin-bottom:0.8rem; background:var(--panel); padding:0.8rem; border-radius:8px;"><strong>🤖 AI Copilot:</strong> ${esc(res.reply)}</div>`;
    hist.scrollTop = hist.scrollHeight;
  } catch (err) { hist.innerHTML += `<p style="color:var(--critical);">${esc(err.message)}</p>`; }
}

async function renderReports(container) {
  container.innerHTML = `
    <div class="card">
      <div class="card-header"><h2>Reports & Multi-Format Exporters</h2></div>
      <div class="grid grid-2" style="margin-top:1rem;">
        <button class="btn primary" onclick="exportReport('executive', 'pdf')">📄 Export PDF Executive Summary</button>
        <button class="btn secondary" onclick="exportReport('technical', 'csv')">📊 Export CSV Technical Findings</button>
      </div>
    </div>
  `;
}

async function renderNotifications(container) {
  container.innerHTML = `<div class="card"><h2>Notifications & Alert Policies</h2><p style="color:var(--muted);">Configure Slack, MS Teams, Discord, PagerDuty, Webhooks.</p></div>`;
}

async function renderMSSP(container) {
  try {
    const clients = await api("/mssp/clients");
    container.innerHTML = `
      <div class="card">
        <div class="card-header"><h2>MSSP Partner Portal</h2></div>
        <div class="grid grid-2" style="margin-top:1rem;">
          ${clients.map(c => `
            <div class="card">
              <span class="card-title">🏢 ${esc(c.client_name)}</span>
              <p>Org ID: <code>${esc(c.client_org_id)}</code></p>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderUsers(container) {
  try {
    const members = await api("/organization/members");
    container.innerHTML = `
      <div class="card">
        <div class="card-header"><h2>Team Members & SCIM SSO Provisioning</h2></div>
        <table>
          <thead><tr><th>Full Name</th><th>Email</th><th>Role</th><th>MFA</th></tr></thead>
          <tbody>
            ${members.map(m => `
              <tr>
                <td><strong>${esc(m.full_name)}</strong></td>
                <td>${esc(m.email)}</td>
                <td><span class="badge pass">${esc(m.role.toUpperCase())}</span></td>
                <td>${m.mfa_enabled ? '<span class="badge pass">Enabled</span>' : '<span class="badge critical">Disabled</span>'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderBilling(container) {
  container.innerHTML = `
    <div class="card">
      <div class="card-header"><h2>Billing & 6-Tier CNAPP Licensing</h2></div>
      <div class="grid grid-4" style="margin-top:1rem;">
        <div class="card"><h3>Community</h3><div class="stat-val">$0</div></div>
        <div class="card"><h3>Starter</h3><div class="stat-val">$49</div></div>
        <div class="card"><h3>Professional</h3><div class="stat-val">$299</div></div>
        <div class="card"><h3>Business</h3><div class="stat-val">$999</div></div>
      </div>
    </div>
  `;
}

async function renderApiKeys(container) {
  container.innerHTML = `<div class="card"><h2>API Keys & Software Development Kits (SDKs)</h2></div>`;
}

async function renderAudit(container) {
  container.innerHTML = `<div class="card"><h2>Tamper-Evident Audit Logs</h2></div>`;
}

async function renderSettings(container) {
  container.innerHTML = `
    <div class="card">
      <div class="card-header"><h2>Settings & White-Label Customization</h2></div>
      <label style="margin-top:1rem;">Organization Name</label>
      <input id="set-org-name" placeholder="Enterprise Inc." value="Enterprise Workspace" />
      <button class="btn primary" style="margin-top:1rem;" onclick="saveSettings()">Save Settings</button>
    </div>
  `;
}

async function saveSettings() {
  try {
    await api("/organization/settings", { method: "POST", body: JSON.stringify({ name: $("#set-org-name").value }) });
    toast("Settings updated successfully!", "success");
  } catch (err) { toast(err.message, "error"); }
}

async function renderSupport(container) {
  container.innerHTML = `<div class="card"><h2>Support, System Health & Documentation</h2></div>`;
}

/* ---------- Global Modal Handlers ---------- */
async function showAIFix(checkId, resource) {
  modal(`🤖 AI Security Fix — ${checkId}`, `<div id="ai-modal-content">Loading AI recommendations...</div>`, async (mbody) => {
    try {
      const res = await api("/ai/remediate", { method: "POST", body: JSON.stringify({ check_id: checkId, resource: resource }) });
      mbody.innerHTML = `
        <p><strong>Explanation:</strong> ${esc(res.explanation)}</p>
        <p><strong>AWS CLI Fix:</strong> <code>${esc(res.cli_fix)}</code></p>
        <p><strong>Terraform Code:</strong> <pre>${esc(res.terraform_fix)}</pre></p>
      `;
    } catch (err) { mbody.innerHTML = `<p style="color:var(--critical);">${esc(err.message)}</p>`; }
  });
}

function openConnectModal() {
  modal("Connect AWS Account", `
    <form id="connect-aws-form">
      <label>Account Label</label>
      <input id="aws-label" placeholder="Prod AWS" required />
      <button type="submit" class="btn primary full" style="margin-top:1rem;">Connect</button>
    </form>
  `, (mbody, close) => {
    $("#connect-aws-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await api("/accounts/aws", { method: "POST", body: JSON.stringify({ provider: "aws", label: $("#aws-label").value, role_arn: "arn:aws:iam::123:role/Aegis" }) });
        toast("AWS Account Connected!", "success");
        close();
        route();
      } catch (err) { toast(err.message, "error"); }
    });
  });
}

function triggerScan(accId) {
  api(`/accounts/${accId}/scan`, { method: "POST" })
    .then(() => { toast("Scan queued successfully", "success"); route(); })
    .catch((err) => toast(err.message, "error"));
}

window.addEventListener("DOMContentLoaded", init);
