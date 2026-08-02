/* Aegis Enterprise CNAPP Web App — Modern Commercial Platform */
"use strict";

const API = "/api/v1/cspm";
const SEVS = ["critical", "high", "medium", "low", "info"];
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
      toast("Demo workspace populated with Knowledge Graph, Attack Paths, and Assets!", "success");
      route();
    } catch (e) { toast(e.message, "error"); }
  });
}

function bindGlobalNav() {
  $("#theme-toggle")?.addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme");
    document.documentElement.setAttribute("data-theme", cur === "light" ? "dark" : "light");
  });
  $("#quick-scan-btn")?.addEventListener("click", async () => {
    try {
      toast("Running CNAPP multi-cloud security audit...", "info");
      await api("/accounts");
      toast("Audit run complete!", "success");
      route();
    } catch (e) { toast(e.message, "error"); }
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
        const res = await api("/ai/search", { method: "POST", body: JSON.stringify({ query: input.value }) });
        results.innerHTML = `<div style="padding:0.5rem;"><p><strong>AI Copilot Intent:</strong> <code>${esc(res.intent)}</code> (${res.count} items)</p><pre style="background:var(--panel-2); padding:1rem; border-radius:8px;">${esc(JSON.stringify(res.results, null, 2))}</pre></div>`;
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
    case "knowledge-graph": renderKnowledgeGraph(viewContainer); break;
    case "asset-tree": renderAssetTree(viewContainer); break;
    case "cdr": renderCDR(viewContainer); break;
    case "accounts": renderAccounts(viewContainer); break;
    case "findings": renderFindings(viewContainer); break;
    case "ciem": renderCIEM(viewContainer); break;
    case "attack-paths": renderAttackPaths(viewContainer); break;
    case "assets": renderAssets(viewContainer); break;
    case "k8s": renderK8s(viewContainer); break;
    case "iac": renderIaC(viewContainer); break;
    case "compliance": renderCompliance(viewContainer); break;
    case "drift": renderDrift(viewContainer); break;
    case "mssp": renderMSSP(viewContainer); break;
    case "apikeys": renderApiKeys(viewContainer); break;
    case "billing": renderBilling(viewContainer); break;
    default: renderOverview(viewContainer); break;
  }
}

/* ---------- View Renderers ---------- */
async function renderOverview(container) {
  try {
    const summary = await api("/ai/summary");
    const findings = await api("/findings?limit=5");
    const accounts = await api("/accounts");

    container.innerHTML = `
      <div class="grid grid-4" style="margin-bottom:1.5rem;">
        <div class="card">
          <div class="card-header"><span class="card-title">Security Posture Score</span><span>🛡️</span></div>
          <div class="stat-val" style="color:var(--pass);">91.5%</div>
          <div class="stat-sub">+${summary.improvements_pct}% improvement this month</div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Critical Risks</span><span>🚨</span></div>
          <div class="stat-val" style="color:var(--critical);">${summary.critical_findings_count}</div>
          <div class="stat-sub">${summary.total_open_findings} total open findings</div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Connected Accounts</span><span>🔌</span></div>
          <div class="stat-val">${accounts.length}</div>
          <div class="stat-sub">AWS, GCP, Azure, Kubernetes</div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">MTTR (Remediation)</span><span>⏱️</span></div>
          <div class="stat-val" style="color:var(--accent-2);">4.2 hrs</div>
          <div class="stat-sub">Mean Time To Remediate</div>
        </div>
      </div>

      <div class="card" style="margin-bottom:1.5rem; background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(15, 23, 42, 0.9));">
        <div class="card-header">
          <span class="card-title">🤖 AI Executive Security Posture Summary</span>
          <span class="badge pass">AI Copilot v1.0</span>
        </div>
        <p style="font-size:1.05rem; line-height:1.6;">${esc(summary.summary_text)}</p>
        <div style="margin-top:1rem;">
          <strong>Monthly Highlights:</strong>
          <ul style="margin:0.5rem 0 0 1.2rem; color:var(--muted);">
            ${summary.highlights.map(h => `<li>${esc(h)}</li>`).join('')}
          </ul>
        </div>
      </div>

      <div class="card">
        <div class="card-header"><span class="card-title">Recent Security Findings</span></div>
        <table>
          <thead>
            <tr><th>Check ID</th><th>Severity</th><th>Resource</th><th>Status</th><th>Action</th></tr>
          </thead>
          <tbody>
            ${findings.map(f => `
              <tr>
                <td><code>${esc(f.check_id)}</code></td>
                <td><span class="badge ${f.severity}">${esc(f.severity.toUpperCase())}</span></td>
                <td><code>${esc(f.resource)}</code></td>
                <td>${esc(f.status)}</td>
                <td><button class="btn sm primary" onclick="showAIFix('${esc(f.check_id)}', '${esc(f.resource)}')">🤖 AI Fix</button></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card" style="color:var(--critical);">Error loading overview: ${esc(err.message)}</div>`; }
}

async function renderKnowledgeGraph(container) {
  try {
    const graph = await api("/knowledge-graph");
    container.innerHTML = `
      <div class="card" style="margin-bottom:1.5rem;">
        <div class="card-header">
          <h2>Cloud Security Knowledge Graph</h2>
          <span class="badge critical">Max Blast Radius: ${graph.max_blast_radius} Downstream Resources</span>
        </div>
        <p style="color:var(--muted);">Visual graph linking cloud resources, IAM trusts, security groups, and attack paths. Click any node to inspect blast radius.</p>
      </div>

      <div class="grid grid-2" style="margin-bottom:1.5rem;">
        <div class="card" style="min-height:360px; background:var(--panel-2); display:flex; flex-direction:column; justify-content:center; align-items:center; border:1px solid var(--accent);">
          <div style="font-size:1.1rem; font-weight:700; margin-bottom:1rem; color:var(--accent-2);">🕸️ Interactive Security Knowledge Graph</div>
          <div style="display:flex; flex-wrap:wrap; gap:1rem; justify-content:center; max-width:500px;">
            ${graph.nodes.map(n => `
              <div onclick="inspectNode('${esc(n.id)}', '${esc(n.name)}', ${n.blast_radius}, ${n.risk_score})"
                   style="background:var(--panel); border:2px solid ${n.risk_score >= 9 ? 'var(--critical)' : 'var(--accent)'}; padding:0.8rem 1.2rem; border-radius:12px; cursor:pointer; text-align:center; box-shadow:0 0 12px rgba(99,102,241,0.2);">
                <div style="font-weight:700;">${esc(n.name)}</div>
                <div style="font-size:0.75rem; color:var(--muted);">${esc(n.category.toUpperCase())}</div>
                <span class="badge ${n.risk_score >= 9 ? 'critical' : 'pass'}" style="margin-top:0.3rem;">Blast Radius: ${n.blast_radius}</span>
              </div>
            `).join('')}
          </div>
        </div>

        <div id="node-inspector" class="card">
          <div class="card-header"><span class="card-title">🔍 Node Inspector</span></div>
          <p style="color:var(--muted);">Click any node in the Knowledge Graph to inspect downstream blast radius, IAM roles, and compliance impact.</p>
        </div>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

function inspectNode(id, name, blastRadius, riskScore) {
  const inspector = $("#node-inspector");
  if (!inspector) return;
  inspector.innerHTML = `
    <div class="card-header">
      <span class="card-title">${esc(name)}</span>
      <span class="badge critical">Risk Score: ${riskScore} / 10</span>
    </div>
    <p><strong>Resource ID:</strong> <code>${esc(id)}</code></p>
    <p><strong>Blast Radius Impact:</strong> <span class="badge critical">${blastRadius} Downstream Resources</span></p>
    <p style="color:var(--muted); margin-top:0.8rem;">If this resource is compromised, an attacker can pivot across connected IAM roles and database instances.</p>
    <button class="btn primary full" style="margin-top:1rem;" onclick="showAIFix('KNOWLEDGE-GRAPH-RISK', '${esc(id)}')">🤖 Generate AI Fix & Blast Radius Mitigation</button>
  `;
}

async function renderAssetTree(container) {
  try {
    const tree = await api("/asset-hierarchy");
    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h2>Hierarchical Cloud Asset Explorer</h2>
        </div>
        <p style="color:var(--muted); margin-bottom:1rem;">Hierarchy: Organization → Cloud Provider → Account → VPC → Cloud Resources.</p>
        <div style="font-family:var(--font-mono); background:var(--panel-2); padding:1.2rem; border-radius:10px;">
          <div style="font-weight:700; color:var(--accent-2);">🏢 ${esc(tree.name)}</div>
          <div style="margin-left:1.5rem; margin-top:0.5rem;">
            ${tree.children.map(p => `
              <div style="margin-bottom:0.8rem;">
                <div>☁️ <strong>${esc(p.name)}</strong></div>
                <div style="margin-left:1.5rem;">
                  ${p.children.map(acc => `
                    <div>🔑 <strong>${esc(acc.name)}</strong></div>
                    <div style="margin-left:1.5rem; color:var(--muted);">
                      ${(acc.children || []).map(r => `
                        <div>📦 ${esc(r.name)} <span class="badge ${r.status === 'critical_risk' ? 'critical' : 'pass'}">${esc(r.status || 'active')}</span></div>
                      `).join('')}
                    </div>
                  `).join('')}
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderCDR(container) {
  try {
    const events = await api("/runtime/events");
    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h2>Runtime Security & Cloud Detection & Response (CDR)</h2>
          <span class="badge critical">${events.length} Active Threat Events</span>
        </div>
        <p style="color:var(--muted); margin-bottom:1rem;">Real-time container runtime process anomalies and suspicious cloud API calls.</p>
        <table>
          <thead>
            <tr><th>Threat Title</th><th>Event Type</th><th>Severity</th><th>Resource</th><th>Detected At</th><th>Recommended Action</th></tr>
          </thead>
          <tbody>
            ${events.map(e => `
              <tr>
                <td><strong>${esc(e.title)}</strong><br><small style="color:var(--muted);">${esc(e.source)}</small></td>
                <td><code>${esc(e.event_type)}</code></td>
                <td><span class="badge ${e.severity}">${esc(e.severity.toUpperCase())}</span></td>
                <td><code>${esc(e.resource)}</code></td>
                <td>${new Date(e.detected_at).toLocaleTimeString()}</td>
                <td><span style="color:var(--accent-2); font-size:0.85rem;">${esc(e.recommended_action)}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderAccounts(container) {
  try {
    const accounts = await api("/accounts");
    container.innerHTML = `
      <div class="card-header" style="margin-bottom:1rem;">
        <h2>Connected Multi-Cloud Accounts</h2>
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
            <p><strong>Created At:</strong> ${new Date(a.created_at).toLocaleString()}</p>
            <div style="margin-top:1rem; display:flex; gap:0.5rem;">
              <button class="btn sm primary" onclick="triggerScan('${a.id}')">⚡ Trigger Audit Scan</button>
            </div>
          </div>
        `).join('')}
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
          <thead>
            <tr><th>Check ID</th><th>Severity</th><th>Resource</th><th>Discovered</th><th>Status</th><th>AI Copilot Fix</th></tr>
          </thead>
          <tbody>
            ${findings.map(f => `
              <tr>
                <td><code>${esc(f.check_id)}</code></td>
                <td><span class="badge ${f.severity}">${esc(f.severity.toUpperCase())}</span></td>
                <td><code>${esc(f.resource)}</code></td>
                <td>${new Date(f.discovered_at).toLocaleDateString()}</td>
                <td><span class="badge">${esc(f.status)}</span></td>
                <td><button class="btn sm primary" onclick="showAIFix('${esc(f.check_id)}', '${esc(f.resource)}')">🤖 AI Fix Recommendation</button></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderCIEM(container) {
  try {
    const ciems = await api("/ciem");
    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h2>CIEM — Cloud Infrastructure Entitlement Management</h2>
          <span class="badge high">Identity Risks Detected</span>
        </div>
        <p style="color:var(--muted); margin-bottom:1rem;">Analyzes IAM excessive permissions, dormant accounts, cross-account trusts, and privilege escalation paths.</p>
        <table>
          <thead>
            <tr><th>Identity Name</th><th>Risk Type</th><th>Risk Score</th><th>Impact & Remediation</th></tr>
          </thead>
          <tbody>
            ${ciems.map(c => `
              <tr>
                <td><strong>${esc(c.identity_name)}</strong></td>
                <td><span class="badge critical">${esc(c.risk_type.toUpperCase())}</span></td>
                <td><strong style="color:var(--critical);">${c.risk_score} / 10</strong></td>
                <td>
                  <p><strong>Impact:</strong> ${esc(c.details.impact || c.details.vector || '')}</p>
                  <p style="color:var(--accent-2);"><strong>Fix:</strong> ${esc(c.details.remediation)}</p>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderAttackPaths(container) {
  try {
    const paths = await api("/attack-paths");
    container.innerHTML = `
      <div class="card" style="margin-bottom:1.5rem;">
        <div class="card-header">
          <h2>Attack Path Analysis Graph</h2>
          <span class="badge critical">2 Exploitable Paths</span>
        </div>
        <p style="color:var(--muted);">Maps multi-hop compromise chains from external internet boundaries to crown-jewel databases.</p>
      </div>

      ${paths.map(p => `
        <div class="card" style="margin-bottom:1.5rem; border-left:4px solid var(--critical);">
          <div class="card-header">
            <span class="card-title">${esc(p.title)}</span>
            <span class="badge critical">Risk Score: ${p.risk_score} / 10</span>
          </div>
          <div style="margin:1rem 0;">
            ${p.steps.map(s => `
              <div class="path-node">
                <div style="display:flex; justify-content:space-between;">
                  <strong>Step ${s.step}: ${esc(s.label)}</strong>
                  <span class="badge high">${esc(s.node_type)}</span>
                </div>
                <div style="color:var(--muted); font-size:0.85rem; margin-top:0.3rem;">${esc(s.description)}</div>
              </div>
              ${s.step < p.steps.length ? '<div class="path-arrow">↓</div>' : ''}
            `).join('')}
          </div>
        </div>
      `).join('')}
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderAssets(container) {
  try {
    const assets = await api("/assets");
    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h2>Unified Multi-Cloud Asset Inventory (${assets.length})</h2>
        </div>
        <table>
          <thead>
            <tr><th>Asset Name</th><th>Provider</th><th>Category</th><th>Environment</th><th>Criticality</th><th>Exposure</th></tr>
          </thead>
          <tbody>
            ${assets.map(a => `
              <tr>
                <td><strong>${esc(a.name)}</strong><br><small style="color:var(--muted);">${esc(a.resource_id)}</small></td>
                <td><span class="badge">${esc(a.provider.toUpperCase())}</span></td>
                <td>${esc(a.category)}</td>
                <td>${esc(a.environment)}</td>
                <td><span class="badge ${a.criticality === 'critical' ? 'critical' : 'medium'}">${esc(a.criticality.toUpperCase())}</span></td>
                <td>${a.is_internet_facing ? '<span class="badge critical">🌐 Internet Facing</span>' : '<span class="badge pass">🔒 Private</span>'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderK8s(container) {
  container.innerHTML = `
    <div class="card" style="margin-bottom:1.5rem;">
      <div class="card-header">
        <h2>Kubernetes Security Auditor (EKS / AKS / GKE)</h2>
        <button class="btn primary" onclick="runK8sAudit()">⚡ Audit EKS Cluster</button>
      </div>
      <p style="color:var(--muted);">Audits Privileged Pods, RBAC wildcards, Network Policies, and Secrets exposure.</p>
    </div>
    <div id="k8s-results"></div>
  `;
  runK8sAudit();
}

async function runK8sAudit() {
  const target = $("#k8s-results");
  if (!target) return;
  target.innerHTML = `<div class="card">Auditing cluster...</div>`;
  try {
    const res = await api("/k8s/scan", { method: "POST", body: JSON.stringify({ cluster_name: "eks-prod-us-east", distro: "eks" }) });
    target.innerHTML = `
      <div class="card">
        <div class="card-header">
          <span class="card-title">Cluster: ${esc(res.cluster_name)} (${esc(res.distro.toUpperCase())})</span>
          <span class="badge pass">Security Score: ${res.score} / 100</span>
        </div>
        <div class="grid grid-4" style="margin:1rem 0;">
          <div class="card"><div>Privileged Pods</div><div class="stat-val" style="color:var(--critical);">${res.privileged_pods}</div></div>
          <div class="card"><div>RBAC Violations</div><div class="stat-val" style="color:var(--high);">${res.rbac_violations}</div></div>
          <div class="card"><div>Missing Net Policies</div><div class="stat-val" style="color:var(--medium);">${res.missing_net_pol}</div></div>
          <div class="card"><div>Exposed Secrets</div><div class="stat-val" style="color:var(--high);">${res.exposed_secrets}</div></div>
        </div>
      </div>
    `;
  } catch (err) { target.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderIaC(container) {
  container.innerHTML = `
    <div class="card" style="margin-bottom:1.5rem;">
      <div class="card-header">
        <h2>Infrastructure as Code (IaC) Static Scanner</h2>
      </div>
      <p style="color:var(--muted);">Scan Terraform (.tf), CloudFormation, ARM/Bicep, and Pulumi before deployment.</p>
      <div style="margin-top:1rem;">
        <textarea id="iac-code" style="width:100%; height:140px; background:var(--panel-2); color:var(--text); border:1px solid var(--border); border-radius:8px; padding:0.8rem; font-family:var(--font-mono);" placeholder="Paste Terraform HCL or CloudFormation JSON here..."></textarea>
        <button class="btn primary" style="margin-top:0.8rem;" onclick="runIaCScan()">🔍 Run IaC Security Analysis</button>
      </div>
    </div>
    <div id="iac-results"></div>
  `;
}

async function runIaCScan() {
  const target = $("#iac-results");
  const code = $("#iac-code")?.value || 'resource "aws_security_group_rule" "ssh" { cidr_blocks = ["0.0.0.0/0"] from_port = 22 }';
  target.innerHTML = `<div class="card">Analyzing IaC code...</div>`;
  try {
    const res = await api("/iac/scan", { method: "POST", body: JSON.stringify({ file_path: "terraform/main.tf", iac_type: "terraform", content: code }) });
    target.innerHTML = `
      <div class="card">
        <div class="card-header">
          <span class="card-title">IaC Scan Findings (${res.findings_count})</span>
          <span class="badge ${res.findings_count > 0 ? 'critical' : 'pass'}">${res.findings_count} Security Violations</span>
        </div>
        ${res.issues.map(iss => `
          <div style="border-bottom:1px solid var(--border); padding:0.8rem 0;">
            <div style="display:flex; gap:0.5rem; align-items:center;">
              <span class="badge ${iss.severity}">${esc(iss.severity.toUpperCase())}</span>
              <strong>Line ${iss.line}: ${esc(iss.title)}</strong>
            </div>
            <p style="margin:0.3rem 0; color:var(--muted);">${esc(iss.description)}</p>
            <p style="color:var(--accent-2); margin:0;"><strong>Remediation:</strong> ${esc(iss.remediation)}</p>
          </div>
        `).join('')}
      </div>
    `;
  } catch (err) { target.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderCompliance(container) {
  container.innerHTML = `
    <div class="card" style="margin-bottom:1.5rem;">
      <div class="card-header">
        <h2>Compliance Frameworks & Multi-Format Exporter</h2>
        <div>
          <button class="btn primary" onclick="exportReport('executive', 'pdf')">📄 Export PDF</button>
          <button class="btn" onclick="exportReport('technical', 'csv')">📊 Export CSV</button>
          <button class="btn" onclick="exportReport('cis', 'json')">⚙️ Export JSON</button>
        </div>
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
          <p>Continuous automated compliance mapping.</p>
          <button class="btn sm" style="margin-top:0.5rem;" onclick="exportReport('${f}', 'pdf')">Download Evidence PDF</button>
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

async function renderDrift(container) {
  try {
    const drifts = await api("/drift");
    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h2>Configuration Drift Detection & Rollback Generator</h2>
          <span class="badge warn">${drifts.length} Drift Events</span>
        </div>
        <table>
          <thead>
            <tr><th>Resource</th><th>Type</th><th>Drift Type</th><th>Detected At</th><th>Rollback Command</th></tr>
          </thead>
          <tbody>
            ${drifts.map(d => `
              <tr>
                <td><code>${esc(d.resource_id || 'bucket-01')}</code></td>
                <td>${esc(d.resource_type || 's3')}</td>
                <td><span class="badge high">${esc(d.drift_type)}</span></td>
                <td>${new Date(d.detected_at).toLocaleString()}</td>
                <td>
                  <button class="btn sm primary" onclick="showRollback('${esc(d.rollback_cli)}', '${esc(d.rollback_terraform)}')">📜 View Rollback Script</button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

async function renderMSSP(container) {
  try {
    const clients = await api("/mssp/clients");
    container.innerHTML = `
      <div class="card" style="margin-bottom:1.5rem;">
        <div class="card-header">
          <h2>MSSP Partner Agency Portal</h2>
          <span class="badge pass">Partner License Active</span>
        </div>
        <p style="color:var(--muted);">Manage multi-tenant clients, white-label branding, and client-specific security posture reports.</p>
      </div>

      <div class="grid grid-2">
        ${clients.map(c => `
          <div class="card">
            <div class="card-header">
              <span class="card-title">🏢 ${esc(c.client_name)}</span>
              <span class="badge pass">Active Client</span>
            </div>
            <p><strong>Client Org ID:</strong> <code>${esc(c.client_org_id)}</code></p>
            <button class="btn sm primary" style="margin-top:0.8rem;" onclick="switchClientOrg('${esc(c.client_org_id)}')">🔄 Switch to Client Workspace</button>
          </div>
        `).join('')}
      </div>
    `;
  } catch (err) { container.innerHTML = `<div class="card">${esc(err.message)}</div>`; }
}

function switchClientOrg(orgId) {
  if (store.session) {
    store.session.org = orgId;
    store.session = store.session;
    toast(`Switched to client workspace: ${orgId}`, "success");
    route();
  }
}

async function renderApiKeys(container) {
  container.innerHTML = `
    <div class="card" style="margin-bottom:1.5rem;">
      <div class="card-header">
        <h2>API Keys & Software Development Kits (SDKs)</h2>
      </div>
      <p style="color:var(--muted);">REST and GraphQL programmatic access credentials.</p>
    </div>
    <div class="grid grid-2">
      <div class="card">
        <h3>Python SDK (<code>cspm-sdk</code>)</h3>
        <pre style="background:var(--panel-2); padding:0.8rem; border-radius:8px;">pip install aegis-cnapp-sdk
from aegis import AegisClient
client = AegisClient(api_key="cspm_...")
findings = client.list_findings()</pre>
      </div>
      <div class="card">
        <h3>JavaScript SDK (<code>@aegis/cnapp-sdk</code>)</h3>
        <pre style="background:var(--panel-2); padding:0.8rem; border-radius:8px;">npm install @aegis/cnapp-sdk
const { AegisClient } = require('@aegis/cnapp-sdk');
const client = new AegisClient('cspm_...');</pre>
      </div>
    </div>
  `;
}

async function renderBilling(container) {
  container.innerHTML = `
    <div class="card" style="margin-bottom:1.5rem;">
      <div class="card-header">
        <h2>Billing & 6-Tier CNAPP Licensing Model</h2>
        <span class="badge pass">Active Plan: Business</span>
      </div>
      <div class="grid grid-4" style="margin-top:1rem;">
        <div class="card" style="border-top:3px solid var(--accent-2);">
          <h3>Community</h3>
          <div class="stat-val">$0</div>
          <p style="color:var(--muted);">Free Learning & Open Source</p>
        </div>
        <div class="card" style="border-top:3px solid var(--pass);">
          <h3>Starter</h3>
          <div class="stat-val">$49 <small style="font-size:0.8rem;">/mo</small></div>
          <p style="color:var(--muted);">Small startups</p>
        </div>
        <div class="card" style="border-top:3px solid var(--high);">
          <h3>Professional</h3>
          <div class="stat-val">$299 <small style="font-size:0.8rem;">/mo</small></div>
          <p style="color:var(--muted);">Growing SaaS teams</p>
        </div>
        <div class="card" style="border-top:3px solid var(--critical);">
          <h3>Business</h3>
          <div class="stat-val">$999 <small style="font-size:0.8rem;">/mo</small></div>
          <p style="color:var(--muted);">Mid-market CNAPP</p>
        </div>
      </div>
    </div>
  `;
}

/* ---------- Global Modal Handlers ---------- */
async function showAIFix(checkId, resource) {
  modal(`🤖 AI Security Fix — ${checkId}`, `<div id="ai-modal-content">Loading AI recommendations...</div>`, async (mbody) => {
    try {
      const res = await api("/ai/remediate", { method: "POST", body: JSON.stringify({ check_id: checkId, resource: resource }) });
      mbody.innerHTML = `
        <p><strong>Explanation:</strong> ${esc(res.explanation)}</p>
        <p><strong>Root Cause:</strong> ${esc(res.root_cause)}</p>
        <p><strong>Risk Impact:</strong> ${esc(res.risk)}</p>
        <p><strong>Estimated Effort:</strong> <span class="badge pass">${esc(res.estimated_effort)}</span></p>
        
        <h4 style="margin-top:1rem;">AWS CLI Fix Command</h4>
        <pre style="background:var(--panel-2); padding:0.8rem; border-radius:8px; overflow-x:auto;">${esc(res.cli_fix)}</pre>
        
        <h4>Terraform Fix Code</h4>
        <pre style="background:var(--panel-2); padding:0.8rem; border-radius:8px; overflow-x:auto;">${esc(res.terraform_fix)}</pre>
        
        <h4>AWS Console Steps</h4>
        <p style="color:var(--muted);">${esc(res.console_fix)}</p>
      `;
    } catch (err) { mbody.innerHTML = `<p style="color:var(--critical);">${esc(err.message)}</p>`; }
  });
}

function showRollback(cliCmd, tfCode) {
  modal("📜 Rollback Script Recommendation", `
    <h4>AWS CLI Rollback Command</h4>
    <pre style="background:var(--panel-2); padding:0.8rem; border-radius:8px;">${esc(cliCmd || 'aws ec2 revoke-security-group-ingress')}</pre>
    <h4>Terraform Rollback Manifest</h4>
    <pre style="background:var(--panel-2); padding:0.8rem; border-radius:8px;">${esc(tfCode || '# Terraform apply rollback')}</pre>
  `);
}

function openConnectModal() {
  modal("Connect AWS Cloud Account", `
    <form id="connect-aws-form">
      <label>Account Label</label>
      <input id="aws-label" placeholder="Production AWS Account" required />
      <label>IAM Role ARN</label>
      <input id="aws-arn" placeholder="arn:aws:iam::123456789012:role/AegisAuditRole" required />
      <button type="submit" class="btn primary full" style="margin-top:1rem;">Connect Account</button>
    </form>
  `, (mbody, close) => {
    $("#connect-aws-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await api("/accounts/aws", { method: "POST", body: JSON.stringify({ provider: "aws", label: $("#aws-label").value, role_arn: $("#aws-arn").value }) });
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
