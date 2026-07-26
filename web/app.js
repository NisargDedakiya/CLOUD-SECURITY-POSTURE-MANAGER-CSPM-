const API = "/api/v1/cspm";
const FRAMEWORKS = ["cis_aws_v2", "soc2", "iso27001", "pci_dss_v4"];

const $ = (id) => document.getElementById(id);

function headers() {
  return { "Content-Type": "application/json", "X-Org-Id": $("org-id").value.trim() };
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, { headers: headers(), ...opts });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `${res.status} ${res.statusText}`);
  }
  return res.status === 204 ? null : res.json();
}

function escapeHtml(str) {
  const d = document.createElement("div");
  d.textContent = str == null ? "" : str;
  return d.innerHTML;
}

async function connectAccount() {
  const btn = $("connect-btn");
  btn.disabled = true;
  try {
    await api("/accounts", {
      method: "POST",
      body: JSON.stringify({
        provider: "aws",
        label: $("label").value || "aws",
        role_arn: $("role-arn").value.trim(),
      }),
    });
    $("role-arn").value = "";
    await refresh();
  } catch (e) {
    alert("Connect failed: " + e.message);
  } finally {
    btn.disabled = false;
  }
}

async function scanAccount(id) {
  try {
    await api(`/accounts/${id}/scan`, { method: "POST" });
    await refresh();
  } catch (e) {
    alert("Scan failed: " + e.message);
  }
}

async function renderAccounts() {
  const accounts = await api("/accounts");
  if (!accounts.length) {
    $("accounts").innerHTML = `<p class="empty">No accounts connected yet.</p>`;
    return;
  }
  $("accounts").innerHTML = accounts
    .map(
      (a) => `<div class="account">
        <div><strong>${escapeHtml(a.label || a.provider)}</strong>
          <span class="cloud-tag">${a.provider}</span>
          <span class="status ${a.status}">${a.status}</span></div>
        <button data-scan="${a.id}">Run Scan</button>
      </div>`
    )
    .join("");
  document
    .querySelectorAll("[data-scan]")
    .forEach((b) => b.addEventListener("click", () => scanAccount(b.dataset.scan)));
}

async function renderCompliance() {
  const cards = await Promise.all(
    FRAMEWORKS.map(async (fw) => {
      try {
        const d = await api(`/compliance/${fw}`);
        const cls = d.score >= 80 ? "good" : d.score >= 50 ? "warn" : "bad";
        return `<div class="card"><div class="value ${cls}">${d.score}%</div>
          <div class="label">${fw}</div>
          <div class="sub">${d.checks_passed}/${d.checks_applicable} controls</div></div>`;
      } catch {
        return `<div class="card"><div class="value">–</div><div class="label">${fw}</div></div>`;
      }
    })
  );
  $("compliance").innerHTML = cards.join("");
}

async function renderFindings() {
  const sev = $("sev-filter").value;
  const findings = await api("/findings" + (sev ? `?severity=${sev}` : ""));
  if (!findings.length) {
    $("findings").innerHTML = `<p class="empty">No findings. &#127881;</p>`;
    return;
  }
  $("findings").innerHTML = findings
    .map(
      (f) => `<div class="finding ${f.severity}">
        <div class="top">
          <span class="badge ${f.severity}">${f.severity}</span>
          <span class="title">${escapeHtml(f.description || f.check_id)}</span>
          <span class="fstatus">${f.status}</span>
        </div>
        <div class="res">${escapeHtml(f.resource)}</div>
        <div class="fix"><span>Fix:</span> ${escapeHtml(f.remediation)}</div>
      </div>`
    )
    .join("");
}

async function refresh() {
  try {
    await renderAccounts();
    await renderCompliance();
    await renderFindings();
  } catch (e) {
    $("findings").innerHTML = `<p class="empty">${escapeHtml(e.message)}</p>`;
  }
}

$("connect-btn").addEventListener("click", connectAccount);
$("refresh-btn").addEventListener("click", refresh);
$("sev-filter").addEventListener("change", renderFindings);
$("org-id").addEventListener("change", refresh);

refresh();
