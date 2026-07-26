const scanBtn = document.getElementById("scan-btn");
const summaryEl = document.getElementById("summary");
const findingsEl = document.getElementById("findings");
const sevFilter = document.getElementById("sev-filter");

let lastResult = null;

function selectedClouds() {
  return Array.from(document.querySelectorAll(".cloud-filter:checked")).map((c) => c.value);
}

async function runScan() {
  scanBtn.disabled = true;
  scanBtn.textContent = "Scanning...";
  findingsEl.innerHTML = "";
  try {
    const params = new URLSearchParams();
    selectedClouds().forEach((c) => params.append("cloud", c));
    const res = await fetch(`/api/scan?${params.toString()}`);
    if (!res.ok) throw new Error(`Scan failed: ${res.status}`);
    lastResult = await res.json();
    render();
  } catch (err) {
    findingsEl.innerHTML = `<div class="empty">${err.message}</div>`;
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "Run Scan";
  }
}

function card(value, label) {
  return `<div class="card"><div class="value">${value}</div><div class="label">${label}</div></div>`;
}

function render() {
  if (!lastResult) return;
  const s = lastResult.summary;
  summaryEl.innerHTML = [
    card(`${s.posture_score}%`, "Posture Score"),
    card(s.total_findings, "Open Findings"),
    card(s.resources_scanned, "Resources"),
    card(s.by_severity.critical, "Critical"),
    card(s.by_severity.high, "High"),
    card(s.passed_checks, "Passed Checks"),
  ].join("");
  renderFindings();
}

function renderFindings() {
  const wanted = sevFilter.value;
  const failed = lastResult.findings.filter((f) => !f.passed);
  const filtered = wanted ? failed.filter((f) => f.severity === wanted) : failed;

  if (filtered.length === 0) {
    findingsEl.innerHTML = `<div class="empty">No findings match. &#127881;</div>`;
    return;
  }

  findingsEl.innerHTML = filtered
    .map(
      (f) => `
    <div class="finding ${f.severity}">
      <div class="top">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="cloud-tag">${f.cloud}</span>
        <span class="title">${escapeHtml(f.title)}</span>
      </div>
      <div class="res">${escapeHtml(f.resource_type)} &middot; ${escapeHtml(f.resource_id)}</div>
      <div class="fix"><span>Fix:</span> ${escapeHtml(f.remediation)}</div>
    </div>`
    )
    .join("");
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

scanBtn.addEventListener("click", runScan);
sevFilter.addEventListener("change", renderFindings);

runScan();
