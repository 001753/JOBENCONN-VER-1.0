(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const notice = $("notice");
  const loginCard = $("login-card");
  const dashboardContent = $("dashboard-content");
  const searchInput = $("global-search");
  const searchResults = $("search-results");
  let currentSummary = null;
  let currentFindings = [];
  let searchTimer = null;

  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  }[character]));
  const csrf = () => decodeURIComponent((document.cookie.match(/(?:^|;\s*)joben_csrf=([^;]+)/) || [])[1] || "");
  const formatDate = (value) => value ? new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "Not available";
  const shortId = (value) => value ? `${String(value).slice(0, 12)}…` : "Not available";
  const showNotice = (message, error = false) => {
    notice.textContent = message;
    notice.className = `notice${error ? " error" : ""}`;
  };
  const api = async (path, options = {}) => {
    const response = await fetch(path, { credentials: "same-origin", ...options });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error?.message || `Request failed (${response.status})`);
    return payload;
  };
  const empty = (title, copy) => `<div class="empty-state"><strong>${escapeHtml(title)}</strong>${escapeHtml(copy)}</div>`;
  const statusClass = (status) => status === "PASS" ? "state-pass" : status === "FAIL" ? "state-fail" : status === "ERROR" ? "state-error" : "state-empty";
  const severityClass = (severity) => String(severity || "").toLowerCase();
  const showDetail = (title, content) => {
    $("detail-title").textContent = title;
    $("detail-content").innerHTML = content;
    $("detail-panel").classList.remove("hidden");
    $("detail-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
  };
  const hideDetail = () => $("detail-panel").classList.add("hidden");

  const postureCopy = (state) => ({
    ACTION_REQUIRED: ["Action required", "ACTION REQUIRED", "Your environment needs attention.", "One or more evaluated controls have failed."],
    INSUFFICIENT_EVIDENCE: ["Insufficient evidence", "INSUFFICIENT EVIDENCE", "The evidence chain needs review.", "Some control results could not be verified with sufficient evidence."],
    OBSERVED: ["Observed", "OBSERVED", "Current state is evidence-backed.", "The backend has observed passing control results for this organization."],
    NOT_EVALUATED: ["Awaiting scan", "NOT EVALUATED", "Your environment has not been evaluated yet.", "Run a read-only scan after an AWS account is verified to establish the first evidence-backed posture."]
  }[state] || ["Data unavailable", "DATA UNAVAILABLE", "Posture state unavailable.", "The backend did not return a posture state."]);

  const renderRisk = (summary) => {
    const counts = [
      ["Critical", summary.findings?.critical ?? null, "critical"],
      ["High", summary.controls?.fail ?? null, "high"],
      ["Medium", summary.controls?.error ?? null, "medium"],
      ["Low", summary.controls?.pass ?? null, "low"]
    ];
    const total = counts.reduce((sum, [, value]) => sum + (typeof value === "number" ? value : 0), 0);
    $("risk-total").textContent = total ? `${total} evaluated signals` : "No evaluation";
    $("risk-distribution").innerHTML = total ? counts.map(([label, value, className]) => {
      const safeValue = typeof value === "number" ? value : 0;
      return `<div class="risk-row"><span class="risk-label">${label}</span><span class="risk-bar"><i class="${className}" style="width:${Math.max(safeValue / total * 100, safeValue ? 3 : 0)}%"></i></span><strong class="risk-number">${safeValue}</strong></div>`;
    }).join("") : empty("Risk distribution unavailable", "No evaluated control or finding data has been returned.");
  };
  const renderActions = (summary) => {
    const actions = [];
    if ((summary.findings?.critical ?? 0) > 0) actions.push(["01", `${summary.findings.critical} critical finding(s) require attention`, "findings"]);
    if ((summary.controls?.fail ?? 0) > 0) actions.push(["02", `${summary.controls.fail} failed control result(s) need review`, "controls"]);
    if (!summary.accountList?.length) actions.push(["01", "Verify an AWS account before running the first scan", "accounts"]);
    if (!summary.latestEvidence) actions.push([String(actions.length + 1).padStart(2, "0"), "Commit evidence through the provider scan path", "evidence"]);
    if (!actions.length) {
      $("actions-list").innerHTML = empty("No action generated", "The backend has not returned an operational action for this organization.");
      return;
    }
    $("actions-list").innerHTML = actions.map(([number, text, target]) => `<button class="action-item" type="button" data-target="${target}"><span class="action-number">${number}</span><span>${escapeHtml(text)}</span><span class="action-arrow">→</span></button>`).join("");
  };
  const renderPosture = (summary) => {
    const [title, badge, detail, explanation] = postureCopy(summary.states?.posture);
    $("posture-value").textContent = title;
    $("posture-badge").textContent = badge;
    $("posture-badge").className = `status-badge ${summary.states?.posture === "ACTION_REQUIRED" ? "danger" : summary.states?.posture === "OBSERVED" ? "success" : summary.states?.posture === "INSUFFICIENT_EVIDENCE" ? "warning" : "neutral"}`;
    $("posture-detail").textContent = detail;
    $("posture-explanation").textContent = explanation;
    $("posture-score").textContent = summary.states?.complianceScore === "NOT_CALCULATED" ? "Not calculated" : String(summary.states?.complianceScore ?? "Not available");
    $("last-scan").textContent = summary.latestScan?.finishedAt ? formatDate(summary.latestScan.finishedAt) : "Not available";
    $("affected-accounts").textContent = typeof summary.accounts === "number" ? `${summary.accounts} monitored` : "Not available";
    $("freshness").textContent = summary.latestScan?.finishedAt ? `Updated ${formatDate(summary.latestScan.finishedAt)}` : "Freshness unavailable";
  };
  const renderMetrics = (summary) => {
    $("finding-count").textContent = typeof summary.findings?.open === "number" ? String(summary.findings.open) : "Not available";
    $("critical-count").textContent = typeof summary.findings?.critical === "number" ? `${summary.findings.critical} critical` : "Critical findings unavailable";
    $("account-count").textContent = typeof summary.accounts === "number" ? String(summary.accounts) : "Not available";
    $("account-context").textContent = summary.accounts ? "Active provider accounts" : "No verified account";
    $("control-count").textContent = typeof summary.controls?.evaluated === "number" ? String(summary.controls.evaluated) : "Not available";
    $("control-context").textContent = summary.controls?.evaluated ? `${summary.controls.pass} pass · ${summary.controls.fail} failed` : "No control evaluation";
    $("evidence-count").textContent = summary.latestEvidence ? (summary.latestEvidence.integrityStatus === "VALID" ? "Verified" : "Review") : "Not available";
    $("evidence-context").textContent = summary.latestEvidence ? `Collected ${formatDate(summary.latestEvidence.collectedAt)}` : "No evidence committed";
  };
  const renderScan = (scan) => {
    $("scan-detail").innerHTML = scan ? `<div class="scan-summary"><span class="scan-ring">${escapeHtml(scan.progress ?? "—")}${scan.progress !== undefined && scan.progress !== null ? "%" : ""}</span><div class="scan-copy"><strong>${escapeHtml(scan.status)}</strong><span>Scan ${escapeHtml(shortId(scan.id))} · created ${escapeHtml(formatDate(scan.createdAt))}</span></div><span class="panel-meta">${escapeHtml(formatDate(scan.finishedAt || scan.startedAt))}</span></div><div class="scan-progress" style="--progress:${Math.max(0, Math.min(100, Number(scan.progress) || 0))}%"><i></i></div><div class="scan-meta"><div>Resources<strong>${scan.totalResources ?? "Not available"}</strong></div><div>Checks<strong>${scan.totalChecks ?? "Not available"}</strong></div><div>Findings<strong>${scan.findingsCreated ?? "Not available"}</strong></div></div>` : empty("No scan yet", "Your environment has not been evaluated. Run the first scan after an AWS account is verified.");
  };
  const renderAccounts = (accounts) => {
    $("account-meta").textContent = accounts.length ? `${accounts.length} active` : "No data";
    $("accounts-list").innerHTML = accounts.length ? accounts.slice(0, 5).map((account) => `<button class="account-row" type="button" data-account-id="${escapeHtml(account.id)}"><span class="metric-icon info">◈</span><span class="account-copy"><strong>${escapeHtml(account.alias || account.awsAccountId)}</strong><span class="mono">${escapeHtml(account.awsAccountId)} · verified ${escapeHtml(formatDate(account.lastVerifiedAt))}</span></span><span class="status-badge ${account.status === "ACTIVE" ? "success" : "warning"}">${escapeHtml(account.status)}</span></button>`).join("") : empty("No AWS account", "Connect and verify an account to establish the security scope.");
  };
  const renderControls = (results) => {
    $("control-meta").textContent = results.length ? `${results.length} evaluated` : "No data";
    $("controls-list").innerHTML = results.length ? results.slice(0, 6).map((result) => `<div class="control-row" data-control-id="${escapeHtml(result.id)}"><span class="control-state ${statusClass(result.status)}">${escapeHtml(result.status)}</span><span class="control-copy"><button type="button"><strong>${escapeHtml(result.checkId)}</strong><span>${escapeHtml(result.message)}</span></button></span><span class="panel-meta">${escapeHtml(formatDate(result.observedAt))}</span></div>`).join("") : empty("No controls evaluated", "Control results will appear here after a backend scan completes.");
  };
  const renderFindings = (findings) => {
    $("findings-list").innerHTML = findings.length ? findings.slice(0, 6).map((finding) => `<div class="finding-row" data-finding-id="${escapeHtml(finding.id)}"><span class="severity ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span><span class="finding-copy"><button type="button"><strong>${escapeHtml(finding.title || finding.ruleId)}</strong><span>${escapeHtml(finding.ruleId)} · ${escapeHtml(finding.status)} · ${escapeHtml(finding.awsAccountId || "Account unavailable")}</span></button></span><span class="panel-meta">${escapeHtml(formatDate(finding.lastDetectedAt))}</span></div>`).join("") : empty("No findings returned", "No open or acknowledged findings are available in the backend preview.");
  };
  const renderEvidence = (evidence) => {
    $("evidence-detail").innerHTML = evidence ? `<button class="evidence-row" type="button" data-evidence-id="${escapeHtml(evidence.id)}"><span class="evidence-check">${evidence.integrityStatus === "VALID" ? "✓" : "!"}</span><span class="evidence-copy"><strong>${evidence.integrityStatus === "VALID" ? "Evidence verified" : "Integrity requires attention"}</strong><span>${escapeHtml(evidence.provider || "Provider unavailable")} · ${escapeHtml(formatDate(evidence.collectedAt))}</span></span><span class="panel-meta">${escapeHtml(shortId(evidence.contentHash))}</span></button>` : empty("No evidence yet", "Evidence will appear when a provider observation is committed.");
  };
  const render = (summary, findings) => {
    currentSummary = summary; currentFindings = findings;
     $("organization-label").textContent = summary.organizationId;
     $("top-organization").textContent = summary.organizationId;
    $("data-source").textContent = summary.source || "backend";
    $("last-refresh").textContent = `Refreshed ${formatDate(new Date().toISOString())}`;
    renderPosture(summary); renderMetrics(summary); renderRisk(summary); renderActions(summary);
    renderScan(summary.latestScan); renderAccounts(summary.accountList || []); renderControls(summary.latestControlResults || []);
    renderFindings(findings); renderEvidence(summary.latestEvidence);
    const canScan = Boolean((summary.accountList || []).length);
    $("scan-button").disabled = !canScan;
    $("scan-button").title = canScan ? "Queue a read-only security scan" : "Verify an AWS account before running a scan";
    $("scan-button").setAttribute("aria-label", canScan ? "Run a read-only security scan" : "Run scan unavailable until an AWS account is verified");
  };
  const load = async () => {
    try {
      const me = await api("/auth/me");
      if (!me.organization) { showNotice("Your session is authenticated but has no active organization.", true); return; }
      $("role-label").textContent = `${me.organization.role} · tenant-scoped`;
      $("avatar").textContent = (me.actor.email || me.actor.userId || "?").slice(0, 1).toUpperCase();
      $("user-label").textContent = me.actor.email || "Admin User";
      const data = await api("/dashboard/summary");
      let findings = [];
      try { const findingData = await api("/security/findings?status=OPEN&page=1&pageSize=6"); findings = findingData.findings || []; } catch { /* summary remains usable if preview permission is narrower */ }
      render(data.summary, findings);
      loginCard.classList.add("hidden"); dashboardContent.classList.remove("hidden");
      showNotice("Live backend data loaded. Unavailable capabilities remain explicitly uncalculated.", false);
    } catch (error) { showNotice(error.message || "Unable to load dashboard data. Retry.", true); }
  };
  const startScan = async () => {
    const account = currentSummary?.accountList?.[0];
    if (!account) { showNotice("No verified provider account is available for a scan.", true); return; }
    try {
      await api(`/security/accounts/${encodeURIComponent(account.id)}/scans`, { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": csrf() }, body: JSON.stringify({ idempotencyKey: `dashboard-${account.id}-${crypto.randomUUID()}` }) });
      showNotice("Read-only scan queued. Refresh to follow its backend status."); await load();
    } catch (error) { showNotice(error.message || "Unable to queue the scan.", true); }
  };
  const openEvidence = async (id) => {
    try {
      const evidence = (await api(`/evidence/${encodeURIComponent(id)}`)).evidence;
      showDetail("Evidence metadata", `<dl class="detail-list"><dt>Integrity</dt><dd>${escapeHtml(evidence.integrityStatus)}</dd><dt>Provider</dt><dd>${escapeHtml(evidence.provider)} · ${escapeHtml(evidence.schemaVersion)}</dd><dt>Collected</dt><dd>${escapeHtml(formatDate(evidence.collectedAt))}</dd><dt>Hash</dt><dd class="mono">${escapeHtml(evidence.contentHash)}</dd></dl>${evidence.integrityStatus !== "VALID" ? '<button class="button secondary" id="verify-detail-evidence" type="button">Verify integrity</button>' : ""}`);
      $("verify-detail-evidence")?.addEventListener("click", async () => { try { await api(`/evidence/${encodeURIComponent(id)}/verify`, { method: "POST", headers: { "x-csrf-token": csrf() } }); showNotice("Evidence integrity verified by the backend."); await load(); await openEvidence(id); } catch (error) { showNotice(error.message || "Unable to verify evidence.", true); } });
    } catch (error) { showNotice(error.message || "Unable to load evidence metadata.", true); }
  };
  const applyTheme = (mode) => {
    const resolved = mode === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : mode;
    document.documentElement.dataset.theme = resolved; localStorage.setItem("joben-theme-mode", mode); $("theme-button").title = `Theme: ${mode}`; $("theme-button").setAttribute("aria-label", `Change color theme (currently ${mode})`);
  };
  $("login-form").addEventListener("submit", async (event) => { event.preventDefault(); const identity = $("identity").value.trim(); try { await api("/auth/dev/session", { method: "POST", headers: { "x-dev-identity": identity, "x-dev-email": `${identity}@example.test` } }); await load(); } catch (error) { showNotice(error.message || "Unable to authenticate with the development adapter.", true); } });
  $("refresh-button").addEventListener("click", load); $("scan-button").addEventListener("click", startScan); $("analysis-link").addEventListener("click", () => $("controls").scrollIntoView({ behavior: "smooth" })); $("close-detail").addEventListener("click", hideDetail);
  $("actions-list").addEventListener("click", (event) => { const target = event.target.closest("[data-target]")?.dataset.target; if (target) document.getElementById(target)?.scrollIntoView({ behavior: "smooth" }); });
  document.addEventListener("click", (event) => {
    const control = event.target.closest("[data-control-id]"); if (control) { const result = currentSummary?.latestControlResults?.find((item) => item.id === control.dataset.controlId); if (result) showDetail(result.checkId, `<dl class="detail-list"><dt>Status</dt><dd>${escapeHtml(result.status)}</dd><dt>Why</dt><dd>${escapeHtml(result.message)}</dd><dt>Coverage</dt><dd>${escapeHtml(result.coverage)}</dd><dt>Observed</dt><dd>${escapeHtml(formatDate(result.observedAt))}</dd></dl>`); }
    const finding = event.target.closest("[data-finding-id]"); if (finding) { const record = currentFindings.find((item) => item.id === finding.dataset.findingId); if (record) showDetail(record.title || record.ruleId, `<dl class="detail-list"><dt>Severity</dt><dd>${escapeHtml(record.severity)}</dd><dt>Status</dt><dd>${escapeHtml(record.status)}</dd><dt>Control / rule</dt><dd class="mono">${escapeHtml(record.ruleId)}</dd><dt>Resource</dt><dd class="mono">${escapeHtml(record.resourceId)}</dd><dt>Recommendation</dt><dd>${escapeHtml(record.recommendation)}</dd></dl>`); }
    const evidence = event.target.closest("[data-evidence-id]"); if (evidence) void openEvidence(evidence.dataset.evidenceId);
    if (event.target.closest(".nav-item")) document.body.classList.remove("menu-open");
  });
  $("theme-button").addEventListener("click", () => { const current = localStorage.getItem("joben-theme-mode") || "dark"; applyTheme(current === "dark" ? "light" : current === "light" ? "system" : "dark"); });
  $("menu-button").addEventListener("click", () => { const open = document.body.classList.toggle("menu-open"); $("menu-button").setAttribute("aria-expanded", String(open)); });
  searchInput.addEventListener("input", () => { clearTimeout(searchTimer); const query = searchInput.value.trim(); if (query.length < 2) { searchResults.classList.add("hidden"); return; } searchTimer = setTimeout(async () => { try { const data = await api(`/search?q=${encodeURIComponent(query)}`); searchResults.innerHTML = data.results?.length ? data.results.map((result) => `<button type="button" class="search-result" role="option"><strong>${escapeHtml(result.label)}</strong><span>${escapeHtml(result.type)} · ${escapeHtml(result.detail)}</span></button>`).join("") : '<div class="search-empty">No matching backend records.</div>'; searchResults.classList.remove("hidden"); } catch (error) { showNotice(error.message || "Unable to search backend records.", true); } }, 220); });
  searchInput.addEventListener("keydown", (event) => { if (event.key === "Escape") { searchInput.value = ""; searchResults.classList.add("hidden"); } });
  document.addEventListener("keydown", (event) => { if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); searchInput.focus(); } });
  applyTheme(localStorage.getItem("joben-theme-mode") || "dark");
  void load();
})();