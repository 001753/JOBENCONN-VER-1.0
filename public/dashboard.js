(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const notice = $("notice");
  const loginCard = $("login-card");
  const dashboardContent = $("dashboard-content");
  const searchInput = $("global-search");
  const searchResults = $("search-results");
  let currentSummary = null;
  let searchTimer = null;
  const csrf = () => decodeURIComponent((document.cookie.match(/(?:^|;\s*)joben_csrf=([^;]+)/) || [])[1] || "");
  const showNotice = (message, error = false) => {
    notice.textContent = message;
    notice.className = `notice${error ? " error" : ""}`;
  };
  const statusClass = (status) => status === "PASS" ? "state-pass" : status === "FAIL" ? "state-fail" : status === "ERROR" ? "state-error" : "state-empty";
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  }[character]));
  const formatDate = (value) => value ? new Date(value).toLocaleString() : "Unavailable";
  const showDetail = (title, content) => {
    $("detail-title").textContent = title;
    $("detail-content").innerHTML = content;
    $("detail-panel").classList.remove("hidden");
    $("detail-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
  };
  const hideDetail = () => $("detail-panel").classList.add("hidden");
  const renderControls = (results) => {
    const list = $("controls-list");
    $("control-count").textContent = results.length ? `${results.length} evaluated` : "Not evaluated";
    if (!results.length) {
      list.innerHTML = '<div class="empty-state">No control has been evaluated for this organization yet.<br>Run a scan after an AWS account is verified.</div>';
      return;
    }
    list.innerHTML = results.map((result) => `<div class="control-row">
      <span class="control-state ${statusClass(result.status)}">${result.status}</span>
      <button class="control-name control-link" type="button" data-control-id="${escapeHtml(result.id)}"><strong>${escapeHtml(result.checkId)}</strong><span>${escapeHtml(result.message)}</span></button>
      <span class="panel-meta">${escapeHtml(formatDate(result.observedAt))}</span>
    </div>`).join("");
  };
  const renderAccounts = (accounts) => {
    $("account-meta").textContent = accounts.length ? `${accounts.length} active` : "No data";
    $("accounts-list").innerHTML = accounts.length
      ? accounts.map((account) => `<div class="account-row"><div class="account-copy"><strong>${escapeHtml(account.alias || account.awsAccountId)}</strong><span>${escapeHtml(account.awsAccountId)} · verified ${escapeHtml(formatDate(account.lastVerifiedAt))}</span></div><span class="control-state state-pass">${escapeHtml(account.status)}</span></div>`).join("")
      : '<div class="empty-state">No verified provider account is available yet.</div>';
  };
  const render = (summary) => {
    currentSummary = summary;
    const posture = summary.states.posture;
    $("organization-label").textContent = summary.organizationId;
    $("posture-value").textContent = posture === "ACTION_REQUIRED" ? "Action required" : posture === "INSUFFICIENT_EVIDENCE" ? "Insufficient evidence" : posture === "OBSERVED" ? "Observed" : "Awaiting scan";
    $("posture-detail").textContent = posture === "ACTION_REQUIRED" ? `${summary.controls.fail} control failure(s) require review.` : posture === "INSUFFICIENT_EVIDENCE" ? `${summary.controls.error} control result(s) lack verified evidence.` : posture === "OBSERVED" ? "Current control results are backed by the provider evidence path." : "No control evaluation is available yet.";
    $("finding-count").textContent = summary.findings.open;
    $("critical-count").textContent = summary.findings.critical;
    $("account-count").textContent = summary.accounts;
    $("freshness").textContent = summary.latestScan?.finishedAt ? `Source: backend · last scanned ${formatDate(summary.latestScan.finishedAt)}` : "Source: backend · freshness unavailable";
    $("scan-status").textContent = summary.latestScan?.status || "Awaiting scan";
    $("scan-detail").innerHTML = summary.latestScan ? `<div class="evidence-row"><div class="evidence-copy"><strong>${escapeHtml(summary.latestScan.status)}</strong><span>Scan ${escapeHtml(summary.latestScan.id)} · ${escapeHtml(formatDate(summary.latestScan.createdAt))}</span></div><span class="panel-meta">${escapeHtml(summary.latestScan.correlationId)}</span></div>` : '<div class="empty-state">No scan has been requested for this organization.</div>';
    $("evidence-detail").innerHTML = summary.latestEvidence ? `<button class="evidence-check evidence-link" type="button" data-evidence-id="${escapeHtml(summary.latestEvidence.id)}" aria-label="Open latest evidence">✓</button><div class="evidence-copy"><strong>${summary.latestEvidence.integrityStatus === "VALID" ? "Integrity verified" : "Integrity requires attention"}</strong><span>Hash ${escapeHtml(summary.latestEvidence.contentHash.slice(0, 16))}… · observed ${escapeHtml(formatDate(summary.latestEvidence.collectedAt))}</span></div>` : '<div class="empty-state">No evidence has been committed yet.</div>';
    renderControls(summary.latestControlResults);
    renderAccounts(summary.accountList || []);
    $("scan-button").disabled = !(summary.accountList || []).length;
  };
  const api = async (path, options = {}) => {
    const response = await fetch(path, { credentials: "same-origin", ...options });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error?.message || `Request failed (${response.status})`);
    return payload;
  };
  const startScan = async () => {
    const account = currentSummary?.accountList?.[0];
    if (!account) {
      showNotice("No verified provider account is available for a scan.", true);
      return;
    }
    const idempotencyKey = `dashboard-${account.id}-${crypto.randomUUID()}`;
    try {
      await api(`/security/accounts/${encodeURIComponent(account.id)}/scans`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-csrf-token": csrf() },
        body: JSON.stringify({ idempotencyKey })
      });
      showNotice("Read-only scan queued. Refresh to follow its backend status.");
      await load();
    } catch (error) {
      showNotice(error.message || "Unable to queue the scan.", true);
    }
  };
  const openEvidence = async (evidenceId) => {
    try {
      const data = await api(`/evidence/${encodeURIComponent(evidenceId)}`);
      const evidence = data.evidence;
      showDetail("Evidence metadata", `<dl class="detail-list">
        <dt>Integrity</dt><dd>${escapeHtml(evidence.integrityStatus)}</dd>
        <dt>Provider</dt><dd>${escapeHtml(evidence.provider)} · ${escapeHtml(evidence.schemaVersion)}</dd>
        <dt>Collected</dt><dd>${escapeHtml(formatDate(evidence.collectedAt))}</dd>
        <dt>Hash</dt><dd class="mono">${escapeHtml(evidence.contentHash)}</dd>
      </dl><button class="button secondary" id="verify-detail-evidence" type="button">Verify integrity</button>`);
      $("verify-detail-evidence").addEventListener("click", async () => {
        try {
          await api(`/evidence/${encodeURIComponent(evidenceId)}/verify`, { method: "POST", headers: { "x-csrf-token": csrf() } });
          showNotice("Evidence integrity verified by the backend.");
          await load();
          await openEvidence(evidenceId);
        } catch (error) { showNotice(error.message || "Unable to verify evidence.", true); }
      });
    } catch (error) {
      showNotice(error.message || "Unable to load evidence metadata.", true);
    }
  };
  const load = async () => {
    try {
      const me = await api("/auth/me");
      if (!me.organization) {
        showNotice("Your session is authenticated but has no active organization.", true);
        return;
      }
      $("role-label").textContent = `${me.organization.role} · tenant-scoped`;
      $("avatar").textContent = (me.actor.email || me.actor.userId || "?").slice(0, 1).toUpperCase();
      const data = await api("/dashboard/summary");
      render(data.summary);
      loginCard.classList.add("hidden");
      dashboardContent.classList.remove("hidden");
      showNotice("Live backend data loaded. Metrics remain unavailable until the underlying capability produces them.");
    } catch (error) {
      showNotice(error.message || "Unable to load dashboard data. Retry.", true);
    }
  };
  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const identity = $("identity").value.trim();
    try {
      await api("/auth/dev/session", { method: "POST", headers: { "x-dev-identity": identity, "x-dev-email": `${identity}@example.test` } });
      await load();
    } catch (error) { showNotice(error.message || "Unable to authenticate with the development adapter.", true); }
  });
  $("refresh-button").addEventListener("click", load);
  $("scan-button").addEventListener("click", startScan);
  $("run-scan-action").addEventListener("click", startScan);
  $("view-controls-action").addEventListener("click", () => $("controls").scrollIntoView({ behavior: "smooth" }));
  $("verify-evidence-action").addEventListener("click", () => {
    if (currentSummary?.latestEvidence?.id) void openEvidence(currentSummary.latestEvidence.id);
    else showNotice("No evidence is available to verify yet.", true);
  });
  $("close-detail").addEventListener("click", hideDetail);
  document.addEventListener("click", (event) => {
    const control = event.target.closest("[data-control-id]");
    if (control) {
      const result = currentSummary?.latestControlResults?.find((item) => item.id === control.dataset.controlId);
      if (result) showDetail(result.checkId, `<dl class="detail-list">
        <dt>Status</dt><dd>${escapeHtml(result.status)}</dd>
        <dt>Why</dt><dd>${escapeHtml(result.message)}</dd>
        <dt>Coverage</dt><dd>${escapeHtml(result.coverage)}</dd>
        <dt>Freshness</dt><dd>${escapeHtml(formatDate(result.observedAt))}</dd>
      </dl>${result.evidenceId ? `<button class="button secondary evidence-action" type="button" data-evidence-id="${escapeHtml(result.evidenceId)}">Open verified evidence</button>` : "<p class=\"muted\">Insufficient evidence is available for this result.</p>"}`);
    }
    const evidence = event.target.closest("[data-evidence-id]");
    if (evidence && !event.target.closest("#verify-detail-evidence")) void openEvidence(evidence.dataset.evidenceId);
  });
  $("theme-button").addEventListener("click", () => {
    document.documentElement.dataset.theme = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  });
  $("density-button").addEventListener("click", () => document.body.classList.toggle("compact"));
  $("menu-button").addEventListener("click", () => document.body.classList.toggle("menu-open"));
  searchInput.addEventListener("input", () => {
    clearTimeout(searchTimer);
    const query = searchInput.value.trim();
    if (query.length < 2) { searchResults.classList.add("hidden"); return; }
    searchTimer = setTimeout(async () => {
      try {
        const data = await api(`/search?q=${encodeURIComponent(query)}`);
        searchResults.innerHTML = data.results.length
          ? data.results.map((result) => `<button type="button" class="search-result" role="option"><strong>${escapeHtml(result.label)}</strong><span>${escapeHtml(result.type)} · ${escapeHtml(result.detail)}</span></button>`).join("")
          : '<div class="search-empty">No matching backend records.</div>';
        searchResults.classList.remove("hidden");
      } catch (error) { showNotice(error.message || "Unable to search backend records.", true); }
    }, 220);
  });
  searchInput.addEventListener("keydown", (event) => {
    if (event.key === "Escape") { searchInput.value = ""; searchResults.classList.add("hidden"); }
  });
  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); searchInput.focus(); }
  });
  void load();
})();