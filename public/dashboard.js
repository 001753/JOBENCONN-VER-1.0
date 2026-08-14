(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const notice = $("notice");
  const loginCard = $("login-card");
  const dashboardContent = $("dashboard-content");
  const csrf = () => decodeURIComponent((document.cookie.match(/(?:^|;\s*)joben_csrf=([^;]+)/) || [])[1] || "");
  const showNotice = (message, error = false) => {
    notice.textContent = message;
    notice.className = `notice${error ? " error" : ""}`;
  };
  const statusClass = (status) => status === "PASS" ? "state-pass" : status === "FAIL" ? "state-fail" : status === "ERROR" ? "state-error" : "state-empty";
  const renderControls = (results) => {
    const list = $("controls-list");
    $("control-count").textContent = results.length ? `${results.length} evaluated` : "Not evaluated";
    if (!results.length) {
      list.innerHTML = '<div class="empty-state">No control has been evaluated for this organization yet.<br>Run a scan after an AWS account is verified.</div>';
      return;
    }
    list.innerHTML = results.map((result) => `<div class="control-row">
      <span class="control-state ${statusClass(result.status)}">${result.status}</span>
      <div class="control-name"><strong>${result.checkId}</strong><span>${result.message}</span></div>
      <span class="panel-meta">${new Date(result.observedAt).toLocaleDateString()}</span>
    </div>`).join("");
  };
  const render = (summary) => {
    const posture = summary.states.posture;
    $("organization-label").textContent = summary.organizationId;
    $("posture-value").textContent = posture === "ACTION_REQUIRED" ? "Action required" : posture === "INSUFFICIENT_EVIDENCE" ? "Insufficient evidence" : posture === "OBSERVED" ? "Observed" : "Awaiting scan";
    $("posture-detail").textContent = posture === "ACTION_REQUIRED" ? `${summary.controls.fail} control failure(s) require review.` : posture === "INSUFFICIENT_EVIDENCE" ? `${summary.controls.error} control result(s) lack verified evidence.` : posture === "OBSERVED" ? "Current control results are backed by the provider evidence path." : "No control evaluation is available yet.";
    $("finding-count").textContent = summary.findings.open;
    $("critical-count").textContent = summary.findings.critical;
    $("account-count").textContent = summary.accounts;
    $("freshness").textContent = summary.latestScan?.finishedAt ? `Source: backend · last scanned ${new Date(summary.latestScan.finishedAt).toLocaleString()}` : "Source: backend · freshness unavailable";
    $("scan-status").textContent = summary.latestScan?.status || "Awaiting scan";
    $("scan-detail").innerHTML = summary.latestScan ? `<div class="evidence-row"><div class="evidence-copy"><strong>${summary.latestScan.status}</strong><span>Scan ${summary.latestScan.id} · ${new Date(summary.latestScan.createdAt).toLocaleString()}</span></div><span class="panel-meta">${summary.latestScan.correlationId}</span></div>` : '<div class="empty-state">No scan has been requested for this organization.</div>';
    $("evidence-detail").innerHTML = summary.latestEvidence ? `<div class="evidence-check">✓</div><div class="evidence-copy"><strong>${summary.latestEvidence.integrityStatus === "VALID" ? "Integrity verified" : "Integrity requires attention"}</strong><span>Hash ${summary.latestEvidence.contentHash.slice(0, 16)}… · observed ${new Date(summary.latestEvidence.collectedAt).toLocaleString()}</span></div>` : '<div class="empty-state">No evidence has been committed yet.</div>';
    renderControls(summary.latestControlResults);
  };
  const api = async (path, options = {}) => {
    const response = await fetch(path, { credentials: "same-origin", ...options });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error?.message || `Request failed (${response.status})`);
    return payload;
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
      $("scan-button").disabled = true;
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
  $("theme-button").addEventListener("click", () => {
    document.documentElement.dataset.theme = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  });
  $("density-button").addEventListener("click", () => document.body.classList.toggle("compact"));
  $("menu-button").addEventListener("click", () => document.body.classList.toggle("menu-open"));
  $("global-search").addEventListener("keydown", (event) => { if (event.key === "Escape") event.currentTarget.value = ""; });
  void load();
})();