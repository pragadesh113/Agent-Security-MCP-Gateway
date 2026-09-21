"use strict";

const apiRoot = "/approval/api";
const refreshIntervalMs = 5000;
const csrfStorageKey = "agent-security.approval.csrf.v1";
const state = {
  approvals: [],
  selectedId: null,
  detail: null,
  detailEtag: null,
  csrfToken: null,
  pendingDecision: null,
  refreshTimer: null,
  countdownTimer: null
};

const byId = (id) => document.getElementById(id);

function announce(message) {
  byId("live-status").textContent = "";
  window.requestAnimationFrame(() => { byId("live-status").textContent = message; });
}

function showAlert(targetId, message) {
  const target = byId(targetId);
  target.textContent = message;
  target.hidden = false;
}

function clearAlert(targetId) {
  const target = byId(targetId);
  target.textContent = "";
  target.hidden = true;
}

function text(value, fallback = "Not available") {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function array(value) {
  return Array.isArray(value) ? value : [];
}

async function requestJson(path, options = {}) {
  const response = await fetch(`${apiRoot}${path}`, {
    cache: "no-store",
    credentials: "same-origin",
    ...options,
    headers: { Accept: "application/json", ...(options.headers || {}) }
  });
  let payload = null;
  try { payload = await response.json(); } catch { /* Safe generic error below. */ }
  if (!response.ok) {
    const error = new Error(text(payload?.error?.message || payload?.message,
      "The protected approval service is unavailable."));
    error.status = response.status;
    throw error;
  }
  return { payload, response };
}

function addFact(list, label, value, options = {}) {
  const wrapper = document.createElement("div");
  wrapper.className = "fact";
  const term = document.createElement("dt");
  term.textContent = label;
  const description = document.createElement("dd");
  description.textContent = text(value);
  if (options.mono) description.classList.add("mono");
  wrapper.append(term, description);
  list.append(wrapper);
}

function replaceFacts(id, facts) {
  const list = byId(id);
  list.replaceChildren();
  for (const fact of facts) addFact(list, fact[0], fact[1], fact[2]);
}

function formatTime(value) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Not available" : parsed.toLocaleString();
}

function humanize(value) {
  return text(value).replaceAll("_", " ").toLowerCase().replace(/^./, (character) => character.toUpperCase());
}

function currentApproval(detail) {
  return detail?.approval || {};
}

function currentView(detail) {
  return detail?.view || {};
}

async function loadSession() {
  const storedCsrfToken = window.localStorage.getItem(csrfStorageKey);
  let payload;
  if (storedCsrfToken) {
    try {
      ({ payload } = await requestJson("/session", {
        headers: { "X-CSRF-Token": storedCsrfToken }
      }));
      state.csrfToken = storedCsrfToken;
    } catch (error) {
      if (error.status !== 401 && error.status !== 403) throw error;
      window.localStorage.removeItem(csrfStorageKey);
    }
  }
  if (!state.csrfToken) {
    ({ payload } = await requestJson("/session", { method: "POST" }));
    state.csrfToken = typeof payload?.csrfToken === "string" ? payload.csrfToken : null;
    if (state.csrfToken) window.localStorage.setItem(csrfStorageKey, state.csrfToken);
  }
  const human = payload?.human || payload?.operator || {};
  byId("operator-name").textContent = text(human.displayName || human.humanId || payload?.humanId, "Authenticated operator");
  byId("session-state").textContent = "Protected session active";
}

function renderQueue() {
  const list = byId("approval-list");
  list.replaceChildren();
  const approvals = state.approvals;
  byId("queue-summary").textContent = `${approvals.length} pending ${approvals.length === 1 ? "request" : "requests"}`;
  byId("empty-state").hidden = approvals.length !== 0;

  for (const item of approvals) {
    const approvalId = text(item.approvalId, "Unknown approval");
    const entry = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "queue-item";
    button.dataset.approvalId = approvalId;
    button.setAttribute("aria-current", state.selectedId === approvalId ? "true" : "false");

    const title = document.createElement("strong");
    title.textContent = text(item.summary || item.toolName || item.actionEffect, "Canonical action");
    const target = document.createElement("span");
    target.textContent = text(item.target || item.canonicalReference, approvalId);
    const meta = document.createElement("span");
    meta.className = "queue-meta";
    meta.textContent = `Expires ${formatTime(item.expiresAt)}`;
    button.append(title, target, meta);
    button.addEventListener("click", () => selectApproval(approvalId, true));
    entry.append(button);
    list.append(entry);
  }
}

async function loadQueue({ announceUpdate = false } = {}) {
  const { payload } = await requestJson("/pending");
  state.approvals = array(payload?.approvals);
  renderQueue();
  if (announceUpdate) announce(`Approval queue refreshed. ${state.approvals.length} pending.`);
  if (state.selectedId && !state.approvals.some((item) => item.approvalId === state.selectedId)) {
    await selectApproval(state.selectedId, false);
  }
}

function renderTargets(view) {
  const container = byId("target-list");
  container.replaceChildren();
  const targets = array(view.targets);
  if (targets.length === 0) {
    const missing = document.createElement("p");
    missing.className = "muted";
    missing.textContent = "No authorized target data was returned.";
    container.append(missing);
    return;
  }
  for (const target of targets) {
    const card = document.createElement("div");
    card.className = "target-card";
    const heading = document.createElement("strong");
    heading.textContent = text(target.resourceClass, "Target");
    const reference = document.createElement("span");
    reference.className = "mono";
    reference.textContent = text(target.canonicalReference);
    const classification = document.createElement("span");
    classification.className = "muted";
    classification.textContent = `Classification: ${text(target.classification)}`;
    card.append(heading, reference, classification);
    container.append(card);
  }
}

function renderList(id, values, emptyMessage) {
  const list = byId(id);
  list.replaceChildren();
  const items = array(values);
  if (items.length === 0) {
    const entry = document.createElement("li");
    entry.textContent = emptyMessage;
    entry.className = "muted";
    list.append(entry);
    return;
  }
  for (const value of items) {
    const entry = document.createElement("li");
    entry.textContent = text(value);
    list.append(entry);
  }
}

function renderAudit(detail) {
  const list = byId("audit-list");
  list.replaceChildren();
  const events = array(detail.audit || detail.events);
  if (events.length === 0) {
    const entry = document.createElement("li");
    entry.className = "muted";
    entry.textContent = "No scope-authorized audit events are available.";
    list.append(entry);
    return;
  }
  for (const event of events) {
    const entry = document.createElement("li");
    const name = document.createElement("strong");
    name.textContent = humanize(event.eventType || event.type);
    const time = document.createElement("time");
    time.dateTime = text(event.occurredAt, "");
    time.textContent = formatTime(event.occurredAt);
    const reasons = document.createElement("span");
    reasons.textContent = array(event.reasonCodes).length
      ? `Reasons: ${event.reasonCodes.join(", ")}`
      : "No additional reason code";
    entry.append(name, time, reasons);
    list.append(entry);
  }
}

function updateCountdown() {
  const expiresAt = currentApproval(state.detail).expiresAt;
  const remaining = Date.parse(expiresAt) - Date.now();
  const target = byId("expiry-countdown");
  if (!Number.isFinite(remaining)) {
    target.textContent = "Expiry unavailable";
    return;
  }
  if (remaining <= 0) {
    target.textContent = "Expired";
    setDecisionAvailability(false);
    return;
  }
  const seconds = Math.ceil(remaining / 1000);
  const minutes = Math.floor(seconds / 60);
  target.textContent = `${minutes}:${String(seconds % 60).padStart(2, "0")} remaining`;
}

function setDecisionAvailability(enabled) {
  byId("approve-button").disabled = !enabled;
  byId("deny-button").disabled = !enabled;
  byId("decision-actions").hidden = !enabled;
}

function renderDetail() {
  const detail = state.detail;
  const approval = currentApproval(detail);
  const view = currentView(detail);
  const route = view.route || {};
  const requester = view.requester || {};
  const flow = view.dataFlow || {};
  const provenance = view.provenance || {};
  const outcome = detail?.outcome || null;
  const result = detail?.result || null;
  const recovery = detail?.recovery || null;

  byId("detail-placeholder").hidden = true;
  byId("detail-content").hidden = false;
  byId("action-title").textContent = `${humanize(view.actionEffect)} via ${text(route.toolName, "unknown tool")}`;
  byId("action-identifier").textContent = text(approval.approvalId || state.selectedId);
  const stateBadge = byId("approval-state");
  stateBadge.textContent = humanize(approval.state);
  stateBadge.dataset.state = text(approval.state, "UNKNOWN");
  byId("expiry-time").textContent = `Expires ${formatTime(approval.expiresAt)}`;

  replaceFacts("requester-fields", [
    ["User", requester.userId, { mono: true }], ["Agent", requester.agentId, { mono: true }],
    ["Client", requester.clientId, { mono: true }], ["Host", requester.hostId, { mono: true }],
    ["Session", requester.sessionId, { mono: true }]
  ]);
  replaceFacts("route-fields", [
    ["Decision", humanize(view.decision)], ["Risk tier", Number.isInteger(view.riskTier) ? `Tier ${view.riskTier}` : null],
    ["Effect", humanize(view.actionEffect)], ["Reversibility", humanize(view.reversibility)],
    ["Blast radius", humanize(view.blastRadius)], ["Server", route.serverId, { mono: true }],
    ["Tool", route.toolName, { mono: true }], ["Route", route.routeId, { mono: true }],
    ["Policy scope", route.policyScopeId, { mono: true }], ["Schema digest", route.schemaDigest, { mono: true }]
  ]);
  renderTargets(view);
  replaceFacts("flow-fields", [
    ["Direction", humanize(flow.direction)], ["External destination", flow.externalDestination === true ? "Yes" : "No"],
    ["Destination", flow.destinationId], ["Data classifications", array(flow.classifications).join(", ")],
    ["Parser", `${text(provenance.parserId)} ${text(provenance.parserVersion, "")}`.trim()],
    ["Parsing status", humanize(provenance.parsingStatus)],
    ["Untrusted influences", array(provenance.influences).map(humanize).join(", ") || "None recorded"]
  ]);
  byId("coverage-summary").textContent = `${humanize(view.coverage)} coverage · evidence ${text(view.coverageEvidenceDigest)}`;
  renderList("missing-guarantees", view.missingGuarantees, "No missing guarantees are recorded for this scope.");
  renderList("related-attempts", view.relatedAttemptIds, "No related attempts are recorded.");
  replaceFacts("outcome-fields", [
    ["Status", outcome ? humanize(outcome.status) : "Pending"],
    ["Possible partial effects", outcome?.possiblePartialEffects === true || view.possiblePartialEffects === true ? "Yes" : "No"],
    ["Recovery class", humanize(outcome?.recoveryClass || recovery?.recoveryClass || view.recoveryClass)],
    ["Result disposition", result ? humanize(result.disposition) : "No governed result"],
    ["Result schema", result ? humanize(result.schemaValidation) : "Not applicable"],
    ["Observed", outcome?.observedAt ? formatTime(outcome.observedAt) : "Not yet observed"]
  ]);
  renderAudit(detail);
  setDecisionAvailability(approval.state === "PENDING" && Date.parse(approval.expiresAt) > Date.now());
  updateCountdown();
}

async function selectApproval(approvalId, moveFocus) {
  if (moveFocus) clearAlert("decision-alert");
  state.selectedId = approvalId;
  if (moveFocus) {
    const location = new URL(window.location.href);
    location.searchParams.set("approval", approvalId);
    window.history.replaceState(null, "", location);
  }
  renderQueue();
  try {
    const { payload, response } = await requestJson(`/approvals/${encodeURIComponent(approvalId)}`);
    state.detail = payload;
    state.detailEtag = response.headers.get("etag") || payload?.etag || null;
    renderDetail();
    if (moveFocus) byId("approval-detail").focus();
    announce(`Loaded approval ${approvalId}.`);
  } catch (error) {
    state.detail = null;
    showAlert("global-alert", error.message);
    announce("Approval details could not be loaded.");
  }
}

function openConfirmation(decision) {
  if (!state.detail || currentApproval(state.detail).state !== "PENDING") return;
  state.pendingDecision = decision;
  const approving = decision === "APPROVE";
  const view = currentView(state.detail);
  const firstTarget = array(view.targets)[0];
  byId("confirmation-title").textContent = approving ? "Approve this action once?" : "Deny this action?";
  byId("confirmation-description").textContent = approving
    ? "This permits one exact downstream attempt only. Changes require a new approval."
    : "This prevents this approval request from being used.";
  replaceFacts("confirmation-facts", [
    ["Effect", humanize(view.actionEffect)],
    ["Tool", view.route?.toolName, { mono: true }],
    ["Target", firstTarget?.canonicalReference, { mono: true }],
    ["Coverage", humanize(view.coverage)]
  ]);
  const confirm = byId("confirm-decision-button");
  confirm.textContent = approving ? "Approve once" : "Deny";
  confirm.className = `button ${approving ? "button-primary" : "button-danger"}`;
  byId("confirmation-dialog").showModal();
}

async function submitDecision(decision) {
  const approval = currentApproval(state.detail);
  if (!approval.approvalId || !state.csrfToken || !state.detailEtag) {
    showAlert("decision-alert", "Decision protection data is unavailable. Reload the approval before deciding.");
    return;
  }
  setDecisionAvailability(false);
  clearAlert("decision-alert");
  try {
    await requestJson(`/approvals/${encodeURIComponent(approval.approvalId)}/decision`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "If-Match": state.detailEtag,
        "X-CSRF-Token": state.csrfToken
      },
      body: JSON.stringify({ schemaVersion: "1.0.0", decision })
    });
    announce(decision === "APPROVE" ? "Approval recorded for one exact action." : "Denial recorded.");
    await Promise.all([loadQueue(), selectApproval(approval.approvalId, true)]);
  } catch (error) {
    showAlert("decision-alert", error.status === 409
      ? "This request changed or was already decided. The current durable state has been reloaded."
      : error.message);
    announce("The decision was not recorded.");
    await selectApproval(approval.approvalId, false).catch(() => undefined);
  }
}

function scheduleRefresh() {
  window.clearInterval(state.refreshTimer);
  state.refreshTimer = window.setInterval(async () => {
    try {
      await loadQueue();
      if (state.selectedId) await selectApproval(state.selectedId, false);
      clearAlert("global-alert");
    } catch {
      showAlert("global-alert", "Live approval data is temporarily unavailable. Do not infer approval or execution.");
    }
  }, refreshIntervalMs);
  window.clearInterval(state.countdownTimer);
  state.countdownTimer = window.setInterval(updateCountdown, 1000);
}

byId("refresh-button").addEventListener("click", async () => {
  clearAlert("global-alert");
  try {
    await loadQueue({ announceUpdate: true });
    if (state.selectedId) await selectApproval(state.selectedId, false);
  } catch (error) { showAlert("global-alert", error.message); }
});
byId("approve-button").addEventListener("click", () => openConfirmation("APPROVE"));
byId("deny-button").addEventListener("click", () => openConfirmation("DENY"));
byId("confirmation-dialog").addEventListener("close", () => { state.pendingDecision = null; });
byId("confirmation-dialog").addEventListener("submit", (event) => {
  const submitter = event.submitter;
  if (submitter?.value === "confirm" && state.pendingDecision) {
    const decision = state.pendingDecision;
    window.setTimeout(() => submitDecision(decision), 0);
  }
});

window.addEventListener("storage", (event) => {
  if (event.key === csrfStorageKey && typeof event.newValue === "string" && event.newValue) {
    state.csrfToken = event.newValue;
  }
});

(async function start() {
  try {
    await loadSession();
    await loadQueue();
    const requestedApprovalId = new URL(window.location.href).searchParams.get("approval");
    if (requestedApprovalId && requestedApprovalId.length <= 128) {
      await selectApproval(requestedApprovalId, false);
    }
    clearAlert("global-alert");
    scheduleRefresh();
  } catch (error) {
    byId("session-state").textContent = "Protected session unavailable";
    showAlert("global-alert", error.message);
    announce("The protected approval interface could not start.");
  }
}());
