const fs = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");

const { loadDotEnv } = require("../../../packages/shared/src/load-env");
const { SAFE_API_CHAIN_SLUGS } = require("../../../packages/integrations/src/safe-client");
const { runIncidentPipeline } = require("../../orchestrator/src/pipeline");
const { resolveInvestigatorConfig } = require("../../../packages/ai/src/investigator");
const {
  resolveSeedConfig,
  seedSuspiciousApproval,
} = require("../../../scripts/seed-demo-incident");
const {
  readReceiptMirror,
  resolveReceiptStorageConfig,
} = require("../../../packages/storage-0g/src/client");

loadDotEnv({ override: true });

function refreshRuntimeEnv() {
  loadDotEnv({ override: true });
  return process.env;
}

// ---------------------------------------------------------------------------
// MonitorService — manages per-Safe polling loops
// ---------------------------------------------------------------------------

const POLL_INTERVAL_MS = 30_000;
const INCIDENT_REUSE_WINDOW_MS = 5 * 60_000;
const WATCHLIST_FILENAME = "watchlist.json";
const MONITOR_STATE_FILENAME = "monitor-state.json";
const INCIDENT_HISTORY_FILENAME = "incident-history.json";
const EXECUTION_FINAL_STATUSES = new Set([
  "executed",
  "already_executed",
  "proposed_and_confirmed",
  "proposed_waiting_for_confirmations",
  "prepared",
  "blocked_by_peer_review",
]);
const EXECUTABLE_STEP_KINDS = new Set([
  "invalidate_pending_approval",
  "invalidate_pending_transaction",
  "revoke_approval",
]);

function clonePlainData(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function toPositiveNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function buildIncidentStateMap(incidents = []) {
  return new Map(
    incidents
      .filter((entry) => entry?.incident?.incidentId)
      .map((entry) => [entry.incident.incidentId, clonePlainData(entry)]),
  );
}

function rankSeverity(severity) {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

class MonitorService {
  constructor(options = {}) {
    this._safes = new Map();
    this._artifactDir =
      options.artifactDir ?? process.env.BREAKGLASS_ARTIFACT_DIR ?? "artifacts";
    this._pollIntervalMs = toPositiveNumber(
      options.pollIntervalMs ?? process.env.BREAKGLASS_MONITOR_POLL_MS,
      POLL_INTERVAL_MS,
    );
    this._incidentReuseWindowMs = toPositiveNumber(
      options.incidentReuseWindowMs ??
        process.env.BREAKGLASS_MONITOR_INCIDENT_REUSE_MS,
      INCIDENT_REUSE_WINDOW_MS,
    );
    this._runIncidentPipeline = options.runIncidentPipeline ?? runIncidentPipeline;
    this._now = options.now ?? (() => new Date());
    this._snapshotBySafe = new Map();
    this._historyByIncidentId = new Map();
    this._autoStartPolling = options.autoStartPolling !== false;
  }

  get safes() {
    return Array.from(this._safes.values());
  }

  get artifactDir() {
    return this._artifactDir;
  }

  get incidents() {
    const all = [];
    for (const state of this._safes.values()) {
      for (const inc of state.incidents ?? []) {
        all.push(inc);
      }
    }
    return all.sort((left, right) => {
      const severityDiff =
        rankSeverity(right.incident?.severity) - rankSeverity(left.incident?.severity);

      if (severityDiff !== 0) {
        return severityDiff;
      }

      return Date.parse(right.monitor?.lastSeenAt ?? 0) -
        Date.parse(left.monitor?.lastSeenAt ?? 0);
    });
  }

  get history() {
    return Array.from(this._historyByIncidentId.values()).sort((left, right) => {
      return Date.parse(right.history?.updatedAt ?? 0) - Date.parse(left.history?.updatedAt ?? 0);
    });
  }

  async load() {
    await this._loadSnapshots();
    await this._loadHistory();

    try {
      const p = path.join(this._artifactDir, WATCHLIST_FILENAME);
      const raw = await fs.readFile(p, "utf8");
      const list = JSON.parse(raw);
      for (const entry of list) {
        const normalized = entry.address?.trim().toLowerCase();
        await this.addSafe(
          entry.address,
          entry.network,
          false,
          this._snapshotBySafe.get(normalized) ?? null,
        );
      }
    } catch {
      // no watchlist yet — fine
    }
  }

  async addSafe(address, network, persist = true, snapshot = null) {
    const normalized = address.trim().toLowerCase();
    if (this._safes.has(normalized)) return { ok: false, reason: "already_monitored" };

    const chain = SAFE_API_CHAIN_SLUGS[network] ?? network;
    const restoredIncidents = clonePlainData(snapshot?.incidents ?? []);
    const state = {
      address: normalized,
      network,
      chain,
      status: snapshot?.status ?? "monitoring",
      incidents: restoredIncidents,
      lastChecked: snapshot?.lastChecked ?? null,
      transactionsScanned: snapshot?.transactionsScanned ?? 0,
      error: snapshot?.error ?? null,
      addedAt: snapshot?.addedAt ?? this._now().toISOString(),
      lastResolvedAt: snapshot?.lastResolvedAt ?? null,
      _incidentResultsById: buildIncidentStateMap(restoredIncidents),
      _pollPromise: null,
    };

    this._safes.set(normalized, state);

    if (this._autoStartPolling) {
      this._poll(normalized).catch(() => {});
      state._intervalId = setInterval(() => {
        this._poll(normalized).catch(() => {});
      }, this._pollIntervalMs);
    }

    if (persist) {
      await this._saveWatchlist();
      await this._saveSnapshot();
    }
    return { ok: true };
  }

  async removeSafe(address) {
    const normalized = address.trim().toLowerCase();
    const state = this._safes.get(normalized);
    if (!state) return { ok: false, reason: "not_found" };
    if (state._intervalId) clearInterval(state._intervalId);
    this._safes.delete(normalized);
    await this._saveWatchlist();
    await this._saveSnapshot();
    return { ok: true };
  }

  async forcePoll(address) {
    const normalized = address.trim().toLowerCase();
    if (!this._safes.has(normalized)) return { ok: false, reason: "not_found" };
    await this._poll(normalized, {
      refreshKnownIncidents: true,
    });
    return { ok: true };
  }

  findIncident(incidentId) {
    return this.incidents.find((entry) => entry.incident?.incidentId === incidentId) ?? null;
  }

  async recordContainmentResult(incidentId, executionArtifact) {
    const now = this._now().toISOString();

    for (const state of this._safes.values()) {
      const index = state.incidents.findIndex(
        (entry) => entry.incident?.incidentId === incidentId,
      );

      if (index === -1) {
        continue;
      }

      const previous = state.incidents[index];
      const updated = {
        ...previous,
        execution: clonePlainData(executionArtifact),
        monitor: {
          ...(previous.monitor ?? {}),
          lastContainmentAt: now,
          lastContainmentStatus: executionArtifact?.status ?? "unknown",
          containmentAttempts: (previous.monitor?.containmentAttempts ?? 0) + 1,
          actionState: "completed",
        },
      };

      state.incidents[index] = updated;
      state._incidentResultsById.set(incidentId, clonePlainData(updated));
      this._upsertHistoryEntry(updated, "active");
      await this._saveSnapshot();
      await this._saveHistory();

      return updated;
    }

    return null;
  }

  async _poll(address, options = {}) {
    const state = this._safes.get(address);
    if (!state) return;

    if (state._pollPromise) {
      return state._pollPromise;
    }

    state._pollPromise = this._performPoll(state, options).finally(() => {
      const current = this._safes.get(address);
      if (current) current._pollPromise = null;
    });

    return state._pollPromise;
  }

  async _saveWatchlist() {
    try {
      await fs.mkdir(this._artifactDir, { recursive: true });
      const list = this.safes.map((s) => ({ address: s.address, network: s.network }));
      await fs.writeFile(
        path.join(this._artifactDir, WATCHLIST_FILENAME),
        JSON.stringify(list, null, 2),
        "utf8",
      );
    } catch {
      // non-fatal
    }
  }

  async _loadSnapshots() {
    try {
      const raw = await fs.readFile(
        path.join(this._artifactDir, MONITOR_STATE_FILENAME),
        "utf8",
      );
      const payload = JSON.parse(raw);

      for (const entry of payload.safes ?? []) {
        if (entry?.address) {
          this._snapshotBySafe.set(entry.address.trim().toLowerCase(), entry);
        }
      }
    } catch {
      // no monitor snapshot yet — fine
    }
  }

  async _loadHistory() {
    try {
      const raw = await fs.readFile(
        path.join(this._artifactDir, INCIDENT_HISTORY_FILENAME),
        "utf8",
      );
      const payload = JSON.parse(raw);

      for (const entry of payload.entries ?? []) {
        if (entry?.incident?.incidentId) {
          this._historyByIncidentId.set(entry.incident.incidentId, entry);
        }
      }
    } catch {
      // no persisted history yet — fine
    }
  }

  async _saveSnapshot() {
    try {
      await fs.mkdir(this._artifactDir, { recursive: true });
      const payload = {
        generatedAt: this._now().toISOString(),
        safes: this.safes.map((state) => ({
          address: state.address,
          network: state.network,
          chain: state.chain,
          status: state.status,
          incidents: clonePlainData(state.incidents ?? []),
          lastChecked: state.lastChecked,
          transactionsScanned: state.transactionsScanned,
          error: state.error,
          addedAt: state.addedAt,
          lastResolvedAt: state.lastResolvedAt ?? null,
        })),
      };
      await fs.writeFile(
        path.join(this._artifactDir, MONITOR_STATE_FILENAME),
        JSON.stringify(payload, null, 2),
        "utf8",
      );
    } catch {
      // non-fatal
    }
  }

  async _saveHistory() {
    try {
      await fs.mkdir(this._artifactDir, { recursive: true });
      const payload = {
        generatedAt: this._now().toISOString(),
        entries: this.history,
      };
      await fs.writeFile(
        path.join(this._artifactDir, INCIDENT_HISTORY_FILENAME),
        JSON.stringify(payload, null, 2),
        "utf8",
      );
    } catch {
      // non-fatal
    }
  }

  _upsertHistoryEntry(result, state = "active") {
    const incidentId = result.incident?.incidentId;

    if (!incidentId) {
      return;
    }

    const nowIso = this._now().toISOString();
    const previous = this._historyByIncidentId.get(incidentId) ?? null;
    const previousHistory = previous?.history ?? {};
    const nextState =
      state === "resolved" && previousHistory.state === "contained"
        ? "contained"
        : state === "active" &&
            result.execution?.status &&
            EXECUTION_FINAL_STATUSES.has(result.execution.status)
          ? "contained"
          : state;

    this._historyByIncidentId.set(incidentId, {
      ...clonePlainData(previous ?? {}),
      ...clonePlainData(result),
      history: {
        state: nextState,
        firstSeenAt:
          result.monitor?.firstSeenAt ??
          previousHistory.firstSeenAt ??
          nowIso,
        lastSeenAt:
          result.monitor?.lastSeenAt ??
          previousHistory.lastSeenAt ??
          nowIso,
        updatedAt: nowIso,
        resolvedAt:
          state === "resolved"
            ? previousHistory.resolvedAt ?? nowIso
            : null,
      },
    });
  }

  _mergeIncidentResults(previousResults, nextResults, nowIso) {
    const previousById = buildIncidentStateMap(previousResults);

    return nextResults.map((result) => {
      const incidentId = result.incident?.incidentId;
      const previous = previousById.get(incidentId) ?? null;
      const previousMonitor = previous?.monitor ?? {};
      const cached = result.cache?.reused === true;

      return {
        ...result,
        execution: result.execution ?? previous?.execution ?? null,
        monitor: {
          firstSeenAt: previousMonitor.firstSeenAt ?? nowIso,
          lastSeenAt: nowIso,
          lastProcessedAt:
            cached
              ? previousMonitor.lastProcessedAt ??
                result.cache?.processedAt ??
                result.receipt?.createdAt ??
                nowIso
              : nowIso,
          seenCount: (previousMonitor.seenCount ?? 0) + 1,
          processedCount:
            cached
              ? previousMonitor.processedCount ?? 1
              : (previousMonitor.processedCount ?? 0) + 1,
          freshness: cached ? "cached" : "fresh",
          reuseWindowMs: this._incidentReuseWindowMs,
          lastContainmentAt: previousMonitor.lastContainmentAt ?? null,
          lastContainmentStatus: previousMonitor.lastContainmentStatus ?? null,
          containmentAttempts: previousMonitor.containmentAttempts ?? 0,
          actionState:
            previous?.execution && EXECUTION_FINAL_STATUSES.has(previous.execution.status)
              ? "completed"
              : "idle",
        },
      };
    });
  }

  async _performPoll(state, options = {}) {
    const nowIso = this._now().toISOString();

    try {
      refreshRuntimeEnv();
      const env = {
        ...process.env,
        SAFE_PENDING_SOURCE: "live",
        SAFE_ADDRESS: state.address,
        SAFE_NETWORK: state.network,
        SAFE_API_CHAIN: state.chain,
        BREAKGLASS_AUTO_EXECUTE_FIRST_STEP: "false",
      };

      const existingResultsByIncidentId = Object.fromEntries(
        Array.from(state._incidentResultsById.entries()).map(([incidentId, result]) => [
          incidentId,
          clonePlainData(result),
        ]),
      );
      const report = await this._runIncidentPipeline(env, {
        existingResultsByIncidentId,
        refreshKnownIncidents: Boolean(options.refreshKnownIncidents),
        incidentReuseWindowMs: this._incidentReuseWindowMs,
        now: this._now(),
      });
      const previousIncidents = state.incidents ?? [];
      const mergedIncidents = this._mergeIncidentResults(
        previousIncidents,
        report.incidents ?? [],
        nowIso,
      );
      const mergedById = new Set(
        mergedIncidents.map((entry) => entry.incident?.incidentId).filter(Boolean),
      );

      state.incidents = mergedIncidents;
      state._incidentResultsById = buildIncidentStateMap(mergedIncidents);
      state.transactionsScanned = report.transactionsScanned ?? 0;
      state.lastChecked = nowIso;
      state.error = null;

      if (previousIncidents.length > 0 && mergedIncidents.length === 0) {
        state.lastResolvedAt = nowIso;
      }

      for (const incident of mergedIncidents) {
        this._upsertHistoryEntry(incident, "active");
      }

      for (const previous of previousIncidents) {
        const incidentId = previous.incident?.incidentId;

        if (incidentId && !mergedById.has(incidentId)) {
          this._upsertHistoryEntry(
            {
              ...clonePlainData(previous),
              monitor: {
                ...(previous.monitor ?? {}),
                lastSeenAt: nowIso,
              },
            },
            "resolved",
          );
        }
      }

      const severities = state.incidents.map((r) => r.incident?.severity);
      if (severities.includes("critical")) state.status = "critical";
      else if (severities.includes("high")) state.status = "threat";
      else if (severities.length > 0) state.status = "warning";
      else state.status = "safe";
    } catch (err) {
      state.error = err instanceof Error ? err.message : String(err);
      state.status = "error";
      state.lastChecked = nowIso;
    }

    await this._saveSnapshot();
    await this._saveHistory();
  }
}

// ---------------------------------------------------------------------------
// HTML rendering helpers
// ---------------------------------------------------------------------------

function esc(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function toPublicSafeState(state) {
  return {
    address: state.address,
    network: state.network,
    chain: state.chain,
    status: state.status,
    incidents: state.incidents?.length ?? 0,
    lastChecked: state.lastChecked,
    transactionsScanned: state.transactionsScanned,
    error: state.error ?? null,
    addedAt: state.addedAt ?? null,
    lastResolvedAt: state.lastResolvedAt ?? null,
  };
}

const SEV = {
  critical: { color: "#dc2626", bg: "#fef2f2", label: "CRITICAL", dot: "●" },
  high:     { color: "#ea580c", bg: "#fff7ed", label: "HIGH",     dot: "●" },
  medium:   { color: "#d97706", bg: "#fffbeb", label: "MEDIUM",   dot: "●" },
  low:      { color: "#16a34a", bg: "#f0fdf4", label: "LOW",      dot: "●" },
};

const STATUS = {
  critical:   { color: "#dc2626", label: "CRITICAL THREAT" },
  threat:     { color: "#ea580c", label: "THREAT DETECTED" },
  warning:    { color: "#d97706", label: "WARNING" },
  safe:       { color: "#16a34a", label: "Safe" },
  error:      { color: "#6b7280", label: "Error" },
  monitoring: { color: "#3b82f6", label: "Polling..." },
};

const TRIGGER_LABELS = {
  suspicious_approval: "Suspicious Approval",
  ownership_change: "Ownership Change",
  threshold_reduction: "Threshold Reduction",
  module_enablement: "Module Enablement",
  large_transfer: "Large Transfer",
  unknown_transaction: "Unknown Transaction",
};

const STEP_ICONS = {
  invalidate_pending_approval: "🚫",
  invalidate_pending_transaction: "🚫",
  revoke_approval: "↩",
  harden_safe_configuration: "🔒",
  audit_ownership_set: "👥",
  verify_threshold_policy: "🔢",
  audit_module_code: "🔍",
  verify_recipient_ownership: "✓",
  investigate_transfer_origin: "🔎",
  investigate_unknown_transaction: "🧠",
  collect_proposer_explanation: "🗣",
  escalate_human_review: "👤",
};

function deriveContainmentUi(result) {
  const executionStatus = result.execution?.status ?? null;
  const firstRunbookStep = result.runbook?.steps?.[0] ?? null;
  const hasExecutableFirstStep =
    firstRunbookStep && EXECUTABLE_STEP_KINDS.has(firstRunbookStep.kind);

  if (!hasExecutableFirstStep) {
    return {
      buttonLabel: "Human Review Required",
      disabled: true,
      message: "This incident requires investigation and manual operator review before containment.",
    };
  }

  switch (executionStatus) {
    case "executed":
      return {
        buttonLabel: "Containment Executed",
        disabled: true,
        message: "First containment step already executed.",
      };
    case "already_executed":
      return {
        buttonLabel: "Already Contained",
        disabled: true,
        message: "The containment transaction had already been executed on the Safe.",
      };
    case "proposed_and_confirmed":
      return {
        buttonLabel: "Containment Proposed",
        disabled: true,
        message: "Containment transaction is proposed and fully confirmed.",
      };
    case "proposed_waiting_for_confirmations":
      return {
        buttonLabel: "Awaiting Signers",
        disabled: true,
        message: "Containment transaction is proposed and waiting for more signatures.",
      };
    case "prepared":
      return {
        buttonLabel: "Preview Ready",
        disabled: true,
        message: "Dry-run preview prepared. Switch Safe execution to live to propose onchain.",
      };
    case "blocked_by_peer_review":
      return {
        buttonLabel: "Blocked by Review",
        disabled: true,
        message: "AXL reviewer quorum blocked automatic containment.",
      };
    default:
      return {
        buttonLabel: "Propose Containment",
        disabled: false,
        message: null,
      };
  }
}

function deriveHistoryUi(entry) {
  switch (entry.history?.state) {
    case "contained":
      return { label: "Contained", color: "#16a34a", bg: "#f0fdf4" };
    case "resolved":
      return { label: "Resolved", color: "#2563eb", bg: "#eff6ff" };
    default:
      return { label: "Active", color: "#ea580c", bg: "#fff7ed" };
  }
}

function deriveDemoControls(env = process.env) {
  const config = resolveSeedConfig(env);
  const seedReady = Boolean(
    config.safeAddress &&
      config.network &&
      config.rpcUrl &&
      config.ownerPrivateKey &&
      config.txServiceUrl &&
      config.tokenAddress &&
      config.spender,
  );

  return {
    seedReady,
    safeAddress: config.safeAddress ?? null,
    network: config.network ?? null,
  };
}

function describeInvestigatorProvider(config) {
  const providers = [];
  if (config.geminiApiKey) providers.push("gemini");
  if (config.anthropicApiKey) providers.push("anthropic");
  if (config.nvidiaApiKey) providers.push("nvidia");
  if (config.mistralApiKey) providers.push("mistral");
  if (config.openrouterApiKey) providers.push("openrouter");
  return providers.length > 0 ? providers.join(" -> ") : "disabled";
}

function deriveRuntimeStatus(env = process.env, incidents = []) {
  const safeApiLive = Boolean(env.SAFE_API_KEY);
  const investigatorConfig = resolveInvestigatorConfig(env);
  const investigatorProviderLabel = describeInvestigatorProvider(investigatorConfig);
  const investigationConfigured = investigatorProviderLabel !== "disabled";
  const keeperhubWebhook =
    String(env.KEEPERHUB_MODE ?? "local").trim().toLowerCase() === "webhook" &&
    Boolean(env.KEEPERHUB_WEBHOOK_URL);
  const safeExecutionLive =
    String(env.SAFE_EXECUTION_MODE ?? "dry-run").trim().toLowerCase() === "live";
  const receiptStorageMode =
    String(env.BREAKGLASS_RECEIPT_STORAGE ?? "file").trim().toLowerCase() === "0g"
      ? "0g"
      : "file";
  const receiptStorageLive = receiptStorageMode === "0g" && Boolean(env.ZERO_G_PRIVATE_KEY);
  const gensynAxl =
    String(env.GENSYN_AXL_MODE ?? "disabled").trim().toLowerCase() === "mcp";
  const keeperhubDegraded = incidents.some((incident) =>
    (incident.runbook?.steps ?? []).some((step) => step.simulation?.fallbackUsed),
  );
  const aiBriefDegraded = incidents.some((incident) =>
    Boolean(incident.briefStatus?.configured && incident.briefStatus?.error),
  );
  const receiptStorageFailed = incidents.some(
    (incident) => incident.receipt?.storagePointer?.status === "failed",
  );
  const gensynDegraded = incidents.some(
    (incident) => incident.peerReview?.decision === "degraded",
  );

  return {
    safeApi: {
      label: "Safe API",
      value: safeApiLive ? "Live" : "Missing API key",
      tone: safeApiLive ? "ok" : "warn",
    },
    aiBriefs: {
      label: "AI Investigation",
      value:
        !investigationConfigured
          ? "Disabled"
          : aiBriefDegraded
            ? `${investigatorProviderLabel} degraded`
            : `${investigatorProviderLabel} live`,
      tone:
        !investigationConfigured
          ? "muted"
          : aiBriefDegraded
            ? "warn"
            : "ok",
    },
    keeperhub: {
      label: "KeeperHub",
      value:
        keeperhubWebhook
          ? keeperhubDegraded
            ? "Webhook degraded"
            : "Webhook live"
          : "Local fallback",
      tone: keeperhubWebhook ? (keeperhubDegraded ? "warn" : "ok") : "warn",
    },
    safeExecution: {
      label: "Containment",
      value: safeExecutionLive ? "Live Safe proposals" : "Dry-run preview",
      tone: safeExecutionLive ? "ok" : "warn",
    },
    receiptStorage: {
      label: "Receipts",
      value:
        receiptStorageLive
          ? receiptStorageFailed
            ? "0G failing"
            : "0G configured"
          : receiptStorageMode === "0g"
            ? "0G selected"
            : "Local file",
      tone:
        receiptStorageLive
          ? receiptStorageFailed
            ? "warn"
            : "ok"
          : receiptStorageMode === "0g"
            ? "warn"
            : "muted",
    },
    gensyn: {
      label: "Gensyn AXL",
      value:
        gensynAxl
          ? gensynDegraded
            ? "Peer review degraded"
            : "Peer review active"
          : "Disabled",
      tone: gensynAxl ? (gensynDegraded ? "warn" : "ok") : "muted",
    },
  };
}

function buildFlagSignals(result) {
  const reasons = result.incident?.evidence?.reasons ?? [];

  return reasons
    .map((reason) => reason?.message)
    .filter(Boolean)
    .slice(0, 4);
}

function buildReceiptHref(receiptId) {
  return receiptId ? `/api/receipts/${encodeURIComponent(receiptId)}` : null;
}

function renderStep(step) {
  const icon = STEP_ICONS[step.kind] ?? "▸";
  const keeperhubId = step.simulation?.keeperhubRunId ?? null;
  let meta;

  if (keeperhubId) {
    meta = `KeeperHub run: <code>${esc(keeperhubId)}</code>`;
  } else if (step.simulation?.fallbackUsed && step.simulation?.webhookError) {
    meta = `KeeperHub fallback: ${esc(step.simulation.webhookError)}`;
  } else {
    meta = `Status: ${esc(step.simulation?.status ?? step.status ?? "pending")}`;
  }

  return `<div class="step">
    <span class="step-icon">${icon}</span>
    <div>
      <div class="step-desc">${esc(step.description)}</div>
      <div class="step-meta">${meta}</div>
    </div>
  </div>`;
}

function renderToolCalls(toolCalls) {
  if (!toolCalls || toolCalls.length === 0) return "";
  const items = toolCalls.map((tc) => {
    const resultPreview = JSON.stringify(tc.result ?? {}).slice(0, 120);
    return `<div class="tool-call">
      <span class="tool-name">${esc(tc.tool)}</span>
      <span class="tool-dur">${tc.durationMs ?? 0}ms</span>
      <div class="tool-result">${esc(resultPreview)}${resultPreview.length >= 120 ? "..." : ""}</div>
    </div>`;
  }).join("");
  return `<details class="tool-steps">
    <summary>Agent steps (${toolCalls.length} tool calls)</summary>
    ${items}
  </details>`;
}

function renderInvestigationSection(investigation, brief) {
  if (!investigation || investigation.provider === "deterministic") {
    // Fall back to old brief display
    if (brief) return `<div class="ai-brief"><div class="ai-tag">AI Analysis</div><p>${esc(brief)}</p></div>`;
    return `<p class="incident-summary">${esc("")}</p>`;
  }

  const verdictColor = {
    HALT: "#dc2626",
    INVESTIGATE: "#d97706",
    APPROVE: "#16a34a",
  }[investigation.verdict] ?? "#475569";

  const findings = (investigation.keyFindings ?? [])
    .map((f) => `<li>${esc(f)}</li>`)
    .join("");

  return `<div class="ai-brief">
    <div class="investigation-header">
      <span class="ai-tag">Investigation Agent</span>
      <span class="verdict-badge" style="background:${verdictColor}">${esc(investigation.verdict ?? "")}</span>
      <span class="ai-provider-tag">${esc(investigation.provider ?? "")}</span>
    </div>
    ${findings ? `<ul class="findings-list">${findings}</ul>` : ""}
    ${investigation.operatorRecommendation ? `<div class="operator-rec">${esc(investigation.operatorRecommendation)}</div>` : ""}
    ${renderToolCalls(investigation.toolCalls)}
  </div>`;
}

function renderIncidentCard(result) {
  const { incident, brief, runbook, peerReview, briefStatus, investigation } = result;
  const sev = SEV[incident.severity] ?? SEV.medium;
  const steps = runbook?.steps ?? [];
  const triggerLabel = TRIGGER_LABELS[incident.triggerType] ?? esc(incident.triggerType);
  const containmentUi = deriveContainmentUi(result);
  const monitorMeta = result.monitor ?? {};
  const signals = buildFlagSignals(result);
  const firstAction = runbook?.steps?.[0]?.description ?? null;
  const receiptHref = buildReceiptHref(result.receipt?.receiptId);

  const briefSection = renderInvestigationSection(investigation, brief);
  const briefError = (investigation?.configured && investigation?.error && !investigation?.text)
    ? investigation.error
    : (!brief && briefStatus?.configured && briefStatus?.error)
      ? briefStatus.error
      : null;
  const briefNotice = briefError
    ? `<div class="brief-note">Investigation agent unavailable: ${esc(briefError)}</div>`
    : "";

  const peerSection = peerReview?.provider?.mode === "mcp"
    ? `<div class="peer-row">
        <span class="peer-tag">Gensyn AXL</span>
        <span class="peer-dec peer-${esc(peerReview.decision)}">${esc((peerReview.decision ?? "n/a").toUpperCase())}</span>
        <span class="peer-quorum">${peerReview.approvals ?? 0}/${peerReview.requiredApprovals ?? 0} approvals · ${esc(peerReview.summary ?? "")}</span>
      </div>`
    : "";
  const monitorSection = `
    <div class="peer-row">
      <span class="peer-tag">Monitor</span>
      <span class="peer-dec peer-${esc(monitorMeta.freshness ?? "fresh")}">${esc((monitorMeta.freshness ?? "fresh").toUpperCase())}</span>
      <span class="peer-quorum">seen ${monitorMeta.seenCount ?? 1}x · processed ${monitorMeta.processedCount ?? 1}x · first seen ${esc(monitorMeta.firstSeenAt ? new Date(monitorMeta.firstSeenAt).toLocaleTimeString() : "now")}</span>
    </div>`;
  const signalsSection = signals.length
    ? `<div class="steps-label">Why Flagged</div><ul class="signal-list">${signals.map((message) => `<li>${esc(message)}</li>`).join("")}</ul>`
    : "";
  const actionSection = firstAction
    ? `<div class="incident-summary"><strong>Recommended first move:</strong> ${esc(firstAction)}</div>`
    : "";
  const receiptSection = receiptHref
    ? `<a class="receipt-link" href="${esc(receiptHref)}" target="_blank" rel="noreferrer">View receipt JSON</a>`
    : "";

  return `<div class="card" style="border-left:4px solid ${sev.color};background:${sev.bg}">
    <div class="card-header">
      <span class="sev-badge" style="background:${sev.color}">${sev.dot} ${sev.label}</span>
      <span class="type-pill">${esc(triggerLabel)}</span>
      <span class="addr">${esc(incident.safeAddress?.slice(0,10))}...${esc(incident.safeAddress?.slice(-6))}</span>
      <span class="network">${esc(incident.network)}</span>
    </div>
    <h3>${esc(incident.title)}</h3>
    ${briefSection}
    ${briefNotice}
    ${peerSection}
    ${monitorSection}
    ${actionSection}
    ${signalsSection}
    <div class="steps-label">Containment Runbook</div>
    <div class="steps">${steps.map(renderStep).join("")}</div>
    <div class="card-footer">
      <button class="btn-contain" data-id="${esc(incident.incidentId)}" ${containmentUi.disabled ? "disabled" : ""}>${esc(containmentUi.buttonLabel)}</button>
      ${receiptSection}
      <span class="inc-id">ID: <code>${esc(incident.incidentId)}</code></span>
      <span class="result-msg ${containmentUi.message ? "result-ok" : ""}" id="result-${esc(incident.incidentId)}">${esc(containmentUi.message ?? "")}</span>
    </div>
  </div>`;
}

function renderHistoryRow(entry) {
  const historyUi = deriveHistoryUi(entry);
  const receiptHref = buildReceiptHref(entry.receipt?.receiptId);
  const updatedAt = entry.history?.updatedAt
    ? new Date(entry.history.updatedAt).toLocaleTimeString()
    : "unknown";

  return `<div class="history-row">
    <div class="history-main">
      <span class="history-state" style="color:${historyUi.color};background:${historyUi.bg};border-color:${historyUi.color}">${esc(historyUi.label)}</span>
      <span class="type-pill">${esc(TRIGGER_LABELS[entry.incident?.triggerType] ?? entry.incident?.triggerType ?? "Incident")}</span>
      <span class="safe-addr" title="${esc(entry.incident?.safeAddress ?? "")}">${esc((entry.incident?.safeAddress ?? "").slice(0,14))}...${esc((entry.incident?.safeAddress ?? "").slice(-6))}</span>
      <span class="checked-time">updated ${esc(updatedAt)}</span>
      ${receiptHref ? `<a class="receipt-link" href="${esc(receiptHref)}" target="_blank" rel="noreferrer">Receipt</a>` : ""}
    </div>
    <div class="incident-summary">${esc(entry.incident?.title ?? "Incident")}</div>
  </div>`;
}

function renderSafeRow(state) {
  const st = STATUS[state.status] ?? STATUS.monitoring;
  const count = state.incidents?.length ?? 0;
  const checked = state.lastChecked
    ? new Date(state.lastChecked).toLocaleTimeString()
    : "pending";

  return `<div class="safe-row">
    <span class="dot" style="background:${st.color}"></span>
    <span class="safe-addr" title="${esc(state.address)}">${esc(state.address.slice(0,14))}...${esc(state.address.slice(-6))}</span>
    <span class="net-pill">${esc(state.network)}</span>
    <span class="st-label" style="color:${st.color}">${esc(st.label)}</span>
    ${count > 0 ? `<span class="cnt-pill">${count} incident${count !== 1 ? "s" : ""}</span>` : ""}
    <span class="checked-time">checked ${esc(checked)}</span>
    ${state.error ? `<span class="safe-err">${esc(state.error)}</span>` : ""}
    <div class="row-actions">
      <button class="btn-sm poll-btn" data-addr="${esc(state.address)}">Poll now</button>
      <button class="btn-sm btn-rm remove-btn" data-addr="${esc(state.address)}">Remove</button>
    </div>
  </div>`;
}

function renderPage(safes, allIncidents, options = {}) {
  const historyEntries = options.historyEntries ?? [];
  const runtimeStatus = options.runtimeStatus ?? deriveRuntimeStatus();
  const demoControls = options.demoControls ?? deriveDemoControls();
  const metrics = options.metrics ?? {
    monitoredSafeCount: safes.length,
    activeIncidentCount: allIncidents.length,
    resolvedIncidentCount: historyEntries.filter((entry) => entry.history?.state === "resolved").length,
  };
  const networkOptions = `
    <optgroup label="Mainnets">
      <option value="ethereum">Ethereum</option>
      <option value="base">Base</option>
      <option value="arbitrum">Arbitrum</option>
      <option value="optimism">Optimism</option>
      <option value="polygon">Polygon</option>
      <option value="bsc">BSC</option>
      <option value="gnosis">Gnosis</option>
      <option value="avalanche">Avalanche</option>
      <option value="zksync">zkSync Era</option>
      <option value="polygon-zkevm">Polygon zkEVM</option>
      <option value="linea">Linea</option>
      <option value="scroll">Scroll</option>
      <option value="blast">Blast</option>
      <option value="mode">Mode</option>
      <option value="mantle">Mantle</option>
      <option value="celo">Celo</option>
      <option value="worldchain">Worldchain</option>
    </optgroup>
    <optgroup label="Testnets">
      <option value="base-sepolia">Base Sepolia</option>
      <option value="sepolia">Sepolia</option>
      <option value="holesky">Holesky</option>
      <option value="arbitrum-sepolia">Arbitrum Sepolia</option>
      <option value="optimism-sepolia">Optimism Sepolia</option>
    </optgroup>`;

  const safeSection = safes.length
    ? safes.map(renderSafeRow).join("")
    : `<p class="empty">No Safes monitored yet. Add one above.</p>`;

  const incidentSection = allIncidents.length
    ? allIncidents.map(renderIncidentCard).join("")
    : `<p class="empty">No active incidents.</p>`;
  const historySection = historyEntries.length
    ? historyEntries.slice(0, 12).map(renderHistoryRow).join("")
    : `<p class="empty">No incident history yet.</p>`;
  const runtimeCards = Object.values(runtimeStatus).map((status) => `
    <div class="status-card">
      <div class="status-label">${esc(status.label)}</div>
      <div class="status-value tone-${esc(status.tone)}">${esc(status.value)}</div>
    </div>`).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>BreakGlass</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f1f5f9;color:#1e293b;min-height:100vh}
code{font-family:"SFMono-Regular",Consolas,monospace;font-size:.83em;background:#e2e8f0;padding:1px 5px;border-radius:3px}
.topbar{background:#0f172a;color:#f8fafc;padding:14px 24px;display:flex;align-items:center;gap:12px}
.topbar h1{font-size:1.05rem;font-weight:700}
.topbar .tag{font-size:.78rem;color:#94a3b8}
.main{max-width:940px;margin:0 auto;padding:24px 16px;display:flex;flex-direction:column;gap:20px}
.section{background:#fff;border-radius:10px;border:1px solid #e2e8f0;overflow:hidden}
.sec-head{padding:14px 20px;border-bottom:1px solid #f1f5f9}
.sec-head h2{font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#64748b}
.sec-body{padding:16px 20px;display:flex;flex-direction:column;gap:10px}
.status-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.status-card{border:1px solid #e2e8f0;border-radius:8px;padding:12px;background:#f8fafc}
.status-label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#64748b}
.status-value{font-size:.86rem;font-weight:700;margin-top:6px}
.tone-ok{color:#16a34a}.tone-warn{color:#ea580c}.tone-muted{color:#64748b}
.metrics-row{display:flex;gap:10px;flex-wrap:wrap}
.metric-pill{background:#f8fafc;border:1px solid #e2e8f0;border-radius:999px;padding:6px 12px;font-size:.78rem;color:#475569}
.add-row{display:flex;gap:8px;flex-wrap:wrap}
.add-row input{flex:1;min-width:180px;padding:8px 12px;border:1px solid #d1d5db;border-radius:7px;font-size:.9rem;outline:none}
.add-row input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.12)}
.add-row select{padding:8px 12px;border:1px solid #d1d5db;border-radius:7px;font-size:.9rem;outline:none;background:#fff}
.msg{font-size:.8rem;min-height:16px}
.msg.ok{color:#16a34a}.msg.err{color:#dc2626}
.btn-add{padding:8px 18px;background:#0f172a;color:#fff;border:none;border-radius:7px;cursor:pointer;font-size:.88rem;font-weight:600}
.btn-add:hover{background:#1e293b}
.btn-secondary{background:#fff;color:#0f172a;border:1px solid #cbd5e1}
.btn-secondary:hover{background:#f8fafc}
.demo-row{margin-top:10px;align-items:center}
.demo-note{font-size:.8rem;color:#64748b}
.btn-sm{padding:4px 10px;background:#f1f5f9;color:#475569;border:1px solid #e2e8f0;border-radius:6px;cursor:pointer;font-size:.78rem}
.btn-sm:hover{background:#e2e8f0}
.btn-rm{color:#dc2626}
.safe-row{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #f8fafc;flex-wrap:wrap}
.safe-row:last-child{border-bottom:none}
.dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.safe-addr{font-family:monospace;font-size:.86rem;font-weight:600}
.net-pill{font-size:.74rem;color:#64748b;background:#f1f5f9;padding:2px 8px;border-radius:99px}
.st-label{font-weight:700;font-size:.82rem}
.cnt-pill{background:#fef2f2;color:#dc2626;font-size:.74rem;padding:2px 8px;border-radius:99px;font-weight:700}
.checked-time{font-size:.74rem;color:#94a3b8}
.safe-err{font-size:.75rem;color:#dc2626;background:#fef2f2;padding:3px 8px;border-radius:5px}
.row-actions{display:flex;gap:6px;margin-left:auto}
.card{border-radius:8px;padding:18px;display:flex;flex-direction:column;gap:12px}
.card-header{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.sev-badge{color:#fff;font-size:.72rem;font-weight:700;padding:3px 10px;border-radius:99px}
.type-pill{font-size:.78rem;font-weight:600;color:#475569;background:#fff;padding:3px 10px;border-radius:99px;border:1px solid #e2e8f0}
.addr{font-family:monospace;font-size:.8rem;color:#64748b}
.network{font-size:.75rem;color:#94a3b8}
.card h3{font-size:.98rem;font-weight:700;color:#0f172a}
.incident-summary{font-size:.86rem;color:#475569;line-height:1.6}
.incident-summary strong{color:#0f172a}
.ai-brief{background:#fff;border-radius:7px;padding:12px 14px;border:1px solid #e2e8f0}
.investigation-header{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap}
.ai-tag{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#7c3aed}
.verdict-badge{font-size:.72rem;font-weight:700;color:#fff;padding:2px 8px;border-radius:99px}
.ai-provider-tag{font-size:.72rem;color:#94a3b8}
.findings-list{margin:6px 0 8px 16px;display:flex;flex-direction:column;gap:3px}
.findings-list li{font-size:.85rem;color:#1e293b;line-height:1.5}
.operator-rec{font-size:.86rem;color:#475569;font-style:italic;margin-top:6px;padding-top:6px;border-top:1px solid #f1f5f9}
.tool-steps{margin-top:8px;border:1px solid #e2e8f0;border-radius:6px;overflow:hidden}
.tool-steps summary{font-size:.75rem;font-weight:600;color:#64748b;padding:6px 10px;cursor:pointer;background:#f8fafc}
.tool-steps summary:hover{background:#f1f5f9}
.tool-call{padding:6px 10px;border-top:1px solid #f1f5f9;display:flex;gap:8px;flex-wrap:wrap;align-items:baseline}
.tool-name{font-family:monospace;font-size:.78rem;font-weight:700;color:#7c3aed}
.tool-dur{font-size:.72rem;color:#94a3b8}
.tool-result{font-family:monospace;font-size:.72rem;color:#475569;width:100%;word-break:break-all}
.ai-brief p{font-size:.86rem;color:#1e293b;line-height:1.7}
.brief-note{font-size:.78rem;color:#7c2d12;background:#fff7ed;border:1px solid #fed7aa;border-radius:7px;padding:8px 12px}
.peer-row{display:flex;align-items:center;gap:8px;background:#f8fafc;border-radius:6px;padding:7px 12px;flex-wrap:wrap}
.peer-tag{font-size:.74rem;color:#64748b;font-weight:700}
.peer-dec{font-size:.74rem;font-weight:700;padding:2px 9px;border-radius:99px;background:#fff}
.peer-approve{color:#16a34a;border:1px solid #86efac}
.peer-halt{color:#dc2626;border:1px solid #fca5a5}
.peer-fresh{color:#2563eb;border:1px solid #93c5fd}
.peer-cached{color:#64748b;border:1px solid #cbd5e1}
.peer-quorum{font-size:.74rem;color:#64748b}
.steps-label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#64748b;margin-top:2px}
.steps{display:flex;flex-direction:column;gap:7px}
.signal-list{padding-left:18px;color:#475569;font-size:.83rem;display:flex;flex-direction:column;gap:6px}
.step{display:flex;gap:10px;align-items:flex-start;background:#fff;border-radius:7px;padding:9px 12px;border:1px solid #e2e8f0}
.step-icon{font-size:.95rem;flex-shrink:0;width:20px;text-align:center}
.step-desc{font-size:.84rem;color:#1e293b;line-height:1.5}
.step-meta{font-size:.75rem;color:#64748b;margin-top:3px}
.card-footer{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.btn-contain{padding:8px 18px;background:#0f172a;color:#fff;border:none;border-radius:7px;cursor:pointer;font-size:.86rem;font-weight:600}
.btn-contain:hover{background:#1e293b}
.btn-contain:disabled{opacity:.5;cursor:default}
.receipt-link{font-size:.8rem;color:#2563eb;text-decoration:none;font-weight:600}
.receipt-link:hover{text-decoration:underline}
.inc-id{font-size:.72rem;color:#94a3b8}
.result-msg{font-size:.8rem;padding:3px 10px;border-radius:5px}
.result-ok{background:#f0fdf4;color:#16a34a}
.result-err{background:#fef2f2;color:#dc2626}
.history-row{display:flex;flex-direction:column;gap:6px;padding:10px 0;border-bottom:1px solid #f8fafc}
.history-row:last-child{border-bottom:none}
.history-main{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.history-state{display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;border:1px solid currentColor;font-size:.74rem;font-weight:700}
.empty{color:#94a3b8;font-size:.86rem}
</style>
</head>
<body>
<div class="topbar"><h1>BreakGlass</h1><span class="tag">Self-hosted Safe incident response</span></div>
<main class="main">

<div class="section">
  <div class="sec-head"><h2>System Status</h2></div>
  <div class="sec-body">
    <div class="status-grid">${runtimeCards}</div>
    <div class="metrics-row">
      <span class="metric-pill">${esc(String(metrics.monitoredSafeCount ?? safes.length))} Safes monitored</span>
      <span class="metric-pill">${esc(String(metrics.activeIncidentCount ?? allIncidents.length))} active incidents</span>
      <span class="metric-pill">${esc(String(metrics.resolvedIncidentCount ?? 0))} resolved incidents</span>
    </div>
  </div>
</div>

<div class="section">
  <div class="sec-head"><h2>Monitor a Safe</h2></div>
  <div class="sec-body">
    <div class="add-row">
      <input id="addr-in" type="text" placeholder="Safe address (0x...)" autocomplete="off" spellcheck="false"/>
      <select id="net-sel">${networkOptions}</select>
      <button class="btn-add" id="add-btn">Start Monitoring</button>
    </div>
    <div class="add-row demo-row">
      <button class="btn-add btn-secondary" id="demo-seed-btn" ${demoControls.seedReady ? "" : "disabled"}>Seed Demo Incident</button>
      <span class="demo-note">${
        demoControls.seedReady
          ? `Seeds a suspicious approval on ${esc(demoControls.network)} for ${esc(demoControls.safeAddress?.slice(0, 10) ?? "")}...`
          : "Seed demo incident is unavailable until SAFE demo credentials are configured on the server."
      }</span>
    </div>
    <div class="msg" id="msg"></div>
  </div>
</div>

<div class="section">
  <div class="sec-head"><h2>Monitored Safes</h2></div>
  <div class="sec-body" id="safes-list">${safeSection}</div>
</div>

<div class="section">
  <div class="sec-head"><h2>Active Incidents</h2></div>
  <div class="sec-body" id="incidents-list">${incidentSection}</div>
</div>

<div class="section">
  <div class="sec-head"><h2>Incident History</h2></div>
  <div class="sec-body" id="history-list">${historySection}</div>
</div>

</main>
<script>
const setMsg = (t,c) => { const el=document.getElementById('msg'); el.textContent=t; el.className='msg '+(c||''); };

document.getElementById('add-btn').addEventListener('click', async () => {
  const addr = document.getElementById('addr-in').value.trim();
  const net  = document.getElementById('net-sel').value;
  if (!addr) return setMsg('Enter a Safe address.','err');
  setMsg('Adding...','');
  const r = await fetch('/api/safes',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({address:addr,network:net})});
  const d = await r.json();
  if (d.ok) { setMsg('Safe added. First poll running — refreshing in 5s.','ok'); document.getElementById('addr-in').value=''; setTimeout(()=>location.reload(),5000); }
  else setMsg(d.reason||'Failed.','err');
});

const demoSeedBtn = document.getElementById('demo-seed-btn');
if (demoSeedBtn) {
  demoSeedBtn.addEventListener('click', async () => {
    demoSeedBtn.textContent='Seeding...';
    demoSeedBtn.disabled=true;
    setMsg('Seeding a suspicious approval and refreshing the monitor...','');
    const r = await fetch('/api/demo/seed',{method:'POST'});
    const d = await r.json();
    if (d.ok) {
      setMsg('Demo incident seeded. Refreshing in 5s.','ok');
      setTimeout(()=>location.reload(),5000);
      return;
    }
    setMsg(d.error||'Failed to seed demo incident.','err');
    demoSeedBtn.textContent='Seed Demo Incident';
    demoSeedBtn.disabled=false;
  });
}

document.getElementById('addr-in').addEventListener('keydown', e => { if(e.key==='Enter') document.getElementById('add-btn').click(); });

document.getElementById('safes-list').addEventListener('click', async e => {
  const rb = e.target.closest('.remove-btn');
  const pb = e.target.closest('.poll-btn');
  if (rb) { await fetch('/api/safes/'+encodeURIComponent(rb.dataset.addr),{method:'DELETE'}); location.reload(); }
  if (pb) { pb.textContent='Polling...'; pb.disabled=true; await fetch('/api/safes/'+encodeURIComponent(pb.dataset.addr)+'/poll',{method:'POST'}); setTimeout(()=>location.reload(),3000); }
});

document.getElementById('incidents-list').addEventListener('click', async e => {
  const btn = e.target.closest('.btn-contain');
  if (!btn) return;
  const id = btn.dataset.id;
  btn.textContent='Proposing...'; btn.disabled=true;
  const r = await fetch('/api/incidents/'+encodeURIComponent(id)+'/contain',{method:'POST'});
  const d = await r.json();
  const el = document.getElementById('result-'+id);
  if (el) { el.textContent = d.ok ? (d.status||'Proposed') : (d.error||'Failed'); el.className='result-msg '+(d.ok?'result-ok':'result-err'); }
  if (!d.ok) { btn.textContent='Propose Containment'; btn.disabled=false; return; }
  btn.textContent = d.status === 'executed' ? 'Containment Executed' : 'Containment Proposed';
});

setTimeout(()=>location.reload(), 30000);
</script>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(body) });
  res.end(body);
}

function sendHtml(res, html) {
  const body = Buffer.from(html, "utf8");
  res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-length": body.length });
  res.end(body);
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

async function handleRequest(req, res, monitor) {
  refreshRuntimeEnv();
  const url = new URL(req.url, "http://localhost");
  const p = url.pathname;

  if (req.method === "GET" && p === "/") {
    return sendHtml(
      res,
      renderPage(monitor.safes, monitor.incidents, {
        historyEntries: monitor.history,
        runtimeStatus: deriveRuntimeStatus(process.env, monitor.incidents),
        metrics: {
          monitoredSafeCount: monitor.safes.length,
          activeIncidentCount: monitor.incidents.length,
          resolvedIncidentCount: monitor.history.filter((entry) => entry.history?.state === "resolved").length,
        },
      }),
    );
  }

  if (req.method === "GET" && p === "/api/safes") {
    return sendJson(res, 200, {
      safes: monitor.safes.map(toPublicSafeState),
    });
  }

  if (req.method === "POST" && p === "/api/safes") {
    let body;
    try { body = JSON.parse(await readBody(req)); } catch { return sendJson(res, 400, { ok: false, reason: "invalid_json" }); }
    if (!body?.address) return sendJson(res, 400, { ok: false, reason: "address_required" });
    if (!body?.network) return sendJson(res, 400, { ok: false, reason: "network_required" });
    const result = await monitor.addSafe(body.address, body.network);
    return sendJson(res, result.ok ? 200 : 409, result);
  }

  const deleteMatch = p.match(/^\/api\/safes\/([^/]+)$/);
  if (req.method === "DELETE" && deleteMatch) {
    const result = await monitor.removeSafe(decodeURIComponent(deleteMatch[1]));
    return sendJson(res, result.ok ? 200 : 404, result);
  }

  const pollMatch = p.match(/^\/api\/safes\/([^/]+)\/poll$/);
  if (req.method === "POST" && pollMatch) {
    const result = await monitor.forcePoll(decodeURIComponent(pollMatch[1]));
    return sendJson(res, result.ok ? 200 : 404, result);
  }

  if (req.method === "GET" && p === "/api/incidents") {
    return sendJson(res, 200, { incidents: monitor.incidents });
  }

  if (req.method === "GET" && p === "/api/history") {
    return sendJson(res, 200, { history: monitor.history });
  }

  if (req.method === "POST" && p === "/api/demo/seed") {
    try {
      const seedIncident = monitor.seedIncident ?? seedSuspiciousApproval;
      const seeded = await seedIncident();

      if (seeded?.safeAddress && seeded?.network) {
        const addResult = await monitor.addSafe(seeded.safeAddress, seeded.network);
        if (!addResult.ok && addResult.reason !== "already_monitored") {
          throw new Error(addResult.reason ?? "Failed to monitor seeded Safe.");
        }

        const pollResult = await monitor.forcePoll(seeded.safeAddress);
        if (!pollResult.ok) {
          throw new Error(pollResult.reason ?? "Failed to poll seeded Safe.");
        }
      }

      return sendJson(res, 200, {
        ok: true,
        seeded,
      });
    } catch (err) {
      return sendJson(res, 500, {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  const containMatch = p.match(/^\/api\/incidents\/([^/]+)\/contain$/);
  if (req.method === "POST" && containMatch) {
    const incidentId = decodeURIComponent(containMatch[1]);
    const found = monitor.findIncident(incidentId);
    if (!found) return sendJson(res, 404, { ok: false, error: "Incident not found." });

    if (found.execution?.status && EXECUTION_FINAL_STATUSES.has(found.execution.status)) {
      return sendJson(res, 200, {
        ok: true,
        ...clonePlainData(found.execution),
      });
    }

    try {
      const {
        resolveSafeExecutionConfig,
        executeMitigationStep,
      } = require("../../../packages/integrations/src/safe-remediation");
      const executionConfig = resolveSafeExecutionConfig(process.env);
      const firstStep = found.runbook?.steps?.[0] ?? null;
      if (!firstStep || !EXECUTABLE_STEP_KINDS.has(firstStep.kind)) {
        return sendJson(res, 200, { ok: false, error: "No executable first step in runbook." });
      }
      const result = await executeMitigationStep(firstStep, found.incident, executionConfig);
      await monitor.recordContainmentResult(incidentId, result);
      return sendJson(res, 200, { ok: true, ...result });
    } catch (err) {
      return sendJson(res, 500, { ok: false, error: err instanceof Error ? err.message : String(err) });
    }
  }

  // Legacy compatibility
  if (req.method === "GET" && p === "/api/report") {
    return sendJson(res, 200, {
      safes: monitor.safes.map(toPublicSafeState),
      incidents: monitor.incidents,
      history: monitor.history,
      runtimeStatus: deriveRuntimeStatus(process.env, monitor.incidents),
    });
  }

  const receiptMatch = p.match(/^\/api\/receipts\/([^/]+)$/);
  if (req.method === "GET" && receiptMatch) {
    try {
      const config = resolveReceiptStorageConfig({
        ...process.env,
        BREAKGLASS_ARTIFACT_DIR: monitor.artifactDir,
      });
      const payload = await readReceiptMirror(
        decodeURIComponent(receiptMatch[1]),
        config,
      );
      return sendJson(res, 200, payload);
    } catch (err) {
      return sendJson(res, 404, {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return sendJson(res, 404, { error: "Not found" });
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

async function startServer() {
  const monitor = new MonitorService();
  await monitor.load();

  const port = Number(process.env.PORT ?? 3030);
  const host = process.env.HOST ?? "127.0.0.1";

  const server = http.createServer(async (req, res) => {
    try {
      await handleRequest(req, res, monitor);
    } catch (err) {
      sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) });
    }
  });

  await new Promise((resolve) => server.listen(port, host, resolve));
  console.log(`BreakGlass dashboard: http://${host}:${port}`);
  return { server, monitor };
}

if (require.main === module) {
  startServer().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}

module.exports = { startServer, MonitorService, renderPage, handleRequest };
