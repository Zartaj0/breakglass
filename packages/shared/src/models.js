const { createHash } = require("node:crypto");

const SAFE_OPERATION = {
  CALL: 0,
  DELEGATECALL: 1,
};

const SAFE_OPERATION_LABELS = {
  [SAFE_OPERATION.CALL]: "CALL",
  [SAFE_OPERATION.DELEGATECALL]: "DELEGATECALL",
};

const INCIDENT_TRIGGER_TYPES = {
  SUSPICIOUS_APPROVAL: "suspicious_approval",
  OWNERSHIP_CHANGE: "ownership_change",
  THRESHOLD_REDUCTION: "threshold_reduction",
  MODULE_ENABLEMENT: "module_enablement",
  LARGE_TRANSFER: "large_transfer",
  UNKNOWN_TRANSACTION: "unknown_transaction",
};

const INCIDENT_SOURCE_STAGE = {
  PENDING_TRANSACTION: "pending_transaction",
  LIVE_ALLOWANCE: "live_allowance",
  UNKNOWN: "unknown",
};

const INCIDENT_SEVERITY = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
};

const RUNBOOK_STEP_STATUS = {
  PLANNED: "planned",
  CONDITIONAL: "conditional",
  NOT_APPLICABLE: "not_applicable",
};

function normalizeAddress(value) {
  if (typeof value !== "string") {
    return null;
  }

  return value.trim().toLowerCase();
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toStringValue(value, fallback = "") {
  if (value === null || value === undefined) {
    return fallback;
  }

  return String(value);
}

function readBooleanLike(value) {
  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "string") {
    return value.trim().toLowerCase() === "true";
  }

  return Boolean(value);
}

function normalizeDecodedParameter(parameter) {
  if (!parameter || typeof parameter !== "object") {
    return null;
  }

  return {
    name: toStringValue(parameter.name, ""),
    type: toStringValue(parameter.type, ""),
    value: parameter.value,
    valueDecoded: parameter.valueDecoded ?? null,
  };
}

function normalizeDataDecoded(dataDecoded) {
  if (!dataDecoded || typeof dataDecoded !== "object") {
    return null;
  }

  return {
    method: toStringValue(dataDecoded.method, ""),
    parameters: asArray(dataDecoded.parameters)
      .map(normalizeDecodedParameter)
      .filter(Boolean),
  };
}

function normalizeConfirmation(confirmation) {
  if (!confirmation || typeof confirmation !== "object") {
    return null;
  }

  return {
    owner: normalizeAddress(confirmation.owner),
    submissionDate: confirmation.submissionDate ?? null,
    signature: confirmation.signature ?? null,
    signatureType: confirmation.signatureType ?? null,
  };
}

function getParameterMap(transaction) {
  return new Map(
    (transaction.dataDecoded?.parameters ?? []).map((p) => [p.name, p.value]),
  );
}

function buildStableId(prefix, payload) {
  const hash = createHash("sha256")
    .update(JSON.stringify(payload))
    .digest("hex")
    .slice(0, 12);

  return `${prefix}-${hash}`;
}

function getOperationLabel(operation) {
  return SAFE_OPERATION_LABELS[operation] ?? `UNKNOWN_${operation}`;
}

function normalizeSafePendingTransaction(rawTransaction, context = {}) {
  const confirmations = asArray(rawTransaction.confirmations)
    .map(normalizeConfirmation)
    .filter(Boolean);
  const operation = toNumber(rawTransaction.operation, SAFE_OPERATION.CALL);
  const safeAddress = normalizeAddress(
    rawTransaction.safe ?? context.safeAddress ?? null,
  );

  return {
    id:
      rawTransaction.safeTxHash ??
      buildStableId("pending-tx", {
        safeAddress,
        nonce: rawTransaction.nonce ?? null,
        to: rawTransaction.to ?? null,
      }),
    safeTxHash: rawTransaction.safeTxHash ?? null,
    safeAddress,
    network: toStringValue(context.network ?? rawTransaction.network, "unknown"),
    to: normalizeAddress(rawTransaction.to),
    value: toStringValue(rawTransaction.value, "0"),
    data: rawTransaction.data ?? null,
    operation,
    operationLabel: rawTransaction.operationLabel ?? getOperationLabel(operation),
    nonce: toNumber(rawTransaction.nonce, -1),
    confirmationsRequired: toNumber(
      rawTransaction.confirmationsRequired,
      confirmations.length,
    ),
    confirmationsCollected: toNumber(
      rawTransaction.confirmationsCollected,
      confirmations.length,
    ),
    confirmations,
    dataDecoded: normalizeDataDecoded(rawTransaction.dataDecoded),
    submissionDate:
      rawTransaction.submissionDate ?? new Date().toISOString(),
    raw: rawTransaction,
  };
}

function buildIncidentCase({
  safeAddress,
  network,
  triggerType,
  sourceStage = INCIDENT_SOURCE_STAGE.UNKNOWN,
  severity,
  title,
  summary,
  source,
  evidence,
  identity = null,
  createdAt,
}) {
  const incidentPayload = {
    safeAddress: normalizeAddress(safeAddress),
    network,
    triggerType,
    sourceStage,
    severity,
    sourceId: source?.safeTxHash ?? source?.transaction?.safeTxHash ?? source?.id,
    identity: identity ?? evidence,
  };

  return {
    incidentId: buildStableId("incident", incidentPayload),
    safeAddress: normalizeAddress(safeAddress),
    network,
    triggerType,
    sourceStage,
    source: source ?? null,
    createdAt: createdAt ?? new Date().toISOString(),
    severity,
    title,
    summary,
    evidence,
  };
}

function buildRunbookStep({
  stepId,
  kind,
  description,
  dependsOn = [],
  status = RUNBOOK_STEP_STATUS.PLANNED,
  simulation = null,
  execution = null,
  metadata = {},
}) {
  return {
    stepId,
    kind,
    description,
    dependsOn,
    status,
    simulation,
    execution,
    metadata,
  };
}

function buildRunbookPlan({
  incident,
  templateId,
  title,
  summary,
  steps,
  metadata = {},
}) {
  return {
    runbookId: buildStableId("runbook", {
      incidentId: incident.incidentId,
      templateId,
    }),
    incidentId: incident.incidentId,
    safeAddress: incident.safeAddress,
    network: incident.network,
    templateId,
    title,
    summary,
    steps,
    compiledAt: new Date().toISOString(),
    metadata,
  };
}

function buildIncidentReceipt({
  incident,
  runbook,
  finalStatus,
  simulationArtifacts = [],
  executionArtifacts = null,
  operatorDecision = null,
  reasoningSummary = "",
  storagePointer = null,
  metadata = {},
}) {
  return {
    receiptId: buildStableId("receipt", {
      incidentId: incident.incidentId,
      runbookId: runbook.runbookId,
      finalStatus,
    }),
    incidentId: incident.incidentId,
    runbookId: runbook.runbookId,
    safeAddress: incident.safeAddress,
    network: incident.network,
    finalStatus,
    simulationArtifacts,
    executionArtifacts,
    operatorDecision,
    reasoningSummary,
    storagePointer,
    createdAt: new Date().toISOString(),
    metadata,
  };
}

module.exports = {
  INCIDENT_SOURCE_STAGE,
  INCIDENT_SEVERITY,
  INCIDENT_TRIGGER_TYPES,
  RUNBOOK_STEP_STATUS,
  SAFE_OPERATION,
  SAFE_OPERATION_LABELS,
  asArray,
  buildIncidentCase,
  buildIncidentReceipt,
  buildRunbookPlan,
  buildRunbookStep,
  buildStableId,
  getOperationLabel,
  getParameterMap,
  normalizeAddress,
  normalizeDataDecoded,
  normalizeSafePendingTransaction,
  readBooleanLike,
  toNumber,
  toStringValue,
};
