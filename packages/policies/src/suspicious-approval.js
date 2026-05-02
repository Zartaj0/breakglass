const {
  INCIDENT_SOURCE_STAGE,
  INCIDENT_SEVERITY,
  INCIDENT_TRIGGER_TYPES,
  buildIncidentCase,
  normalizeAddress,
  readBooleanLike,
} = require("../../shared/src/models");

const APPROVAL_METHODS = new Set([
  "approve",
  "forceApprove",
  "increaseAllowance",
  "setApprovalForAll",
]);

const MAX_UINT256 =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const DEFAULT_APPROVAL_THRESHOLD = "100000000000000000000000";

function parseAddressSet(rawValue) {
  if (!rawValue) {
    return new Set();
  }

  return new Set(
    String(rawValue)
      .split(",")
      .map((value) => normalizeAddress(value))
      .filter(Boolean),
  );
}

function toBigInt(value, fallback = 0n) {
  try {
    if (typeof value === "bigint") {
      return value;
    }

    if (value === null || value === undefined || value === "") {
      return fallback;
    }

    return BigInt(String(value));
  } catch {
    return fallback;
  }
}

function getParameterMap(transaction) {
  return new Map(
    (transaction.dataDecoded?.parameters ?? []).map((parameter) => [
      parameter.name,
      parameter.value,
    ]),
  );
}

function resolvePolicyConfig(env = process.env) {
  return {
    allowedSpenders: parseAddressSet(env.BREAKGLASS_ALLOWED_SPENDERS),
    approvalThreshold: toBigInt(
      env.BREAKGLASS_APPROVAL_THRESHOLD,
      BigInt(DEFAULT_APPROVAL_THRESHOLD),
    ),
    unlimitedApprovalValue: toBigInt(MAX_UINT256),
  };
}

function buildApprovalEvidence(transaction) {
  const params = getParameterMap(transaction);
  const method = transaction.dataDecoded?.method ?? "";
  const spender = normalizeAddress(
    params.get("spender") ?? params.get("operator") ?? null,
  );
  const rawAmount =
    params.get("value") ??
    params.get("amount") ??
    params.get("addedValue") ??
    null;
  const approvalValue = toBigInt(rawAmount, 0n);
  const approved =
    method === "setApprovalForAll"
      ? readBooleanLike(params.get("approved"))
      : approvalValue > 0n;

  return {
    method,
    spender,
    rawAmount: rawAmount === null ? null : String(rawAmount),
    approvalValue: approvalValue.toString(),
    approved,
  };
}

function calculateSeverity(reasons) {
  if (reasons.some((reason) => reason.severity === INCIDENT_SEVERITY.CRITICAL)) {
    return INCIDENT_SEVERITY.CRITICAL;
  }

  if (reasons.some((reason) => reason.severity === INCIDENT_SEVERITY.HIGH)) {
    return INCIDENT_SEVERITY.HIGH;
  }

  if (reasons.some((reason) => reason.severity === INCIDENT_SEVERITY.MEDIUM)) {
    return INCIDENT_SEVERITY.MEDIUM;
  }

  return INCIDENT_SEVERITY.LOW;
}

function buildSuspiciousApprovalIdentity(transaction, approval) {
  return {
    safeTxHash: transaction.safeTxHash ?? null,
    safeAddress: transaction.safeAddress,
    network: transaction.network,
    triggerType: INCIDENT_TRIGGER_TYPES.SUSPICIOUS_APPROVAL,
    sourceStage: INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION,
    spender: approval.spender ?? null,
    method: approval.method ?? null,
    rawAmount: approval.rawAmount ?? null,
    token: transaction.to ?? null,
    nonce: transaction.nonce,
  };
}

function detectSuspiciousApprovalIncident(transaction, policyConfig) {
  const method = transaction.dataDecoded?.method ?? "";
  if (!APPROVAL_METHODS.has(method)) {
    return null;
  }

  const approval = buildApprovalEvidence(transaction);
  const reasons = [];

  if (!approval.approved) {
    return null;
  }

  if (approval.spender && !policyConfig.allowedSpenders.has(approval.spender)) {
    reasons.push({
      code: "unknown_spender",
      severity: INCIDENT_SEVERITY.HIGH,
      message: `Approval targets spender ${approval.spender}, which is not on the allowlist.`,
    });
  }

  if (
    approval.rawAmount &&
    toBigInt(approval.rawAmount, 0n) >= policyConfig.approvalThreshold
  ) {
    reasons.push({
      code: "high_value_approval",
      severity: INCIDENT_SEVERITY.MEDIUM,
      message: `Approval value ${approval.rawAmount} exceeds the configured threshold.`,
    });
  }

  if (approval.rawAmount && approval.rawAmount === policyConfig.unlimitedApprovalValue.toString()) {
    reasons.push({
      code: "unlimited_approval",
      severity: INCIDENT_SEVERITY.CRITICAL,
      message: "Approval grants effectively unlimited spending power.",
    });
  }

  if (method === "setApprovalForAll") {
    reasons.push({
      code: "operator_enablement",
      severity: INCIDENT_SEVERITY.HIGH,
      message: "setApprovalForAll enables an operator over the entire collection.",
    });
  }

  if (reasons.length === 0) {
    return null;
  }

  const severity = calculateSeverity(reasons);

  return buildIncidentCase({
    safeAddress: transaction.safeAddress,
    network: transaction.network,
    triggerType: INCIDENT_TRIGGER_TYPES.SUSPICIOUS_APPROVAL,
    sourceStage: INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION,
    severity,
    title: "Suspicious approval pending in Safe queue",
    summary: `${method} to ${approval.spender ?? "unknown spender"} triggered ${reasons.length} approval risk signal(s).`,
    source: {
      kind: "safe_pending_transaction",
      safeTxHash: transaction.safeTxHash,
      transaction,
    },
    identity: buildSuspiciousApprovalIdentity(transaction, approval),
    evidence: {
      approval,
      reasons,
      transaction: {
        to: transaction.to,
        nonce: transaction.nonce,
        operation: transaction.operationLabel,
        confirmationsCollected: transaction.confirmationsCollected,
        confirmationsRequired: transaction.confirmationsRequired,
      },
      policy: {
        allowedSpenders: Array.from(policyConfig.allowedSpenders),
        approvalThreshold: policyConfig.approvalThreshold.toString(),
      },
    },
  });
}

function detectSuspiciousApprovalIncidents(transactions, policyConfig = resolvePolicyConfig()) {
  return transactions
    .map((transaction) =>
      detectSuspiciousApprovalIncident(transaction, policyConfig),
    )
    .filter(Boolean);
}

module.exports = {
  APPROVAL_METHODS,
  DEFAULT_APPROVAL_THRESHOLD,
  MAX_UINT256,
  buildApprovalEvidence,
  buildSuspiciousApprovalIdentity,
  detectSuspiciousApprovalIncident,
  detectSuspiciousApprovalIncidents,
  resolvePolicyConfig,
};
