const {
  INCIDENT_SEVERITY,
  INCIDENT_SOURCE_STAGE,
  INCIDENT_TRIGGER_TYPES,
  SAFE_OPERATION,
  buildIncidentCase,
  normalizeAddress,
  readBooleanLike,
  toNumber,
  toStringValue,
} = require("../../shared/src/models");

function resolveUnknownTransactionPolicyConfig(env = process.env) {
  return {
    enabled:
      env.BREAKGLASS_ENABLE_UNKNOWN_TRANSACTION === undefined
        ? true
        : readBooleanLike(env.BREAKGLASS_ENABLE_UNKNOWN_TRANSACTION),
    minCalldataBytes: Math.max(
      4,
      toNumber(env.BREAKGLASS_UNKNOWN_TX_MIN_DATA_BYTES, 4),
    ),
  };
}

function countDataBytes(data) {
  if (!data || data === "0x") {
    return 0;
  }

  const normalized = String(data).replace(/^0x/i, "");
  return Math.max(0, Math.floor(normalized.length / 2));
}

function detectUnknownTransactionIncident(transaction, policyConfig) {
  if (!policyConfig.enabled) {
    return null;
  }

  const calldataBytes = countDataBytes(transaction.data);
  const method = transaction.dataDecoded?.method ?? null;
  const isDelegateCall = transaction.operation === SAFE_OPERATION.DELEGATECALL;

  if (!isDelegateCall && calldataBytes < policyConfig.minCalldataBytes) {
    return null;
  }

  let severity = INCIDENT_SEVERITY.MEDIUM;
  let code = "uncategorized_contract_call";
  let message = `Pending ${method ?? "contract"} call is not covered by a high-confidence deterministic detector and should be investigated before more owners sign.`;

  if (isDelegateCall) {
    severity = INCIDENT_SEVERITY.CRITICAL;
    code = "delegatecall_requires_investigation";
    message =
      "Pending delegatecall can execute external code in the Safe context and requires immediate investigation before any additional signatures are added.";
  } else if (!method) {
    severity = INCIDENT_SEVERITY.HIGH;
    code = "opaque_calldata";
    message =
      "Pending transaction includes opaque calldata that did not decode into a known method. Investigation agent should assess intent before additional owners sign.";
  }

  const target = normalizeAddress(transaction.to);
  const reasons = [
    {
      code,
      severity,
      message,
    },
  ];

  return buildIncidentCase({
    safeAddress: transaction.safeAddress,
    network: transaction.network,
    triggerType: INCIDENT_TRIGGER_TYPES.UNKNOWN_TRANSACTION,
    sourceStage: INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION,
    severity,
    title: "Uncategorized Safe transaction requires investigation",
    summary: `${method ?? "Opaque calldata"} to ${target ?? "unknown target"} did not match a deterministic incident class. Investigation is required before signing continues.`,
    source: {
      kind: "safe_pending_transaction",
      safeTxHash: transaction.safeTxHash,
      transaction,
    },
    identity: {
      safeTxHash: transaction.safeTxHash ?? null,
      safeAddress: transaction.safeAddress,
      network: transaction.network,
      triggerType: INCIDENT_TRIGGER_TYPES.UNKNOWN_TRANSACTION,
      method: method ?? null,
      target,
      operation: transaction.operationLabel,
      nonce: transaction.nonce,
    },
    evidence: {
      anomaly: {
        target,
        method,
        operation: transaction.operationLabel,
        value: toStringValue(transaction.value, "0"),
        calldataBytes,
        isDelegateCall,
      },
      reasons,
      transaction: {
        to: transaction.to,
        nonce: transaction.nonce,
        operation: transaction.operationLabel,
        confirmationsCollected: transaction.confirmationsCollected,
        confirmationsRequired: transaction.confirmationsRequired,
      },
    },
  });
}

function detectUnknownTransactionIncidents(
  transactions,
  policyConfig = resolveUnknownTransactionPolicyConfig(),
) {
  return transactions
    .map((transaction) =>
      detectUnknownTransactionIncident(transaction, policyConfig),
    )
    .filter(Boolean);
}

module.exports = {
  detectUnknownTransactionIncident,
  detectUnknownTransactionIncidents,
  resolveUnknownTransactionPolicyConfig,
};
