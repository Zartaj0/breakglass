const {
  INCIDENT_SEVERITY,
  INCIDENT_SOURCE_STAGE,
  INCIDENT_TRIGGER_TYPES,
  buildIncidentCase,
  getParameterMap,
  toNumber,
} = require("../../shared/src/models");

function resolveThresholdPolicyConfig(env = process.env) {
  return {
    minThreshold: toNumber(env.BREAKGLASS_MIN_THRESHOLD, 2),
  };
}

function detectThresholdReductionIncident(transaction, policyConfig) {
  const method = transaction.dataDecoded?.method ?? "";
  if (method !== "changeThreshold") return null;

  const params = getParameterMap(transaction);
  const proposed = toNumber(params.get("_threshold"), -1);

  if (proposed < 0) return null;

  const severity =
    proposed === 1
      ? INCIDENT_SEVERITY.CRITICAL
      : proposed < policyConfig.minThreshold
        ? INCIDENT_SEVERITY.HIGH
        : INCIDENT_SEVERITY.MEDIUM;

  const reasons = [
    {
      code: proposed < policyConfig.minThreshold ? "threshold_below_minimum" : "threshold_change",
      severity,
      message:
        proposed === 1
          ? "Setting threshold to 1 means a single compromised key can drain the Safe."
          : `Proposed threshold of ${proposed} is below the configured minimum of ${policyConfig.minThreshold}.`,
    },
  ];

  return buildIncidentCase({
    safeAddress: transaction.safeAddress,
    network: transaction.network,
    triggerType: INCIDENT_TRIGGER_TYPES.THRESHOLD_REDUCTION,
    sourceStage: INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION,
    severity,
    title: "Safe signing threshold change pending",
    summary: `changeThreshold(${proposed}) would reduce required signatures — weakens the multisig protection.`,
    source: {
      kind: "safe_pending_transaction",
      safeTxHash: transaction.safeTxHash,
      transaction,
    },
    identity: {
      safeTxHash: transaction.safeTxHash ?? null,
      safeAddress: transaction.safeAddress,
      network: transaction.network,
      triggerType: INCIDENT_TRIGGER_TYPES.THRESHOLD_REDUCTION,
      method,
      proposedThreshold: proposed,
      nonce: transaction.nonce,
    },
    evidence: {
      threshold: { method, proposedThreshold: proposed },
      reasons,
      transaction: {
        to: transaction.to,
        nonce: transaction.nonce,
        confirmationsCollected: transaction.confirmationsCollected,
        confirmationsRequired: transaction.confirmationsRequired,
      },
    },
  });
}

function detectThresholdReductionIncidents(transactions, policyConfig = resolveThresholdPolicyConfig()) {
  return transactions
    .map((tx) => detectThresholdReductionIncident(tx, policyConfig))
    .filter(Boolean);
}

module.exports = {
  detectThresholdReductionIncident,
  detectThresholdReductionIncidents,
  resolveThresholdPolicyConfig,
};
