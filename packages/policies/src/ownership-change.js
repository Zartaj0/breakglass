const {
  INCIDENT_SEVERITY,
  INCIDENT_SOURCE_STAGE,
  INCIDENT_TRIGGER_TYPES,
  buildIncidentCase,
  getParameterMap,
  normalizeAddress,
  toNumber,
  toStringValue,
} = require("../../shared/src/models");

const OWNERSHIP_CHANGE_METHODS = new Set([
  "addOwnerWithThreshold",
  "removeOwner",
  "swapOwner",
]);

function parseAddressSet(rawValue) {
  if (!rawValue) return new Set();
  return new Set(
    String(rawValue)
      .split(",")
      .map((v) => normalizeAddress(v))
      .filter(Boolean),
  );
}

function resolveOwnershipPolicyConfig(env = process.env) {
  return {
    allowedOwners: parseAddressSet(env.BREAKGLASS_ALLOWED_OWNERS),
    minThreshold: toNumber(env.BREAKGLASS_MIN_THRESHOLD, 2),
  };
}

function extractOwnershipEvidence(transaction) {
  const params = getParameterMap(transaction);
  const method = transaction.dataDecoded?.method ?? "";

  let affectedOwner = null;
  let newThreshold = null;

  if (method === "addOwnerWithThreshold") {
    affectedOwner = normalizeAddress(params.get("owner"));
    newThreshold = toNumber(params.get("_threshold"), null);
  } else if (method === "removeOwner") {
    affectedOwner = normalizeAddress(params.get("owner"));
    newThreshold = toNumber(params.get("_threshold"), null);
  } else if (method === "swapOwner") {
    affectedOwner = normalizeAddress(params.get("newOwner"));
  }

  return { method, affectedOwner, newThreshold };
}

function detectOwnershipChangeIncident(transaction, policyConfig) {
  const method = transaction.dataDecoded?.method ?? "";
  if (!OWNERSHIP_CHANGE_METHODS.has(method)) return null;

  const ev = extractOwnershipEvidence(transaction);
  const reasons = [];

  const isAddingOwner = method === "addOwnerWithThreshold" || method === "swapOwner";

  if (
    isAddingOwner &&
    ev.affectedOwner &&
    policyConfig.allowedOwners.size > 0 &&
    !policyConfig.allowedOwners.has(ev.affectedOwner)
  ) {
    reasons.push({
      code: "unknown_owner_addition",
      severity: INCIDENT_SEVERITY.CRITICAL,
      message: `Adding ${ev.affectedOwner} as an owner but this address is not on the allowlist.`,
    });
  } else {
    reasons.push({
      code: "ownership_structure_change",
      severity: INCIDENT_SEVERITY.HIGH,
      message: `${method} modifies the Safe owner set — requires review before signing.`,
    });
  }

  if (ev.newThreshold !== null && ev.newThreshold < policyConfig.minThreshold) {
    reasons.push({
      code: "threshold_below_minimum",
      severity: ev.newThreshold === 1 ? INCIDENT_SEVERITY.CRITICAL : INCIDENT_SEVERITY.HIGH,
      message: `Operation sets threshold to ${ev.newThreshold}, below the minimum of ${policyConfig.minThreshold}.`,
    });
  }

  const severity = reasons.some((r) => r.severity === INCIDENT_SEVERITY.CRITICAL)
    ? INCIDENT_SEVERITY.CRITICAL
    : INCIDENT_SEVERITY.HIGH;

  return buildIncidentCase({
    safeAddress: transaction.safeAddress,
    network: transaction.network,
    triggerType: INCIDENT_TRIGGER_TYPES.OWNERSHIP_CHANGE,
    sourceStage: INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION,
    severity,
    title: "Safe ownership structure change pending",
    summary: `${method} would alter who controls this Safe. ${reasons.length} risk signal(s) detected.`,
    source: {
      kind: "safe_pending_transaction",
      safeTxHash: transaction.safeTxHash,
      transaction,
    },
    identity: {
      safeTxHash: transaction.safeTxHash ?? null,
      safeAddress: transaction.safeAddress,
      network: transaction.network,
      triggerType: INCIDENT_TRIGGER_TYPES.OWNERSHIP_CHANGE,
      method: ev.method,
      affectedOwner: ev.affectedOwner ?? null,
      nonce: transaction.nonce,
    },
    evidence: {
      ownership: ev,
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

function detectOwnershipChangeIncidents(transactions, policyConfig = resolveOwnershipPolicyConfig()) {
  return transactions
    .map((tx) => detectOwnershipChangeIncident(tx, policyConfig))
    .filter(Boolean);
}

module.exports = {
  OWNERSHIP_CHANGE_METHODS,
  detectOwnershipChangeIncident,
  detectOwnershipChangeIncidents,
  resolveOwnershipPolicyConfig,
};
