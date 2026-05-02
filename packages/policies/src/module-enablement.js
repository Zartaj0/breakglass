const {
  INCIDENT_SEVERITY,
  INCIDENT_SOURCE_STAGE,
  INCIDENT_TRIGGER_TYPES,
  buildIncidentCase,
  getParameterMap,
  normalizeAddress,
} = require("../../shared/src/models");

function parseAddressSet(rawValue) {
  if (!rawValue) return new Set();
  return new Set(
    String(rawValue)
      .split(",")
      .map((v) => normalizeAddress(v))
      .filter(Boolean),
  );
}

function resolveModulePolicyConfig(env = process.env) {
  return {
    allowedModules: parseAddressSet(env.BREAKGLASS_ALLOWED_MODULES),
  };
}

function detectModuleEnablementIncident(transaction, policyConfig) {
  const method = transaction.dataDecoded?.method ?? "";
  if (method !== "enableModule") return null;

  const params = getParameterMap(transaction);
  const moduleAddress = normalizeAddress(params.get("module"));

  const isUnknown =
    policyConfig.allowedModules.size > 0 &&
    moduleAddress &&
    !policyConfig.allowedModules.has(moduleAddress);

  const severity = isUnknown ? INCIDENT_SEVERITY.CRITICAL : INCIDENT_SEVERITY.HIGH;

  const reasons = [
    {
      code: isUnknown ? "unknown_module" : "module_enablement",
      severity,
      message: isUnknown
        ? `Module ${moduleAddress} is not on the allowlist. Modules have unrestricted access to Safe funds.`
        : "Enabling a Safe module grants it the ability to execute transactions without owner signatures.",
    },
  ];

  return buildIncidentCase({
    safeAddress: transaction.safeAddress,
    network: transaction.network,
    triggerType: INCIDENT_TRIGGER_TYPES.MODULE_ENABLEMENT,
    sourceStage: INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION,
    severity,
    title: "Safe module enablement pending",
    summary: `enableModule(${moduleAddress ?? "unknown"}) would give a contract unrestricted execution access to the Safe.`,
    source: {
      kind: "safe_pending_transaction",
      safeTxHash: transaction.safeTxHash,
      transaction,
    },
    identity: {
      safeTxHash: transaction.safeTxHash ?? null,
      safeAddress: transaction.safeAddress,
      network: transaction.network,
      triggerType: INCIDENT_TRIGGER_TYPES.MODULE_ENABLEMENT,
      module: moduleAddress ?? null,
      nonce: transaction.nonce,
    },
    evidence: {
      module: { address: moduleAddress, isUnknown },
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

function detectModuleEnablementIncidents(transactions, policyConfig = resolveModulePolicyConfig()) {
  return transactions
    .map((tx) => detectModuleEnablementIncident(tx, policyConfig))
    .filter(Boolean);
}

module.exports = {
  detectModuleEnablementIncident,
  detectModuleEnablementIncidents,
  resolveModulePolicyConfig,
};
