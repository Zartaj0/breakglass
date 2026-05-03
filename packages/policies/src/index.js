const {
  detectSuspiciousApprovalIncidents,
  resolvePolicyConfig,
} = require("./suspicious-approval");
const {
  detectOwnershipChangeIncidents,
  resolveOwnershipPolicyConfig,
} = require("./ownership-change");
const {
  detectThresholdReductionIncidents,
  resolveThresholdPolicyConfig,
} = require("./threshold-reduction");
const {
  detectModuleEnablementIncidents,
  resolveModulePolicyConfig,
} = require("./module-enablement");
const {
  detectLargeTransferIncidents,
  resolveTransferPolicyConfig,
} = require("./large-transfer");
const {
  detectUnknownTransactionIncidents,
  resolveUnknownTransactionPolicyConfig,
} = require("./unknown-transaction");

function resolveAllPolicyConfigs(env = process.env) {
  return {
    approval: resolvePolicyConfig(env),
    ownership: resolveOwnershipPolicyConfig(env),
    threshold: resolveThresholdPolicyConfig(env),
    module: resolveModulePolicyConfig(env),
    transfer: resolveTransferPolicyConfig(env),
    unknown: resolveUnknownTransactionPolicyConfig(env),
  };
}

function detectAllIncidents(transactions, configs = resolveAllPolicyConfigs()) {
  const knownIncidents = [
    ...detectSuspiciousApprovalIncidents(transactions, configs.approval),
    ...detectOwnershipChangeIncidents(transactions, configs.ownership),
    ...detectThresholdReductionIncidents(transactions, configs.threshold),
    ...detectModuleEnablementIncidents(transactions, configs.module),
    ...detectLargeTransferIncidents(transactions, configs.transfer),
  ];

  const coveredTransactionIds = new Set(
    knownIncidents
      .map((incident) => incident.source?.transaction?.id ?? incident.source?.safeTxHash ?? null)
      .filter(Boolean),
  );

  const unknownIncidents = detectUnknownTransactionIncidents(
    transactions.filter(
      (transaction) =>
        !coveredTransactionIds.has(transaction.id) &&
        !coveredTransactionIds.has(transaction.safeTxHash),
    ),
    configs.unknown,
  );

  return [...knownIncidents, ...unknownIncidents];
}

module.exports = {
  detectAllIncidents,
  resolveAllPolicyConfigs,
};
