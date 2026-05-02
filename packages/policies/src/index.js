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

function resolveAllPolicyConfigs(env = process.env) {
  return {
    approval: resolvePolicyConfig(env),
    ownership: resolveOwnershipPolicyConfig(env),
    threshold: resolveThresholdPolicyConfig(env),
    module: resolveModulePolicyConfig(env),
    transfer: resolveTransferPolicyConfig(env),
  };
}

function detectAllIncidents(transactions, configs = resolveAllPolicyConfigs()) {
  return [
    ...detectSuspiciousApprovalIncidents(transactions, configs.approval),
    ...detectOwnershipChangeIncidents(transactions, configs.ownership),
    ...detectThresholdReductionIncidents(transactions, configs.threshold),
    ...detectModuleEnablementIncidents(transactions, configs.module),
    ...detectLargeTransferIncidents(transactions, configs.transfer),
  ];
}

module.exports = {
  detectAllIncidents,
  resolveAllPolicyConfigs,
};
