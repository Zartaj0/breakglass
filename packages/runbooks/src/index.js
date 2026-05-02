const { INCIDENT_TRIGGER_TYPES } = require("../../shared/src/models");
const { compileApprovalExposureRunbook } = require("./approval-exposure");
const { compileOwnershipChangeRunbook } = require("./ownership-change");
const { compileThresholdReductionRunbook } = require("./threshold-reduction");
const { compileModuleEnablementRunbook } = require("./module-enablement");
const { compileLargeTransferRunbook } = require("./large-transfer");

const RUNBOOK_COMPILERS = {
  [INCIDENT_TRIGGER_TYPES.SUSPICIOUS_APPROVAL]: compileApprovalExposureRunbook,
  [INCIDENT_TRIGGER_TYPES.OWNERSHIP_CHANGE]: compileOwnershipChangeRunbook,
  [INCIDENT_TRIGGER_TYPES.THRESHOLD_REDUCTION]: compileThresholdReductionRunbook,
  [INCIDENT_TRIGGER_TYPES.MODULE_ENABLEMENT]: compileModuleEnablementRunbook,
  [INCIDENT_TRIGGER_TYPES.LARGE_TRANSFER]: compileLargeTransferRunbook,
};

function compileRunbook(incident) {
  const compiler = RUNBOOK_COMPILERS[incident.triggerType];

  if (!compiler) {
    throw new Error(
      `No runbook compiler registered for incident type: ${incident.triggerType}`,
    );
  }

  return compiler(incident);
}

module.exports = {
  compileRunbook,
};
