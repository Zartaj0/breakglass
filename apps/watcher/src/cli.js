const { loadDotEnv } = require("../../../packages/shared/src/load-env");
const {
  getPendingTransactions,
  resolveSafeSourceConfig,
} = require("../../../packages/integrations/src/safe-client");
const {
  detectSuspiciousApprovalIncidents,
  resolvePolicyConfig,
} = require("../../../packages/policies/src/suspicious-approval");
const {
  compileApprovalExposureRunbook,
} = require("../../../packages/runbooks/src/approval-exposure");

loadDotEnv({ override: true });

async function main() {
  const sourceConfig = resolveSafeSourceConfig(process.env);
  const policyConfig = resolvePolicyConfig(process.env);
  const pending = await getPendingTransactions(sourceConfig);
  const incidents = detectSuspiciousApprovalIncidents(
    pending.transactions,
    policyConfig,
  );

  const output = {
    fetchedAt: pending.fetchedAt,
    source: pending.source,
    safeAddress: pending.safeAddress,
    network: pending.network,
    transactionsScanned: pending.transactions.length,
    incidentsDetected: incidents.length,
    incidents: incidents.map((incident) => ({
      incident,
      runbook: compileApprovalExposureRunbook(incident),
    })),
  };

  console.log(JSON.stringify(output, null, 2));
}

main().catch((error) => {
  console.error("[breakglass-watcher] failed to build incident cases");
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
