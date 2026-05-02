const fs = require("node:fs");

const { loadDotEnv } = require("../packages/shared/src/load-env");
const {
  resolveReceiptStorageConfig,
} = require("../packages/storage-0g/src/client");

loadDotEnv({ override: true });

function main() {
  const storageConfig = resolveReceiptStorageConfig(process.env);

  if (!fs.existsSync(storageConfig.reportPath)) {
    throw new Error(
      `Latest report not found at ${storageConfig.reportPath}. Run the orchestrator first.`,
    );
  }

  const report = JSON.parse(fs.readFileSync(storageConfig.reportPath, "utf8"));
  const warnings = report.readiness?.fallbackWarnings ?? [];

  if (warnings.length > 0) {
    console.error(
      JSON.stringify(
        {
          demoReady: false,
          warnings,
        },
        null,
        2,
      ),
    );
    process.exitCode = 1;
    return;
  }

  console.log(
    JSON.stringify(
      {
        demoReady: true,
        source: report.source,
        keeperhub: report.keeperhub,
        agentMesh: report.agentMesh,
        storage: report.storage,
      },
      null,
      2,
    ),
  );
}

try {
  main();
} catch (error) {
  console.error(
    error instanceof Error ? error.message : String(error),
  );
  process.exitCode = 1;
}
