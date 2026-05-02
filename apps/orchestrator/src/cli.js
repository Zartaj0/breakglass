const { loadDotEnv } = require("../../../packages/shared/src/load-env");
const { runIncidentPipeline } = require("./pipeline");

loadDotEnv({ override: true });

async function main() {
  const report = await runIncidentPipeline(process.env);
  console.log(JSON.stringify(report, null, 2));
}

main().catch((error) => {
  console.error("[breakglass-orchestrator] failed to process incidents");
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
