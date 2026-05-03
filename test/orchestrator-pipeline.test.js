const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runIncidentPipeline } = require("../apps/orchestrator/src/pipeline");

test("runs the incident pipeline end to end in dry-run mode", async () => {
  const artifactDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "breakglass-artifacts-"),
  );

  const report = await runIncidentPipeline({
    SAFE_PENDING_SOURCE: "fixture",
    SAFE_NETWORK: "base-sepolia",
    WATCHER_FIXTURE_PATH: "apps/watcher/fixtures/pending-transactions.json",
    BREAKGLASS_ALLOWED_SPENDERS:
      "0x1111111111111111111111111111111111111111",
    BREAKGLASS_APPROVAL_THRESHOLD: "100000000000000000000000",
    KEEPERHUB_MODE: "local",
    SAFE_EXECUTION_MODE: "dry-run",
    BREAKGLASS_AUTO_EXECUTE_FIRST_STEP: "true",
    BREAKGLASS_RECEIPT_STORAGE: "file",
    BREAKGLASS_ARTIFACT_DIR: artifactDir,
  });

  assert.equal(report.incidentsDetected, 3);
  assert.equal(report.incidents.length, 3);
  const approvalIncident = report.incidents.find(
    (entry) => entry.incident.triggerType === "suspicious_approval",
  );
  assert.ok(approvalIncident);
  assert.equal(approvalIncident.runbook.steps[0].kind, "invalidate_pending_approval");
  assert.equal(approvalIncident.execution.status, "prepared");
  assert.equal(approvalIncident.receipt.storagePointer.kind, "local_file");
  assert.match(
    JSON.stringify(report.readiness.fallbackWarnings),
    /safe_ingestion_fixture_mode/,
  );
  assert.equal(fs.existsSync(approvalIncident.localReceiptPath), true);
  assert.equal(fs.existsSync(report.reportPath), true);
});

test("pipeline records AXL peer review and blocks execution when quorum is required", async () => {
  const artifactDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "breakglass-axl-"),
  );
  const previousFetch = global.fetch;

  global.fetch = async (url) => {
    if (String(url).endsWith("/topology")) {
      return {
        ok: true,
        text: async () => JSON.stringify({ our_public_key: "local-peer" }),
      };
    }

    return {
      ok: true,
      text: async () =>
        JSON.stringify({
          jsonrpc: "2.0",
          id: "1",
          result: {
            structuredContent: {
              recommendation: "halt",
              summary: "peer halted automation",
            },
          },
        }),
    };
  };

  try {
    const report = await runIncidentPipeline({
      SAFE_PENDING_SOURCE: "fixture",
      SAFE_NETWORK: "base-sepolia",
      WATCHER_FIXTURE_PATH: "apps/watcher/fixtures/pending-transactions.json",
      BREAKGLASS_ALLOWED_SPENDERS: "",
      BREAKGLASS_APPROVAL_THRESHOLD: "100000000000000000000000",
      KEEPERHUB_MODE: "local",
      SAFE_EXECUTION_MODE: "live",
      BREAKGLASS_AUTO_EXECUTE_FIRST_STEP: "true",
      BREAKGLASS_RECEIPT_STORAGE: "file",
      BREAKGLASS_ARTIFACT_DIR: artifactDir,
      GENSYN_AXL_MODE: "mcp",
      GENSYN_AXL_PEER_IDS: "peer-a",
      GENSYN_AXL_MIN_APPROVALS: "1",
      GENSYN_AXL_REQUIRE_QUORUM_FOR_EXECUTION: "true",
    });

    assert.equal(report.agentMesh.mode, "mcp");
    assert.equal(report.incidents[0].peerReview.decision, "halt");
    assert.equal(report.incidents[0].execution.status, "blocked_by_peer_review");
  } finally {
    global.fetch = previousFetch;
  }
});

test("pipeline reuses cached incident results within the configured reuse window", async () => {
  const artifactDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "breakglass-cache-"),
  );
  const firstReport = await runIncidentPipeline(
    {
      SAFE_PENDING_SOURCE: "fixture",
      SAFE_NETWORK: "base-sepolia",
      WATCHER_FIXTURE_PATH: "apps/watcher/fixtures/pending-transactions.json",
      BREAKGLASS_ALLOWED_SPENDERS:
        "0x1111111111111111111111111111111111111111",
      BREAKGLASS_APPROVAL_THRESHOLD: "100000000000000000000000",
      KEEPERHUB_MODE: "local",
      SAFE_EXECUTION_MODE: "dry-run",
      BREAKGLASS_AUTO_EXECUTE_FIRST_STEP: "false",
      BREAKGLASS_RECEIPT_STORAGE: "file",
      BREAKGLASS_ARTIFACT_DIR: artifactDir,
    },
    {
      now: new Date("2026-04-28T00:00:00.000Z"),
    },
  );

  const cachedReport = await runIncidentPipeline(
    {
      SAFE_PENDING_SOURCE: "fixture",
      SAFE_NETWORK: "base-sepolia",
      WATCHER_FIXTURE_PATH: "apps/watcher/fixtures/pending-transactions.json",
      BREAKGLASS_ALLOWED_SPENDERS:
        "0x1111111111111111111111111111111111111111",
      BREAKGLASS_APPROVAL_THRESHOLD: "100000000000000000000000",
      KEEPERHUB_MODE: "local",
      SAFE_EXECUTION_MODE: "dry-run",
      BREAKGLASS_AUTO_EXECUTE_FIRST_STEP: "false",
      BREAKGLASS_RECEIPT_STORAGE: "file",
      BREAKGLASS_ARTIFACT_DIR: artifactDir,
    },
    {
      existingResultsByIncidentId: {
        [firstReport.incidents[0].incident.incidentId]: firstReport.incidents[0],
      },
      incidentReuseWindowMs: 60_000,
      now: new Date("2026-04-28T00:00:20.000Z"),
    },
  );

  assert.equal(cachedReport.incidents[0].cache.reused, true);
  assert.equal(
    cachedReport.incidents[0].receipt.receiptId,
    firstReport.incidents[0].receipt.receiptId,
  );
  assert.equal(
    cachedReport.incidents[0].runbook.runbookId,
    firstReport.incidents[0].runbook.runbookId,
  );
});
