const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");

const {
  normalizeSafePendingTransaction,
} = require("../packages/shared/src/models");
const {
  detectSuspiciousApprovalIncidents,
  resolvePolicyConfig,
} = require("../packages/policies/src/suspicious-approval");
const {
  compileApprovalExposureRunbook,
} = require("../packages/runbooks/src/approval-exposure");
const {
  REVIEW_TOOL_NAME,
  handleReviewerRpc,
} = require("../packages/agent-mesh/src/reviewer");

function buildFixtureIncident() {
  const fixture = JSON.parse(
    fs.readFileSync(
      "apps/watcher/fixtures/pending-transactions.json",
      "utf8",
    ),
  );
  const normalized = fixture.transactions.map((entry) =>
    normalizeSafePendingTransaction(entry, {
      network: "base-sepolia",
      safeAddress: fixture.transactions[0].safe,
    }),
  );
  const incidents = detectSuspiciousApprovalIncidents(
    normalized,
    resolvePolicyConfig({
      BREAKGLASS_ALLOWED_SPENDERS: "",
      BREAKGLASS_APPROVAL_THRESHOLD: "100000000000000000000000",
    }),
  );

  return incidents[0];
}

test("reviewer exposes the incident review tool", () => {
  const response = handleReviewerRpc({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
    params: {},
  });

  assert.equal(response.result.tools[0].name, REVIEW_TOOL_NAME);
});

test("reviewer approves the deterministic first step for a suspicious approval", () => {
  const incident = buildFixtureIncident();
  const runbook = compileApprovalExposureRunbook(incident);
  const response = handleReviewerRpc(
    {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: REVIEW_TOOL_NAME,
        arguments: {
          incident,
          runbook,
        },
      },
    },
    {
      reviewerId: "peer-a",
      reviewerLabel: "peer-a",
    },
  );
  const review = response.result.structuredContent;

  assert.equal(review.recommendation, "approve");
  assert.equal(review.firstStepKind, "invalidate_pending_approval");
  assert.equal(review.agreedFirstStep, true);
});
