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
  compileOwnershipChangeRunbook,
} = require("../packages/runbooks/src/ownership-change");
const {
  buildPeerReviewBlockArtifact,
  resolveAgentMeshConfig,
  reviewIncidentWithPeers,
  shouldAllowExecution,
} = require("../packages/agent-mesh/src/axl-client");
const {
  reviewIncidentAgainstRunbook,
  reviewIncidentWithAI,
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

test("resolveAgentMeshConfig parses peer review env", () => {
  const config = resolveAgentMeshConfig({
    GENSYN_AXL_MODE: "mcp",
    GENSYN_AXL_PEER_IDS: "peer-a, peer-b",
    GENSYN_AXL_MIN_APPROVALS: "2",
    GENSYN_AXL_REQUIRE_QUORUM_FOR_EXECUTION: "true",
  });

  assert.equal(config.mode, "mcp");
  assert.deepEqual(config.peers, ["peer-a", "peer-b"]);
  assert.equal(config.minApprovals, 2);
  assert.equal(config.requireQuorumForExecution, true);
});

test("reviewIncidentWithPeers aggregates reviewer approvals over AXL", async () => {
  const incident = buildFixtureIncident();
  const runbook = compileApprovalExposureRunbook(incident);
  const previousFetch = global.fetch;

  global.fetch = async (url) => {
    if (String(url).endsWith("/topology")) {
      return {
        ok: true,
        text: async () =>
          JSON.stringify({
            our_public_key: "local-peer",
          }),
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
              recommendation: "approve",
              summary: "peer approved invalidate_pending_approval",
            },
          },
        }),
    };
  };

  try {
    const review = await reviewIncidentWithPeers(incident, runbook, {
      mode: "mcp",
      apiBaseUrl: "http://127.0.0.1:9002",
      peers: ["peer-a", "peer-b"],
      service: "breakglass-review",
      timeoutMs: 2000,
      minApprovals: 2,
      requireQuorumForExecution: true,
    });

    assert.equal(review.provider.mode, "mcp");
    assert.equal(review.approvals, 2);
    assert.equal(review.quorumReached, true);
    assert.equal(review.decision, "approve");
    assert.equal(shouldAllowExecution(review, {
      mode: "mcp",
      requireQuorumForExecution: true,
    }), true);
  } finally {
    global.fetch = previousFetch;
  }
});

test("peer review can block execution when quorum is not met", () => {
  const block = buildPeerReviewBlockArtifact(
    {
      summary: "AXL peer review returned 0 approvals.",
      decision: "insufficient_quorum",
      approvals: 0,
      requiredApprovals: 2,
      executionGate: "block",
    },
    {
      mode: "live",
    },
  );

  assert.equal(block.status, "blocked_by_peer_review");
  assert.equal(block.peerReview.requiredApprovals, 2);
});

test("reviewIncidentWithAI stays deterministic when no LLM provider is configured", async () => {
  const incident = buildFixtureIncident();
  const runbook = compileApprovalExposureRunbook(incident);

  const review = await reviewIncidentWithAI(incident, runbook, {
    reviewerLabel: "reviewer-a",
    aiConfig: {},
  });

  assert.equal(review.recommendation, "approve");
  assert.equal(review.aiEnhanced, false);
  assert.equal(review.aiProvider, null);
});

test("reviewIncidentAgainstRunbook approves ownership-change containment when first step matches", () => {
  const incident = {
    triggerType: "ownership_change",
    severity: "critical",
    sourceStage: "pending_transaction",
    evidence: {
      reasons: [{ code: "unknown_owner_addition", message: "owner not allowlisted" }],
    },
  };
  const runbook = compileOwnershipChangeRunbook({
    incidentId: "incident-own-1",
    safeAddress: "0xabc",
    network: "base-sepolia",
    triggerType: "ownership_change",
    sourceStage: "pending_transaction",
    evidence: {
      ownership: {
        method: "addOwnerWithThreshold",
        affectedOwner: "0xdef",
        newThreshold: 1,
      },
    },
    source: {
      safeTxHash: "0xown",
      transaction: { nonce: 4, safeTxHash: "0xown" },
    },
  });

  const review = reviewIncidentAgainstRunbook(incident, runbook, {
    reviewerLabel: "reviewer-b",
  });

  assert.equal(review.recommendation, "approve");
  assert.equal(review.expectedFirstStepKind, "invalidate_pending_transaction");
});
