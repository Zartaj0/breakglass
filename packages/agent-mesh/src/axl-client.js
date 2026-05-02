const {
  readBooleanLike,
  toNumber,
  toStringValue,
} = require("../../shared/src/models");
const {
  REVIEW_SERVICE_NAME,
  REVIEW_TOOL_NAME,
} = require("./reviewer");

function parseCsv(value) {
  if (!value) {
    return [];
  }

  return String(value)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function trimTrailingSlash(value) {
  return String(value).replace(/\/+$/, "");
}

function resolveAgentMeshConfig(env = process.env) {
  const mode =
    toStringValue(env.GENSYN_AXL_MODE, "disabled").trim().toLowerCase() === "mcp"
      ? "mcp"
      : "disabled";
  const peers = parseCsv(env.GENSYN_AXL_PEER_IDS);
  const explicitMinApprovals = toNumber(env.GENSYN_AXL_MIN_APPROVALS, 0);
  const minApprovals =
    explicitMinApprovals > 0
      ? explicitMinApprovals
      : peers.length > 0
        ? 1
        : 0;

  return {
    mode,
    apiBaseUrl: trimTrailingSlash(
      toStringValue(env.GENSYN_AXL_API_BASE_URL, "http://127.0.0.1:9002"),
    ),
    peers,
    service: toStringValue(env.GENSYN_AXL_SERVICE, REVIEW_SERVICE_NAME),
    timeoutMs: toNumber(env.GENSYN_AXL_TIMEOUT_MS, 7000),
    minApprovals,
    requireQuorumForExecution: readBooleanLike(
      env.GENSYN_AXL_REQUIRE_QUORUM_FOR_EXECUTION,
    ),
  };
}

async function readJson(response) {
  const text = await response.text();

  if (!text) {
    return {};
  }

  try {
    return JSON.parse(text);
  } catch {
    return {
      raw: text,
    };
  }
}

async function fetchJson(url, options, timeoutMs) {
  const response = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const body = await readJson(response);

  if (!response.ok) {
    throw new Error(
      `AXL request failed with ${response.status}: ${JSON.stringify(body).slice(0, 400)}`,
    );
  }

  return body;
}

function extractStructuredContent(body) {
  const structured = body?.result?.structuredContent;

  if (structured && typeof structured === "object") {
    return structured;
  }

  const textPart = body?.result?.content?.find(
    (entry) => typeof entry?.text === "string",
  );

  if (!textPart) {
    return null;
  }

  try {
    return JSON.parse(textPart.text);
  } catch {
    return {
      raw: textPart.text,
    };
  }
}

async function fetchTopology(config) {
  try {
    return await fetchJson(
      `${config.apiBaseUrl}/topology`,
      {
        method: "GET",
        headers: {
          accept: "application/json",
        },
      },
      config.timeoutMs,
    );
  } catch (error) {
    return {
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

async function requestPeerReview(peerId, incident, runbook, config) {
  try {
    const body = await fetchJson(
      `${config.apiBaseUrl}/mcp/${peerId}/${config.service}`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: `breakglass-${peerId}`,
          method: "tools/call",
          params: {
            name: REVIEW_TOOL_NAME,
            arguments: {
              incident,
              runbook,
            },
          },
        }),
      },
      config.timeoutMs,
    );
    const review = extractStructuredContent(body);

    if (!review || typeof review !== "object") {
      throw new Error("Peer review response did not contain structured content.");
    }

    return {
      peerId,
      status: review.recommendation === "approve" ? "approved" : "halted",
      review,
      summary: review.summary ?? null,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    return {
      peerId,
      status: "error",
      error: message,
      summary: `Peer review failed: ${message}`,
    };
  }
}

function buildDisabledSummary(config) {
  return {
    provider: {
      name: "gensyn-axl",
      mode: config.mode,
      configured: false,
      service: config.service,
      peerCount: config.peers.length,
      requireQuorumForExecution: config.requireQuorumForExecution,
    },
    reviewers: [],
    approvals: 0,
    halts: 0,
    errors: 0,
    requiredApprovals: config.minApprovals,
    quorumReached: false,
    decision: "not_requested",
    summary: "AXL peer review is not configured for this run.",
    executionGate: "not_configured",
  };
}

function buildPeerReviewSummary(config, topology, reviewers) {
  const approvals = reviewers.filter(
    (reviewer) => reviewer.review?.recommendation === "approve",
  ).length;
  const halts = reviewers.filter(
    (reviewer) => reviewer.review?.recommendation === "halt",
  ).length;
  const errors = reviewers.filter((reviewer) => reviewer.status === "error").length;
  const requiredApprovals = Math.max(
    1,
    Math.min(config.minApprovals || 1, config.peers.length || 1),
  );
  const quorumReached = approvals >= requiredApprovals;
  const decision =
    halts > 0
      ? "halt"
      : quorumReached
        ? "approve"
        : errors === reviewers.length
          ? "degraded"
          : "insufficient_quorum";
  const executionGate = config.requireQuorumForExecution
    ? decision === "approve"
      ? "pass"
      : "block"
    : "advisory_only";

  let summary = `${approvals}/${reviewers.length} reviewer node(s) approved the first containment step over AXL.`;

  if (decision === "halt") {
    summary = "At least one AXL reviewer halted automation.";
  } else if (decision === "degraded") {
    summary = "AXL peer review could not reach any reviewer successfully.";
  } else if (decision === "insufficient_quorum") {
    summary = `AXL peer review returned ${approvals} approval(s), below the required quorum of ${requiredApprovals}.`;
  }

  return {
    provider: {
      name: "gensyn-axl",
      mode: config.mode,
      configured: true,
      apiBaseUrl: config.apiBaseUrl,
      service: config.service,
      peerCount: config.peers.length,
      ourPeerId: topology?.our_public_key ?? null,
      topologyError: topology?.error ?? null,
      requireQuorumForExecution: config.requireQuorumForExecution,
    },
    reviewers,
    approvals,
    halts,
    errors,
    requiredApprovals,
    quorumReached,
    decision,
    summary,
    executionGate,
  };
}

async function reviewIncidentWithPeers(
  incident,
  runbook,
  config = resolveAgentMeshConfig(),
) {
  if (config.mode !== "mcp" || config.peers.length === 0) {
    return buildDisabledSummary(config);
  }

  const topology = await fetchTopology(config);
  const reviewers = await Promise.all(
    config.peers.map((peerId) =>
      requestPeerReview(peerId, incident, runbook, config),
    ),
  );

  return buildPeerReviewSummary(config, topology, reviewers);
}

function shouldAllowExecution(peerReview, config) {
  if (config.mode !== "mcp" || !config.requireQuorumForExecution) {
    return true;
  }

  return peerReview.decision === "approve" && peerReview.quorumReached;
}

function buildPeerReviewBlockArtifact(peerReview, executionConfig) {
  return {
    provider: "safe",
    mode: executionConfig.mode,
    status: "blocked_by_peer_review",
    reason: peerReview.summary,
    peerReview: {
      decision: peerReview.decision,
      approvals: peerReview.approvals,
      requiredApprovals: peerReview.requiredApprovals,
      executionGate: peerReview.executionGate,
    },
  };
}

module.exports = {
  buildPeerReviewBlockArtifact,
  resolveAgentMeshConfig,
  reviewIncidentWithPeers,
  shouldAllowExecution,
};
