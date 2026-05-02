const {
  INCIDENT_SOURCE_STAGE,
  asArray,
  toStringValue,
} = require("../../shared/src/models");

const REVIEW_SERVICE_NAME = "breakglass-review";
const REVIEW_TOOL_NAME = "review_incident";
const REVIEW_VERSION = "breakglass-review-v1";

function buildJsonRpcResponse(id, result) {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    result,
  };
}

function buildJsonRpcError(id, code, message) {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    error: {
      code,
      message,
    },
  };
}

function calculateConfidence(recommendation, incident, agreedFirstStep) {
  if (recommendation !== "approve") {
    return 0.2;
  }

  if (!agreedFirstStep) {
    return 0.35;
  }

  if (incident.severity === "critical") {
    return 0.96;
  }

  if (incident.severity === "high") {
    return 0.88;
  }

  return 0.72;
}

function buildReviewReasons(incident, firstStep, expectedFirstStepKind) {
  const reasons = [];
  const riskSignals = asArray(incident.evidence?.reasons);
  const riskCodes = riskSignals.map((signal) => signal.code);

  if (incident.sourceStage === INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION) {
    reasons.push({
      code: "pending_tx_requires_nonce_rejection",
      message:
        "The approval is still pending in the Safe queue, so invalidating that nonce is the correct first containment action.",
    });
  }

  if (firstStep?.kind === expectedFirstStepKind) {
    reasons.push({
      code: "first_step_matches_containment_rule",
      message: `The proposed first step matches the deterministic ${expectedFirstStepKind} containment rule.`,
    });
  } else {
    reasons.push({
      code: "first_step_mismatch",
      message: `The runbook starts with ${firstStep?.kind ?? "no step"}, but ${expectedFirstStepKind} was expected.`,
    });
  }

  if (riskCodes.includes("unknown_spender")) {
    reasons.push({
      code: "unknown_spender_confirmed",
      message:
        "The approval targets a spender outside the configured allowlist.",
    });
  }

  if (riskCodes.includes("unlimited_approval")) {
    reasons.push({
      code: "unlimited_approval_confirmed",
      message:
        "The approval amount is effectively unlimited, which materially raises urgency.",
    });
  }

  if (riskCodes.includes("high_value_approval")) {
    reasons.push({
      code: "high_value_threshold_crossed",
      message:
        "The approval amount exceeds the configured risk threshold.",
    });
  }

  return reasons;
}

function reviewIncidentAgainstRunbook(
  incident,
  runbook,
  options = {},
) {
  const reviewerLabel = toStringValue(options.reviewerLabel, "unnamed-reviewer");
  const reviewerId = toStringValue(options.reviewerId, "local-reviewer");
  const firstStep = runbook?.steps?.[0] ?? null;
  const expectedFirstStepKind =
    incident?.sourceStage === INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION
      ? "invalidate_pending_approval"
      : "revoke_approval";

  let recommendation = "approve";

  if (!incident || !runbook) {
    recommendation = "halt";
  } else if (incident.triggerType !== "suspicious_approval") {
    recommendation = "halt";
  } else if (!firstStep) {
    recommendation = "halt";
  } else if (firstStep.kind !== expectedFirstStepKind) {
    recommendation = "halt";
  }

  const reasons = buildReviewReasons(incident, firstStep, expectedFirstStepKind);
  const agreedFirstStep = firstStep?.kind === expectedFirstStepKind;
  const confidence = calculateConfidence(
    recommendation,
    incident ?? {},
    agreedFirstStep,
  );

  return {
    reviewVersion: REVIEW_VERSION,
    reviewerId,
    reviewerLabel,
    recommendation,
    confidence,
    agreedSeverity: incident?.severity ?? null,
    firstStepKind: firstStep?.kind ?? null,
    expectedFirstStepKind,
    agreedFirstStep,
    riskCodes: asArray(incident?.evidence?.reasons).map((reason) => reason.code),
    reasons,
    summary:
      recommendation === "approve"
        ? `${reviewerLabel} independently approved ${expectedFirstStepKind} as the first containment step.`
        : `${reviewerLabel} halted automation because the proposed first step did not match the deterministic containment rule.`,
    generatedAt: new Date().toISOString(),
  };
}

function buildToolDefinition() {
  return {
    name: REVIEW_TOOL_NAME,
    description:
      "Independently review a BreakGlass incident and proposed runbook before treasury mitigation executes.",
    inputSchema: {
      type: "object",
      properties: {
        incident: {
          type: "object",
          description: "Normalized BreakGlass incident object.",
        },
        runbook: {
          type: "object",
          description: "Compiled deterministic BreakGlass runbook.",
        },
      },
      required: ["incident", "runbook"],
    },
  };
}

function handleReviewerRpc(requestBody, options = {}) {
  const method = requestBody?.method;
  const id = requestBody?.id ?? null;

  if (method === "tools/list") {
    return buildJsonRpcResponse(id, {
      tools: [buildToolDefinition()],
    });
  }

  if (method === "tools/call") {
    const toolName = requestBody?.params?.name;

    if (toolName !== REVIEW_TOOL_NAME) {
      return buildJsonRpcError(id, -32601, `Unknown tool: ${toolName}`);
    }

    const args = requestBody?.params?.arguments ?? {};

    if (!args.incident || !args.runbook) {
      return buildJsonRpcError(
        id,
        -32602,
        "review_incident requires incident and runbook arguments.",
      );
    }

    const review = reviewIncidentAgainstRunbook(
      args.incident,
      args.runbook,
      options,
    );

    return buildJsonRpcResponse(id, {
      content: [
        {
          type: "text",
          text: JSON.stringify(review),
        },
      ],
      structuredContent: review,
    });
  }

  return buildJsonRpcError(id, -32601, `Unsupported method: ${method}`);
}

module.exports = {
  REVIEW_SERVICE_NAME,
  REVIEW_TOOL_NAME,
  REVIEW_VERSION,
  buildToolDefinition,
  handleReviewerRpc,
  reviewIncidentAgainstRunbook,
};
