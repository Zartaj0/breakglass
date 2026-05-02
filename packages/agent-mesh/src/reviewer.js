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

    const aiConfig = options.aiConfig ?? null;
    const useAi = aiConfig && aiConfig.provider !== "disabled";

    if (useAi) {
      return reviewIncidentWithAI(args.incident, args.runbook, options).then((review) =>
        buildJsonRpcResponse(id, {
          content: [{ type: "text", text: JSON.stringify(review) }],
          structuredContent: review,
        }),
      );
    }

    const review = reviewIncidentAgainstRunbook(args.incident, args.runbook, options);
    return buildJsonRpcResponse(id, {
      content: [{ type: "text", text: JSON.stringify(review) }],
      structuredContent: review,
    });
  }

  return buildJsonRpcError(id, -32601, `Unsupported method: ${method}`);
}

// ---------------------------------------------------------------------------
// AI-powered review layer
// ---------------------------------------------------------------------------

const GEMINI_REVIEWER_URL = "https://generativelanguage.googleapis.com/v1beta/models";
const ANTHROPIC_REVIEWER_URL = "https://api.anthropic.com/v1/messages";
const REVIEWER_TIMEOUT_MS = 7000;

const NVIDIA_REVIEWER_URL = "https://integrate.api.nvidia.com/v1/chat/completions";

function resolveAiReviewerConfig(env = process.env) {
  return {
    geminiApiKey: env.GEMINI_API_KEY ?? null,
    geminiModel: env.GEMINI_MODEL ?? "gemini-2.5-flash",
    anthropicApiKey: env.ANTHROPIC_API_KEY ?? null,
    anthropicModel: env.ANTHROPIC_MODEL ?? "claude-haiku-4-5-20251001",
    nvidiaApiKey: env.NVIDIA ?? null,
    nvidiaModel: env.NVIDIA_MODEL ?? "meta/llama-3.1-8b-instruct",
    mistralApiKey: env.MISTRAL ?? null,
    mistralModel: env.MISTRAL_MODEL ?? "mistral-small-latest",
  };
}

function buildAiReviewPrompt(incident, runbook, deterministicReview) {
  const firstStep = runbook?.steps?.[0];
  const reasons = (incident?.evidence?.reasons ?? [])
    .map((r) => `  - ${r.code}: ${r.message}`)
    .join("\n");

  return `You are an independent security reviewer for a Safe multisig treasury wallet.

CONTEXT: BreakGlass has detected a suspicious pending transaction in the Safe queue. It has NOT been executed yet. The system wants to block it by proposing a rejection transaction at the same nonce.

INCIDENT DETAILS:
- Trigger: ${incident?.triggerType ?? "unknown"} (severity: ${incident?.severity ?? "unknown"})
- Safe: ${incident?.safeAddress} on ${incident?.network}
- Risk signals detected:\n${reasons || "  none"}

PROPOSED AUTOMATED RESPONSE:
Step: ${firstStep?.kind ?? "none"}
Action: ${firstStep?.description ?? ""}
Deterministic engine says: ${deterministicReview.recommendation.toUpperCase()}

YOUR TASK: Independently verify whether the automated response plan is correct.
- "approve" = the plan is sensible, go ahead with the containment
- "halt" = something is wrong with the plan, a human must review before proceeding

Respond with ONLY this JSON — no other text:
{"recommendation":"approve","confidence":0.88,"reasoning":"one sentence explaining your verdict","agreedWithDeterministic":true}

Note: approving a suspicious-approval containment plan means you agree the Safe should block this pending transaction. This is the correct response for unknown or risky approvals.`;
}

function parseAiReviewResponse(text) {
  if (!text) return null;
  try {
    const match = text.match(/\{[\s\S]*"recommendation"[\s\S]*\}/);
    if (!match) return null;
    return JSON.parse(match[0]);
  } catch {
    return null;
  }
}

async function callReviewerLlm(prompt, config) {
  const MISTRAL_URL = "https://api.mistral.ai/v1/chat/completions";

  const providers = [];
  if (config.geminiApiKey) {
    providers.push(async () => {
      const res = await fetch(`${GEMINI_REVIEWER_URL}/${config.geminiModel ?? "gemini-2.5-flash"}:generateContent`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-goog-api-key": config.geminiApiKey },
        body: JSON.stringify({ generationConfig: { temperature: 0.1, maxOutputTokens: 256 }, contents: [{ role: "user", parts: [{ text: prompt }] }] }),
        signal: AbortSignal.timeout(REVIEWER_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`Gemini ${res.status}`);
      const d = await res.json();
      return (d?.candidates?.[0]?.content?.parts ?? []).filter((p) => p.text).map((p) => p.text).join("").trim();
    });
  }
  if (config.anthropicApiKey) {
    providers.push(async () => {
      const res = await fetch(ANTHROPIC_REVIEWER_URL, {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": config.anthropicApiKey, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: config.anthropicModel ?? "claude-haiku-4-5-20251001", max_tokens: 256, messages: [{ role: "user", content: prompt }] }),
        signal: AbortSignal.timeout(REVIEWER_TIMEOUT_MS),
      });
      if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e?.error?.message ?? `Anthropic ${res.status}`); }
      const d = await res.json();
      return (d?.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("").trim();
    });
  }
  if (config.nvidiaApiKey) {
    providers.push(async () => {
      const res = await fetch(NVIDIA_REVIEWER_URL, {
        method: "POST",
        headers: { "content-type": "application/json", "authorization": `Bearer ${config.nvidiaApiKey}` },
        body: JSON.stringify({ model: config.nvidiaModel ?? "meta/llama-3.1-8b-instruct", max_tokens: 256, temperature: 0.1, messages: [{ role: "user", content: prompt }] }),
        signal: AbortSignal.timeout(REVIEWER_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`Nvidia ${res.status}`);
      const d = await res.json();
      return (d?.choices ?? []).map((c) => c.message?.content ?? "").join("").trim();
    });
  }
  if (config.mistralApiKey) {
    providers.push(async () => {
      const res = await fetch(MISTRAL_URL, {
        method: "POST",
        headers: { "content-type": "application/json", "authorization": `Bearer ${config.mistralApiKey}` },
        body: JSON.stringify({ model: config.mistralModel ?? "mistral-small-latest", max_tokens: 256, temperature: 0.1, messages: [{ role: "user", content: prompt }] }),
        signal: AbortSignal.timeout(REVIEWER_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`Mistral ${res.status}`);
      const d = await res.json();
      return d?.choices?.[0]?.message?.content?.trim() ?? null;
    });
  }

  for (const fn of providers) {
    try {
      const text = await fn();
      if (text) return text;
    } catch {
      // try next
    }
  }

  return null;
}

async function reviewIncidentWithAI(incident, runbook, options = {}) {
  const deterministicReview = reviewIncidentAgainstRunbook(incident, runbook, options);
  const aiConfig = options.aiConfig ?? resolveAiReviewerConfig({});

  if (aiConfig.provider === "disabled") {
    return deterministicReview;
  }

  try {
    const prompt = buildAiReviewPrompt(incident, runbook, deterministicReview);
    const rawText = await callReviewerLlm(prompt, aiConfig);
    const parsed = parseAiReviewResponse(rawText);

    if (!parsed) {
      return { ...deterministicReview, aiReasoning: rawText, aiProvider: aiConfig.provider, aiEnhanced: true };
    }

    const aiRecommendation = parsed.recommendation === "halt" ? "halt" : "approve";
    const finalRecommendation =
      aiRecommendation !== deterministicReview.recommendation
        ? "halt"
        : deterministicReview.recommendation;

    const reviewerLabel = toStringValue(options.reviewerLabel, "unnamed-reviewer");

    return {
      ...deterministicReview,
      recommendation: finalRecommendation,
      confidence: typeof parsed.confidence === "number"
        ? Math.min(1, Math.max(0, parsed.confidence))
        : deterministicReview.confidence,
      summary: parsed.reasoning
        ? `${reviewerLabel}: ${parsed.reasoning}`
        : deterministicReview.summary,
      aiReasoning: parsed.reasoning ?? null,
      aiProvider: aiConfig.provider,
      aiEnhanced: true,
      aiAgreedWithDeterministic: parsed.agreedWithDeterministic ?? null,
    };
  } catch {
    return { ...deterministicReview, aiReasoning: null, aiProvider: null, aiEnhanced: false };
  }
}

module.exports = {
  REVIEW_SERVICE_NAME,
  REVIEW_TOOL_NAME,
  REVIEW_VERSION,
  buildToolDefinition,
  handleReviewerRpc,
  reviewIncidentAgainstRunbook,
  reviewIncidentWithAI,
  resolveAiReviewerConfig,
};
