const {
  INCIDENT_SOURCE_STAGE,
  INCIDENT_TRIGGER_TYPES,
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
  const triggerType = incident?.triggerType;

  if (
    incident.sourceStage === INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION &&
    expectedFirstStepKind?.startsWith("invalidate_pending")
  ) {
    reasons.push({
      code: "pending_tx_requires_containment",
      message:
        "The transaction is still pending in the Safe queue, so blocking it before more owners sign is the correct first containment action.",
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

  if (triggerType === INCIDENT_TRIGGER_TYPES.SUSPICIOUS_APPROVAL && riskCodes.includes("unknown_spender")) {
    reasons.push({
      code: "unknown_spender_confirmed",
      message:
        "The approval targets a spender outside the configured allowlist.",
    });
  }

  if (triggerType === INCIDENT_TRIGGER_TYPES.SUSPICIOUS_APPROVAL && riskCodes.includes("unlimited_approval")) {
    reasons.push({
      code: "unlimited_approval_confirmed",
      message:
        "The approval amount is effectively unlimited, which materially raises urgency.",
    });
  }

  if (triggerType === INCIDENT_TRIGGER_TYPES.SUSPICIOUS_APPROVAL && riskCodes.includes("high_value_approval")) {
    reasons.push({
      code: "high_value_threshold_crossed",
      message:
        "The approval amount exceeds the configured risk threshold.",
      });
  }

  if (triggerType === INCIDENT_TRIGGER_TYPES.OWNERSHIP_CHANGE) {
    reasons.push({
      code: "ownership_change_requires_review",
      message:
        "Changing the Safe owner set alters treasury control, so rejecting the pending owner-set transaction is the safest first step.",
    });
  }

  if (triggerType === INCIDENT_TRIGGER_TYPES.THRESHOLD_REDUCTION) {
    reasons.push({
      code: "threshold_change_requires_review",
      message:
        "Lowering the Safe threshold weakens signature requirements, so blocking the pending threshold change is the correct first response.",
    });
  }

  if (triggerType === INCIDENT_TRIGGER_TYPES.MODULE_ENABLEMENT) {
    reasons.push({
      code: "module_enablement_requires_review",
      message:
        "Enabling a Safe module can grant unrestricted execution powers, so the pending enablement should be blocked first.",
    });
  }

  if (triggerType === INCIDENT_TRIGGER_TYPES.LARGE_TRANSFER) {
    reasons.push({
      code: "large_transfer_requires_review",
      message:
        "A large pending transfer should be blocked first so the destination and intent can be verified before funds move.",
    });
  }

  if (triggerType === INCIDENT_TRIGGER_TYPES.UNKNOWN_TRANSACTION) {
    reasons.push({
      code: "unknown_transaction_investigation_first",
      message:
        "This transaction did not match a deterministic incident class, so an investigation-first runbook is appropriate before any automated containment.",
    });
  }

  return reasons;
}

function resolveExpectedFirstStepKind(incident) {
  if (!incident) {
    return null;
  }

  switch (incident.triggerType) {
    case INCIDENT_TRIGGER_TYPES.SUSPICIOUS_APPROVAL:
      return incident.sourceStage === INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION
        ? "invalidate_pending_approval"
        : "revoke_approval";
    case INCIDENT_TRIGGER_TYPES.OWNERSHIP_CHANGE:
    case INCIDENT_TRIGGER_TYPES.THRESHOLD_REDUCTION:
    case INCIDENT_TRIGGER_TYPES.MODULE_ENABLEMENT:
    case INCIDENT_TRIGGER_TYPES.LARGE_TRANSFER:
      return "invalidate_pending_transaction";
    case INCIDENT_TRIGGER_TYPES.UNKNOWN_TRANSACTION:
      return "investigate_unknown_transaction";
    default:
      return null;
  }
}

function reviewIncidentAgainstRunbook(
  incident,
  runbook,
  options = {},
) {
  const reviewerLabel = toStringValue(options.reviewerLabel, "unnamed-reviewer");
  const reviewerId = toStringValue(options.reviewerId, "local-reviewer");
  const firstStep = runbook?.steps?.[0] ?? null;
  const expectedFirstStepKind = resolveExpectedFirstStepKind(incident);

  let recommendation = "approve";

  if (!incident || !runbook) {
    recommendation = "halt";
  } else if (!expectedFirstStepKind) {
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
        ? `${reviewerLabel} independently approved ${expectedFirstStepKind} as the correct first step for ${incident?.triggerType ?? "this incident"}.`
        : `${reviewerLabel} halted automation because the proposed first step did not match the deterministic incident-response rule.`,
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
    const useAi = aiConfig && hasReviewerLlmProvider(aiConfig);

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
const MISTRAL_REVIEWER_URL = "https://api.mistral.ai/v1/chat/completions";
const OPENROUTER_REVIEWER_URL = "https://openrouter.ai/api/v1/chat/completions";
const OPENROUTER_FREE_MODEL = "google/gemma-3-27b-it:free";

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
    openrouterApiKey: env.OPENROUTER ?? null,
    openrouterModels: (env.OPENROUTER_MODELS ?? OPENROUTER_FREE_MODEL)
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean),
  };
}

function hasReviewerLlmProvider(config = {}) {
  return Boolean(
    config.geminiApiKey ||
      config.anthropicApiKey ||
      config.nvidiaApiKey ||
      config.mistralApiKey ||
      config.openrouterApiKey,
  );
}

const TRIGGER_CONTEXT = {
  suspicious_approval: "A suspicious token approval is pending. The proposed response blocks it by invalidating the pending nonce.",
  ownership_change: "A pending ownership modification (add/remove/swap owner) was detected. The proposed response rejects the pending transaction before it can be signed by enough owners.",
  threshold_reduction: "A pending Safe threshold reduction was detected. The proposed response blocks it to prevent weakening the multisig signature requirement.",
  module_enablement: "A pending Safe module enablement was detected. Enabled modules can execute arbitrary transactions. The proposed response blocks the enablement.",
  large_transfer: "A large pending asset transfer was detected. The proposed response blocks it pending destination verification.",
  unknown_transaction: "A pending transaction that does not match any known attack class was detected. The investigation agent has assessed it. The proposed response routes it to human review before any signatures are added.",
};

function buildAiReviewPrompt(incident, runbook, deterministicReview) {
  const firstStep = runbook?.steps?.[0];
  const reasons = (incident?.evidence?.reasons ?? [])
    .map((r) => `  - ${r.code}: ${r.message}`)
    .join("\n");
  const triggerContext = TRIGGER_CONTEXT[incident?.triggerType] ?? "A suspicious Safe transaction was detected.";

  return `You are an independent security reviewer for a Safe multisig treasury wallet.

CONTEXT: ${triggerContext}

INCIDENT DETAILS:
- Incident class: ${incident?.triggerType ?? "unknown"} (severity: ${incident?.severity ?? "unknown"})
- Safe: ${incident?.safeAddress} on ${incident?.network}
- Risk signals:\n${reasons || "  none"}

PROPOSED RESPONSE PLAN:
First step: ${firstStep?.kind ?? "none"}
Description: ${firstStep?.description ?? ""}
Deterministic engine verdict: ${deterministicReview.recommendation.toUpperCase()}

YOUR TASK: Independently verify whether the proposed response plan is correct for this incident class.
- "approve" = the plan is the right response — proceed
- "halt" = the plan is incorrect or incomplete — a human must review before anything executes

Respond with ONLY this JSON — no other text:
{"recommendation":"approve","confidence":0.88,"reasoning":"one sentence explaining your verdict","agreedWithDeterministic":true}`;
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
      return {
        provider: "gemini",
        text: (d?.candidates?.[0]?.content?.parts ?? []).filter((p) => p.text).map((p) => p.text).join("").trim(),
      };
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
      return {
        provider: "anthropic",
        text: (d?.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("").trim(),
      };
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
      return {
        provider: "nvidia",
        text: (d?.choices ?? []).map((c) => c.message?.content ?? "").join("").trim(),
      };
    });
  }
  if (config.mistralApiKey) {
    providers.push(async () => {
      const res = await fetch(MISTRAL_REVIEWER_URL, {
        method: "POST",
        headers: { "content-type": "application/json", "authorization": `Bearer ${config.mistralApiKey}` },
        body: JSON.stringify({ model: config.mistralModel ?? "mistral-small-latest", max_tokens: 256, temperature: 0.1, messages: [{ role: "user", content: prompt }] }),
        signal: AbortSignal.timeout(REVIEWER_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`Mistral ${res.status}`);
      const d = await res.json();
      return {
        provider: "mistral",
        text: d?.choices?.[0]?.message?.content?.trim() ?? null,
      };
    });
  }
  if (config.openrouterApiKey) {
    for (const model of config.openrouterModels ?? [OPENROUTER_FREE_MODEL]) {
      providers.push(async () => {
        const res = await fetch(OPENROUTER_REVIEWER_URL, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "authorization": `Bearer ${config.openrouterApiKey}`,
            "http-referer": "https://breakglass.xyz",
          },
          body: JSON.stringify({
            model,
            max_tokens: 256,
            temperature: 0.1,
            messages: [{ role: "user", content: prompt }],
          }),
          signal: AbortSignal.timeout(REVIEWER_TIMEOUT_MS),
        });
        if (!res.ok) throw new Error(`OpenRouter ${res.status}`);
        const d = await res.json();
        if (d.error) throw new Error(d.error.message ?? "OpenRouter error");
        return {
          provider: "openrouter",
          text: d?.choices?.[0]?.message?.content?.trim() ?? null,
        };
      });
    }
  }

  for (const fn of providers) {
    try {
      const result = await fn();
      if (result?.text) return result;
    } catch {
      // try next
    }
  }

  return null;
}

async function reviewIncidentWithAI(incident, runbook, options = {}) {
  const deterministicReview = reviewIncidentAgainstRunbook(incident, runbook, options);
  const aiConfig = options.aiConfig ?? resolveAiReviewerConfig({});

  if (!hasReviewerLlmProvider(aiConfig)) {
    return {
      ...deterministicReview,
      aiReasoning: null,
      aiProvider: null,
      aiEnhanced: false,
    };
  }

  try {
    const prompt = buildAiReviewPrompt(incident, runbook, deterministicReview);
    const llmResult = await callReviewerLlm(prompt, aiConfig);
    const rawText = llmResult?.text ?? null;
    const parsed = parseAiReviewResponse(rawText);
    const aiProvider = llmResult?.provider ?? null;

    if (!parsed) {
      return {
        ...deterministicReview,
        aiReasoning: rawText,
        aiProvider,
        aiEnhanced: Boolean(rawText),
      };
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
      aiProvider,
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
