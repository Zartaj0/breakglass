const ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_MODEL = "claude-haiku-4-5-20251001";
const GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models";
const GEMINI_MODEL = "gemini-2.5-flash";
const OLLAMA_API_URL = "http://127.0.0.1:11434/api/generate";
const OLLAMA_MODEL = "gemma3:4b";
const BRIEF_MAX_TOKENS = 250;
const DEFAULT_BRIEF_TIMEOUT_MS = 20_000;

const INCIDENT_TYPE_CONTEXT = {
  suspicious_approval: "a token spending approval that grants an external address permission to move tokens from the Safe",
  ownership_change: "a modification to who controls the Safe — adding, removing, or swapping a signing owner",
  threshold_reduction: "a reduction in the number of signatures required to execute transactions from the Safe",
  module_enablement: "the activation of a Smart contract module that can execute transactions on behalf of the Safe without owner signatures",
  large_transfer: "a transfer of a significant amount of assets out of the Safe to an external address",
};

function buildBriefPrompt(incident, runbook) {
  const incidentContext = INCIDENT_TYPE_CONTEXT[incident.triggerType] ?? "a potentially risky transaction";
  const firstStep = runbook?.steps?.[0];
  const riskCodes = (incident.evidence?.reasons ?? []).map((r) => r.code).join(", ");
  const severity = incident.severity?.toUpperCase() ?? "UNKNOWN";

  return `You are a treasury security assistant. A Safe multisig wallet has a ${severity} severity incident.

The pending transaction is ${incidentContext}.

Key facts:
- Safe address: ${incident.safeAddress}
- Network: ${incident.network}
- Severity: ${severity}
- Risk signals: ${riskCodes || "none specified"}
- Incident summary: ${incident.summary}
- First containment step: ${firstStep?.description ?? "none"}

Write exactly 3 short sentences (no headers, no bullet points):
1. What this transaction would do in plain English
2. Why it is risky for the treasury
3. What the Safe owners should do right now

Be direct. Use plain language. Do not use jargon. Do not add disclaimers.`;
}

function buildBriefResult({
  provider,
  configured,
  text = null,
  error = null,
}) {
  return {
    provider,
    configured,
    text,
    error,
  };
}

function resolveBriefConfig(input = process.env) {
  if (typeof input === "string") {
    return {
      provider: "anthropic",
      anthropicApiKey: input,
      anthropicModel: ANTHROPIC_MODEL,
      geminiApiKey: null,
      geminiModel: GEMINI_MODEL,
      ollamaApiUrl: OLLAMA_API_URL,
      ollamaModel: OLLAMA_MODEL,
      timeoutMs: DEFAULT_BRIEF_TIMEOUT_MS,
    };
  }

  const provider = String(input.AI_BRIEF_PROVIDER ?? "").trim().toLowerCase();
  const inferredProvider =
    provider ||
    (input.GEMINI_API_KEY ? "gemini" : "") ||
    (input.ANTHROPIC_API_KEY ? "anthropic" : "") ||
    (input.OLLAMA_MODEL || input.OLLAMA_BASE_URL ? "ollama" : "") ||
    "disabled";

  return {
    provider: inferredProvider,
    anthropicApiKey: input.ANTHROPIC_API_KEY ?? null,
    anthropicModel: input.ANTHROPIC_MODEL ?? ANTHROPIC_MODEL,
    geminiApiKey: input.GEMINI_API_KEY ?? null,
    geminiModel: input.GEMINI_MODEL ?? GEMINI_MODEL,
    ollamaApiUrl: input.OLLAMA_BASE_URL ?? OLLAMA_API_URL,
    ollamaModel: input.OLLAMA_MODEL ?? OLLAMA_MODEL,
    timeoutMs: Number(input.AI_BRIEF_TIMEOUT_MS ?? DEFAULT_BRIEF_TIMEOUT_MS),
  };
}

async function generateAnthropicBrief(incident, runbook, config) {
  if (!config.anthropicApiKey) {
    return buildBriefResult({
      provider: "anthropic",
      configured: false,
      error: "ANTHROPIC_API_KEY is not configured.",
    });
  }

  try {
    const response = await fetch(ANTHROPIC_API_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": config.anthropicApiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: config.anthropicModel,
        max_tokens: BRIEF_MAX_TOKENS,
        messages: [
          {
            role: "user",
            content: buildBriefPrompt(incident, runbook),
          },
        ],
      }),
      signal: AbortSignal.timeout(config.timeoutMs),
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      return buildBriefResult({
        provider: "anthropic",
        configured: true,
        error:
          payload?.error?.message ??
          `Anthropic API returned ${response.status}.`,
      });
    }

    const data = await response.json();
    return buildBriefResult({
      provider: "anthropic",
      configured: true,
      text: data?.content?.[0]?.text?.trim() ?? null,
      error: data?.content?.[0]?.text?.trim() ? null : "Anthropic returned an empty brief.",
    });
  } catch (error) {
    return buildBriefResult({
      provider: "anthropic",
      configured: true,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

async function generateGeminiBrief(incident, runbook, config) {
  if (!config.geminiApiKey) {
    return buildBriefResult({
      provider: "gemini",
      configured: false,
      error: "GEMINI_API_KEY is not configured.",
    });
  }

  try {
    const response = await fetch(
      `${GEMINI_API_URL}/${config.geminiModel}:generateContent`,
      {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-goog-api-key": config.geminiApiKey,
      },
      body: JSON.stringify({
        generationConfig: {
          maxOutputTokens: BRIEF_MAX_TOKENS,
          temperature: 0.2,
        },
        contents: [
          {
            role: "user",
            parts: [
              {
                text: buildBriefPrompt(incident, runbook),
              },
            ],
          },
        ],
      }),
      signal: AbortSignal.timeout(config.timeoutMs),
      },
    );

    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      return buildBriefResult({
        provider: "gemini",
        configured: true,
        error:
          payload?.error?.message ??
          `Gemini API returned ${response.status}.`,
      });
    }

    const data = await response.json();
    const text = data?.candidates?.[0]?.content?.parts?.map((part) => part?.text ?? "").join("").trim() ?? null;
    return buildBriefResult({
      provider: "gemini",
      configured: true,
      text,
      error: text ? null : "Gemini returned an empty brief.",
    });
  } catch (error) {
    return buildBriefResult({
      provider: "gemini",
      configured: true,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

async function generateOllamaBrief(incident, runbook, config) {
  try {
    const response = await fetch(config.ollamaApiUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: config.ollamaModel,
        prompt: buildBriefPrompt(incident, runbook),
        stream: false,
      }),
      signal: AbortSignal.timeout(config.timeoutMs),
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      return buildBriefResult({
        provider: "ollama",
        configured: true,
        error:
          payload?.error ??
          `Ollama API returned ${response.status}.`,
      });
    }

    const data = await response.json();
    const text = data?.response?.trim() ?? null;
    return buildBriefResult({
      provider: "ollama",
      configured: true,
      text,
      error: text ? null : "Ollama returned an empty brief.",
    });
  } catch (error) {
    return buildBriefResult({
      provider: "ollama",
      configured: true,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

function buildFallbackChain(config) {
  const chain = [];
  if (config.provider === "gemini" || config.geminiApiKey) {
    chain.push((i, r) => generateGeminiBrief(i, r, config));
  }
  if (config.anthropicApiKey) {
    chain.push((i, r) => generateAnthropicBrief(i, r, config));
  }
  if (config.ollamaModel) {
    chain.push((i, r) => generateOllamaBrief(i, r, config));
  }
  return chain;
}

async function generateIncidentBrief(incident, runbook, configInput) {
  const config = resolveBriefConfig(configInput);

  if (config.provider === "disabled") {
    return buildBriefResult({
      provider: "disabled",
      configured: false,
      error: "No AI brief provider is configured.",
    });
  }

  // For non-gemini providers, use direct dispatch (no fallback needed)
  if (config.provider === "anthropic") {
    return generateAnthropicBrief(incident, runbook, config);
  }
  if (config.provider === "ollama") {
    return generateOllamaBrief(incident, runbook, config);
  }

  // For gemini (or when gemini is inferred), cascade through available providers
  const chain = buildFallbackChain(config);
  if (chain.length === 0) {
    return buildBriefResult({ provider: "disabled", configured: false, error: "No provider configured." });
  }

  let lastResult = null;
  for (const attempt of chain) {
    const result = await attempt(incident, runbook);
    if (result.text) return result;
    lastResult = result;
  }
  return lastResult;
}

module.exports = { generateIncidentBrief, resolveBriefConfig };
