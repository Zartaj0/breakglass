const { SAFE_API_CHAIN_SLUGS } = require("../../integrations/src/safe-client");

const GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models";
const ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages";
const NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions";
const MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions";
const OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions";

const MAX_AGENT_TURNS = 4;
const TOOL_TIMEOUT_MS = 2000;
const TOTAL_TIMEOUT_MS = 9000;

// ---------------------------------------------------------------------------
// Tool definitions (provider-agnostic shape, adapted per provider below)
// ---------------------------------------------------------------------------

const TOOL_SCHEMAS = [
  {
    name: "get_safe_info",
    description:
      "Fetch current Safe wallet details: owner count, threshold, enabled modules, and nonce. Use this to understand how the Safe is configured.",
    parameters: {
      type: "object",
      properties: {
        safeAddress: { type: "string", description: "Checksummed Safe address." },
        network: { type: "string", description: "Network name, e.g. base-sepolia, ethereum, arbitrum." },
      },
      required: ["safeAddress", "network"],
    },
  },
  {
    name: "check_address_type",
    description:
      "Check whether an address is a verified smart contract, an unverified contract, or an externally owned account (EOA). Helps assess whether the counterparty is a known protocol.",
    parameters: {
      type: "object",
      properties: {
        address: { type: "string", description: "Address to check." },
        network: { type: "string", description: "Network the address lives on." },
      },
      required: ["address", "network"],
    },
  },
  {
    name: "get_token_metadata",
    description:
      "Fetch ERC-20 token name, symbol, and decimals for a contract address. Use this to identify what asset is involved in a transfer or approval.",
    parameters: {
      type: "object",
      properties: {
        tokenAddress: { type: "string", description: "ERC-20 token contract address." },
        network: { type: "string", description: "Network the token lives on." },
      },
      required: ["tokenAddress", "network"],
    },
  },
  {
    name: "get_recent_safe_activity",
    description:
      "Fetch the last few executed transactions from this Safe to understand its normal activity patterns and whether this counterparty has appeared before.",
    parameters: {
      type: "object",
      properties: {
        safeAddress: { type: "string", description: "Safe address to query." },
        network: { type: "string", description: "Network name." },
        limit: { type: "number", description: "Number of recent transactions to fetch (1-10)." },
      },
      required: ["safeAddress", "network"],
    },
  },
];

// ---------------------------------------------------------------------------
// Tool execution
// ---------------------------------------------------------------------------

function safeApiBaseUrl(network) {
  const slug = SAFE_API_CHAIN_SLUGS[network] ?? network;
  return `https://api.safe.global/tx-service/${slug}/api/v2`;
}

async function toolGetSafeInfo({ safeAddress, network }, apiKey) {
  const url = `${safeApiBaseUrl(network)}/safes/${safeAddress}/`;
  const headers = { Accept: "application/json" };
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;

  const res = await fetch(url, {
    headers,
    signal: AbortSignal.timeout(TOOL_TIMEOUT_MS),
  });

  if (!res.ok) return { error: `Safe API returned ${res.status}` };

  const d = await res.json();
  return {
    threshold: d.threshold,
    ownerCount: d.owners?.length ?? 0,
    nonce: d.nonce,
    moduleCount: d.modules?.length ?? 0,
    modules: (d.modules ?? []).slice(0, 3),
    guard: d.guard ?? null,
  };
}

async function toolCheckAddressType({ address, network }, apiKey) {
  const url = `${safeApiBaseUrl(network)}/contracts/${address}/`;
  const headers = { Accept: "application/json" };
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;

  try {
    const res = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(TOOL_TIMEOUT_MS),
    });

    if (res.status === 404) {
      return { type: "unverified_or_eoa", verified: false, name: null };
    }

    if (!res.ok) return { type: "unknown", verified: false, error: `API ${res.status}` };

    const d = await res.json();
    return {
      type: d.contractAbi ? "verified_contract" : "unverified_contract",
      verified: Boolean(d.contractAbi),
      name: d.displayName ?? d.name ?? null,
      trustedForDelegateCall: d.trustedForDelegateCall ?? false,
    };
  } catch {
    return { type: "unknown", verified: false };
  }
}

async function toolGetTokenMetadata({ tokenAddress, network }, apiKey) {
  const url = `${safeApiBaseUrl(network)}/tokens/${tokenAddress}/`;
  const headers = { Accept: "application/json" };
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;

  try {
    const res = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(TOOL_TIMEOUT_MS),
    });

    if (!res.ok) return { error: `Token API ${res.status}`, symbol: null, name: null };

    const d = await res.json();
    return {
      name: d.name ?? null,
      symbol: d.symbol ?? null,
      decimals: d.decimals ?? null,
      logoUri: d.logoUri ?? null,
    };
  } catch {
    return { error: "timeout or network error", symbol: null, name: null };
  }
}

async function toolGetRecentSafeActivity({ safeAddress, network, limit = 5 }, apiKey) {
  const cap = Math.min(Math.max(1, limit), 10);
  const url = `${safeApiBaseUrl(network)}/safes/${safeAddress}/multisig-transactions/?executed=true&limit=${cap}&ordering=-nonce`;
  const headers = { Accept: "application/json" };
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;

  try {
    const res = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(TOOL_TIMEOUT_MS),
    });

    if (!res.ok) return { count: 0, transactions: [], error: `API ${res.status}` };

    const d = await res.json();
    const txs = (d.results ?? []).slice(0, cap).map((tx) => ({
      method: tx.dataDecoded?.method ?? (tx.data ? "unknown" : "transfer"),
      to: tx.to,
      nonce: tx.nonce,
      executionDate: tx.executionDate ?? null,
    }));
    return { count: d.count ?? txs.length, recentTransactions: txs };
  } catch {
    return { count: 0, transactions: [], error: "timeout or network error" };
  }
}

async function executeTool(name, args, config) {
  const start = Date.now();
  let result;
  try {
    if (name === "get_safe_info") result = await toolGetSafeInfo(args, config.safeApiKey);
    else if (name === "check_address_type") result = await toolCheckAddressType(args, config.safeApiKey);
    else if (name === "get_token_metadata") result = await toolGetTokenMetadata(args, config.tokenAddress ?? args.tokenAddress, config.safeApiKey);
    else if (name === "get_recent_safe_activity") result = await toolGetRecentSafeActivity(args, config.safeApiKey);
    else result = { error: `Unknown tool: ${name}` };
  } catch (err) {
    result = { error: err instanceof Error ? err.message : String(err) };
  }
  return { tool: name, result, durationMs: Date.now() - start };
}

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

function buildSystemPrompt(incident) {
  return `You are a blockchain security agent. A Safe multisig wallet has a suspicious pending transaction that needs investigation.

You MUST call at least 2 tools to gather on-chain evidence before giving your assessment. Do not skip tool calls.

Suggested investigation order:
1. Call get_safe_info to understand the wallet configuration
2. Call check_address_type on the suspicious counterparty address
3. Call get_token_metadata if this is a token approval or transfer
4. Call get_recent_safe_activity to check if this counterparty has appeared before

After calling tools, respond with ONLY this JSON object (no other text, no markdown):
{"verdict":"HALT","riskLevel":"critical","keyFindings":["finding1","finding2"],"operatorRecommendation":"one sentence"}

Verdict options: HALT (block immediately), INVESTIGATE (needs human review), APPROVE (appears safe).
Severity: critical, high, medium, or low.`;
}

function buildIncidentMessage(incident) {
  const evidence = incident.evidence ?? {};
  const reasons = (evidence.reasons ?? []).map((r) => `- ${r.code}: ${r.message}`).join("\n");

  return `Investigate this incident:
Title: ${incident.title}
Summary: ${incident.summary}
Trigger type: ${incident.triggerType}
Severity: ${incident.severity}
Safe address: ${incident.safeAddress}
Network: ${incident.network}

Risk signals detected:
${reasons || "none"}

Transaction details:
${JSON.stringify(evidence.transaction ?? {}, null, 2)}

${evidence.approval ? `Approval evidence:\n${JSON.stringify(evidence.approval, null, 2)}` : ""}
${evidence.transfer ? `Transfer evidence:\n${JSON.stringify(evidence.transfer, null, 2)}` : ""}
${evidence.ownership ? `Ownership evidence:\n${JSON.stringify(evidence.ownership, null, 2)}` : ""}`;
}

function parseVerdict(text) {
  if (!text) return null;
  try {
    const match = text.match(/\{[\s\S]*"verdict"[\s\S]*\}/);
    if (!match) return null;
    return JSON.parse(match[0]);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Gemini multi-turn investigation
// ---------------------------------------------------------------------------

function buildGeminiToolDeclarations() {
  return TOOL_SCHEMAS.map((t) => ({
    name: t.name,
    description: t.description,
    parameters: t.parameters,
  }));
}

async function runGeminiInvestigation(incident, config) {
  const model = config.geminiModel ?? "gemini-2.5-flash";
  const url = `${GEMINI_API_URL}/${model}:generateContent`;

  const contents = [
    {
      role: "user",
      parts: [{ text: buildSystemPrompt(incident) + "\n\n" + buildIncidentMessage(incident) }],
    },
  ];

  const toolCalls = [];
  const controller = new AbortController();
  const totalTimer = setTimeout(() => controller.abort(), TOTAL_TIMEOUT_MS);

  try {
    for (let turn = 0; turn < MAX_AGENT_TURNS; turn++) {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-goog-api-key": config.geminiApiKey,
        },
        body: JSON.stringify({
          tools: [{ functionDeclarations: buildGeminiToolDeclarations() }],
          generationConfig: { temperature: 0.1, maxOutputTokens: 600 },
          contents,
        }),
        signal: controller.signal,
      });

      if (!res.ok) {
        const err = await res.text();
        throw new Error(`Gemini API ${res.status}: ${err.slice(0, 200)}`);
      }

      const data = await res.json();
      const candidate = data?.candidates?.[0];
      const parts = candidate?.content?.parts ?? [];

      // Check if the model made tool calls
      const funcCalls = parts.filter((p) => p.functionCall);
      const textParts = parts.filter((p) => p.text);

      if (funcCalls.length === 0) {
        // Model gave a final text response
        const text = textParts.map((p) => p.text).join("").trim();
        return { text, toolCalls };
      }

      // Execute each tool call
      contents.push({ role: "model", parts });
      const functionResponses = [];

      for (const part of funcCalls) {
        const { name, args } = part.functionCall;
        const result = await executeTool(name, args, config);
        toolCalls.push(result);
        functionResponses.push({
          functionResponse: {
            name,
            response: result.result,
          },
        });
      }

      contents.push({ role: "user", parts: functionResponses });
    }

    // Hit turn limit — ask for final answer
    contents.push({
      role: "user",
      parts: [{ text: "Based on your investigation, provide your final JSON assessment now." }],
    });

    const finalRes = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-goog-api-key": config.geminiApiKey,
      },
      body: JSON.stringify({
        generationConfig: { temperature: 0.1, maxOutputTokens: 400 },
        contents,
      }),
      signal: controller.signal,
    });

    if (!finalRes.ok) throw new Error(`Gemini final call ${finalRes.status}`);
    const finalData = await finalRes.json();
    const text = (finalData?.candidates?.[0]?.content?.parts ?? [])
      .filter((p) => p.text)
      .map((p) => p.text)
      .join("")
      .trim();

    return { text, toolCalls };
  } finally {
    clearTimeout(totalTimer);
  }
}

// ---------------------------------------------------------------------------
// Anthropic multi-turn investigation
// ---------------------------------------------------------------------------

function buildAnthropicTools() {
  return TOOL_SCHEMAS.map((t) => ({
    name: t.name,
    description: t.description,
    input_schema: t.parameters,
  }));
}

async function runAnthropicInvestigation(incident, config) {
  const model = config.anthropicModel ?? "claude-haiku-4-5-20251001";
  const messages = [
    { role: "user", content: buildIncidentMessage(incident) },
  ];

  const toolCalls = [];
  const controller = new AbortController();
  const totalTimer = setTimeout(() => controller.abort(), TOTAL_TIMEOUT_MS);

  try {
    for (let turn = 0; turn < MAX_AGENT_TURNS; turn++) {
      const res = await fetch(ANTHROPIC_API_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": config.anthropicApiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model,
          max_tokens: 1024,
          system: buildSystemPrompt(incident),
          tools: buildAnthropicTools(),
          messages,
        }),
        signal: controller.signal,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err?.error?.message ?? `Anthropic API ${res.status}`);
      }

      const data = await res.json();
      const content = data.content ?? [];

      messages.push({ role: "assistant", content });

      if (data.stop_reason === "end_turn") {
        const text = content
          .filter((c) => c.type === "text")
          .map((c) => c.text)
          .join("")
          .trim();
        return { text, toolCalls };
      }

      // Handle tool_use blocks
      const useBlocks = content.filter((c) => c.type === "tool_use");
      if (useBlocks.length === 0) {
        const text = content.filter((c) => c.type === "text").map((c) => c.text).join("").trim();
        return { text, toolCalls };
      }

      const toolResults = [];
      for (const block of useBlocks) {
        const result = await executeTool(block.name, block.input, config);
        toolCalls.push(result);
        toolResults.push({
          type: "tool_result",
          tool_use_id: block.id,
          content: JSON.stringify(result.result),
        });
      }

      messages.push({ role: "user", content: toolResults });
    }

    return { text: "", toolCalls };
  } finally {
    clearTimeout(totalTimer);
  }
}

// ---------------------------------------------------------------------------
// Config resolution
// ---------------------------------------------------------------------------


function resolveInvestigatorConfig(input = process.env) {
  if (typeof input === "string") {
    return {
      anthropicApiKey: input,
      anthropicModel: "claude-haiku-4-5-20251001",
      geminiApiKey: null,
      geminiModel: "gemini-2.5-flash",
      nvidiaApiKey: null,
      nvidiaModel: "meta/llama-3.1-8b-instruct",
      mistralApiKey: null,
      mistralModel: "mistral-small-latest",
      openrouterApiKey: null,
      openrouterModels: ["google/gemma-3-27b-it:free"],
      safeApiKey: null,
    };
  }

  return {
    anthropicApiKey: input.ANTHROPIC_API_KEY ?? null,
    anthropicModel: input.ANTHROPIC_MODEL ?? "claude-haiku-4-5-20251001",
    geminiApiKey: input.GEMINI_API_KEY ?? null,
    geminiModel: input.GEMINI_MODEL ?? "gemini-2.5-flash",
    nvidiaApiKey: input.NVIDIA ?? null,
    nvidiaModel: input.NVIDIA_MODEL ?? "meta/llama-3.1-8b-instruct",
    mistralApiKey: input.MISTRAL ?? null,
    mistralModel: input.MISTRAL_MODEL ?? "mistral-small-latest",
    openrouterApiKey: input.OPENROUTER ?? null,
    openrouterModels: (input.OPENROUTER_MODELS ?? "google/gemma-3-27b-it:free").split(",").map((s) => s.trim()),
    safeApiKey: input.SAFE_API_KEY ?? null,
  };
}

function buildProviderChain(config) {
  const chain = [];
  if (config.geminiApiKey) {
    chain.push({ name: "gemini", call: (p) => callGeminiSimple(p, config) });
  }
  if (config.anthropicApiKey) {
    chain.push({ name: "anthropic", call: (p) => callAnthropicSimple(p, config) });
  }
  if (config.nvidiaApiKey) {
    chain.push({ name: "nvidia", call: (p) => callNvidiaSimple(p, config) });
  }
  if (config.mistralApiKey) {
    chain.push({ name: "mistral", call: (p) => callMistralSimple(p, config) });
  }
  if (config.openrouterApiKey) {
    for (const model of config.openrouterModels ?? []) {
      chain.push({ name: "openrouter", call: (p) => callOpenRouterSimple(p, { ...config, openrouterModel: model }) });
    }
  }
  return chain;
}

function buildDeterministicFallback(incident, runbook) {
  const firstStep = runbook?.steps?.[0];
  const reasons = (incident?.evidence?.reasons ?? []).map((r) => r.message).filter(Boolean);
  const verdict = incident?.severity === "critical" || incident?.severity === "high" ? "HALT" : "INVESTIGATE";

  return {
    provider: "deterministic",
    configured: false,
    verdict,
    riskLevel: incident?.severity ?? "medium",
    keyFindings: reasons.length > 0 ? reasons.slice(0, 3) : [incident?.summary ?? "Incident detected."],
    operatorRecommendation: firstStep
      ? `Review the incident and consider: ${firstStep.description}`
      : "Review the incident manually before approving any actions.",
    toolCalls: [],
    text: incident?.summary ?? "",
    error: null,
  };
}

function buildResult({ provider, text, toolCalls, error, incident }) {
  const verdict = parseVerdict(text);

  if (!verdict) {
    // Couldn't parse structured JSON — extract what we can from the text
    const isHalt = /halt|block|reject|suspicious|dangerous/i.test(text);
    return {
      provider,
      configured: true,
      verdict: isHalt ? "HALT" : "INVESTIGATE",
      riskLevel: incident?.severity ?? "high",
      keyFindings: text ? [text.slice(0, 300)] : ["Investigation completed."],
      operatorRecommendation: "Review the incident manually before approving any actions.",
      toolCalls,
      text: text ?? "",
      error: error ?? null,
    };
  }

  return {
    provider,
    configured: true,
    verdict: verdict.verdict ?? "INVESTIGATE",
    riskLevel: verdict.riskLevel ?? incident?.severity ?? "high",
    keyFindings: Array.isArray(verdict.keyFindings) ? verdict.keyFindings : [],
    operatorRecommendation: verdict.operatorRecommendation ?? "",
    toolCalls,
    text: verdict.operatorRecommendation ?? verdict.keyFindings?.[0] ?? text ?? "",
    error: error ?? null,
  };
}

// ---------------------------------------------------------------------------
// Gather-then-reason: pre-fetch context, then ask the LLM to reason
// Works with any model — no native tool-use capability required
// ---------------------------------------------------------------------------

async function gatherInvestigationContext(incident, config) {
  const toolCalls = [];

  const run = async (name, args) => {
    const result = await executeTool(name, args, config);
    toolCalls.push(result);
    return result.result;
  };

  const safeInfo = await run("get_safe_info", {
    safeAddress: incident.safeAddress,
    network: incident.network,
  }).catch(() => null);

  const counterparty =
    incident.evidence?.approval?.spender ||
    incident.evidence?.transfer?.recipient ||
    incident.evidence?.ownership?.affectedOwner ||
    incident.evidence?.module?.address ||
    null;

  const [addressInfo, recentActivity] = await Promise.all([
    counterparty
      ? run("check_address_type", { address: counterparty, network: incident.network }).catch(() => null)
      : Promise.resolve(null),
    run("get_recent_safe_activity", { safeAddress: incident.safeAddress, network: incident.network, limit: 5 }).catch(() => null),
  ]);

  const tokenAddress = incident.evidence?.approval?.method === "approve"
    ? incident.source?.transaction?.to ?? null
    : incident.evidence?.transfer?.token ?? null;

  const tokenInfo = tokenAddress
    ? await run("get_token_metadata", { tokenAddress, network: incident.network }).catch(() => null)
    : null;

  return { safeInfo, addressInfo, recentActivity, tokenInfo, toolCalls };
}

function buildContextPrompt(incident, runbook, context) {
  const { safeInfo, addressInfo, recentActivity, tokenInfo } = context;
  const firstStep = runbook?.steps?.[0];
  const reasons = (incident?.evidence?.reasons ?? []).map((r) => `- ${r.code}: ${r.message}`).join("\n");

  return `You are a blockchain security agent. Analyze this incident and respond with ONLY a JSON verdict.

INCIDENT:
Type: ${incident.triggerType} | Severity: ${incident.severity}
Safe: ${incident.safeAddress} (${incident.network})
Title: ${incident.title}
Risk signals: ${reasons || "none"}

GATHERED EVIDENCE:
Safe wallet: ${safeInfo ? JSON.stringify(safeInfo) : "unavailable"}
Counterparty address type: ${addressInfo ? JSON.stringify(addressInfo) : "not checked"}
Token involved: ${tokenInfo ? JSON.stringify(tokenInfo) : "not applicable"}
Recent Safe activity: ${recentActivity ? JSON.stringify(recentActivity) : "unavailable"}

PROPOSED FIRST CONTAINMENT STEP: ${firstStep?.kind ?? "none"} — ${firstStep?.description ?? ""}

Based on the evidence above, respond with ONLY this JSON (no other text):
{"verdict":"HALT","riskLevel":"high","keyFindings":["finding1","finding2","finding3"],"operatorRecommendation":"one sentence action for operator"}

Verdict: HALT (block immediately), INVESTIGATE (needs human review), or APPROVE (appears safe).`;
}

async function callMistralSimple(prompt, config) {
  const res = await fetch(MISTRAL_API_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${config.mistralApiKey}`,
    },
    body: JSON.stringify({
      model: config.mistralModel ?? "mistral-small-latest",
      max_tokens: 400,
      temperature: 0.1,
      messages: [{ role: "user", content: prompt }],
    }),
    signal: AbortSignal.timeout(TOTAL_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`Mistral ${res.status}`);
  const d = await res.json();
  if (d.error) throw new Error(d.error.message ?? `Mistral error`);
  return d?.choices?.[0]?.message?.content?.trim() ?? null;
}

async function callLlmForVerdict(prompt, config) {
  const chain = buildProviderChain(config);

  for (const { name, call } of chain) {
    try {
      const text = await call(prompt);
      if (text) return { provider: name, text };
    } catch {
      // try next provider
    }
  }

  return null;
}

async function callGeminiSimple(prompt, config) {
  const model = config.geminiModel ?? "gemini-2.5-flash";
  const res = await fetch(`${GEMINI_API_URL}/${model}:generateContent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-goog-api-key": config.geminiApiKey },
    body: JSON.stringify({
      generationConfig: { temperature: 0.1, maxOutputTokens: 400 },
      contents: [{ role: "user", parts: [{ text: prompt }] }],
    }),
    signal: AbortSignal.timeout(TOTAL_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`Gemini ${res.status}`);
  const d = await res.json();
  return (d?.candidates?.[0]?.content?.parts ?? []).filter((p) => p.text).map((p) => p.text).join("").trim();
}

async function callAnthropicSimple(prompt, config) {
  const res = await fetch(ANTHROPIC_API_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": config.anthropicApiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: config.anthropicModel ?? "claude-haiku-4-5-20251001",
      max_tokens: 400,
      messages: [{ role: "user", content: prompt }],
    }),
    signal: AbortSignal.timeout(TOTAL_TIMEOUT_MS),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.error?.message ?? `Anthropic ${res.status}`);
  }
  const d = await res.json();
  return (d?.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("").trim();
}

async function callNvidiaSimple(prompt, config) {
  const res = await fetch(NVIDIA_API_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${config.nvidiaApiKey}`,
    },
    body: JSON.stringify({
      model: config.nvidiaModel ?? "meta/llama-3.1-8b-instruct",
      max_tokens: 400,
      temperature: 0.1,
      messages: [{ role: "user", content: prompt }],
    }),
    signal: AbortSignal.timeout(TOTAL_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`Nvidia NIM ${res.status}`);
  const d = await res.json();
  if (d.error || d.detail) throw new Error(JSON.stringify(d.error ?? d.detail).slice(0, 100));
  return d?.choices?.[0]?.message?.content?.trim() ?? null;
}

async function callOpenRouterSimple(prompt, config) {
  const res = await fetch(OPENROUTER_API_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${config.openrouterApiKey}`,
      "http-referer": "https://breakglass.xyz",
    },
    body: JSON.stringify({
      model: config.openrouterModel ?? OPENROUTER_FREE_MODEL,
      max_tokens: 400,
      temperature: 0.1,
      messages: [{ role: "user", content: prompt }],
    }),
    signal: AbortSignal.timeout(TOTAL_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`OpenRouter ${res.status}`);
  const d = await res.json();
  if (d.error) throw new Error(d.error.message ?? "OpenRouter error");
  return d?.choices?.[0]?.message?.content?.trim() ?? null;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

async function investigateIncident(incident, runbook, configInput) {
  const config = resolveInvestigatorConfig(configInput);

  if (config.provider === "disabled" && !config.openrouterApiKey) {
    return buildDeterministicFallback(incident, runbook);
  }

  try {
    // Step 1: gather context via tool calls (always runs, regardless of LLM)
    const context = await gatherInvestigationContext(incident, config);

    // Step 2: call LLM with gathered context
    const prompt = buildContextPrompt(incident, runbook, context);
    const llmResult = await callLlmForVerdict(prompt, config);

    if (!llmResult) {
      return {
        ...buildDeterministicFallback(incident, runbook),
        toolCalls: context.toolCalls,
        configured: true,
        error: "No LLM provider available",
      };
    }

    return {
      ...buildResult({ provider: llmResult.provider, text: llmResult.text, toolCalls: context.toolCalls, incident }),
      configured: true,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ...buildDeterministicFallback(incident, runbook),
      configured: true,
      error: message,
    };
  }
}

module.exports = { investigateIncident, resolveInvestigatorConfig };
