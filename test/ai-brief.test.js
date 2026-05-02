const test = require("node:test");
const assert = require("node:assert/strict");

const {
  generateIncidentBrief,
  resolveBriefConfig,
} = require("../packages/ai/src/brief");

function buildIncident() {
  return {
    safeAddress: "0xsafe",
    network: "base-sepolia",
    severity: "high",
    triggerType: "suspicious_approval",
    summary: "approve to unknown spender",
    evidence: {
      reasons: [{ code: "unknown_spender" }],
    },
  };
}

function buildRunbook() {
  return {
    steps: [
      {
        description: "Invalidate the pending approval first.",
      },
    ],
  };
}

test("generateIncidentBrief returns Claude text when Anthropic responds successfully", async () => {
  const previousFetch = global.fetch;
  let requestBody = null;

  global.fetch = async (_url, options) => {
    requestBody = JSON.parse(options.body);

    return {
      ok: true,
      json: async () => ({
        content: [{ text: "This approval would let an unknown spender move tokens. That is risky because it grants external control over treasury assets. Reject the pending Safe transaction immediately." }],
      }),
    };
  };

  try {
    const brief = await generateIncidentBrief(
      buildIncident(),
      buildRunbook(),
      "test-key",
    );

    assert.match(brief.text, /unknown spender move tokens/i);
    assert.equal(brief.error, null);
    assert.equal(brief.configured, true);
    assert.equal(requestBody.model, "claude-haiku-4-5-20251001");
  } finally {
    global.fetch = previousFetch;
  }
});

test("generateIncidentBrief returns structured error details when Anthropic rejects the request", async () => {
  const previousFetch = global.fetch;

  global.fetch = async () => ({
    ok: false,
    status: 400,
    json: async () => ({
      error: {
        message: "credits exhausted",
      },
    }),
  });

  try {
    const brief = await generateIncidentBrief(
      buildIncident(),
      buildRunbook(),
      "test-key",
    );

    assert.equal(brief.text, null);
    assert.equal(brief.error, "credits exhausted");
    assert.equal(brief.configured, true);
  } finally {
    global.fetch = previousFetch;
  }
});

test("resolveBriefConfig prefers explicit provider selection", () => {
  const config = resolveBriefConfig({
    AI_BRIEF_PROVIDER: "ollama",
    ANTHROPIC_API_KEY: "anthropic-key",
    GEMINI_API_KEY: "gemini-key",
  });

  assert.equal(config.provider, "ollama");
});

test("generateIncidentBrief supports Gemini free-tier style calls", async () => {
  const previousFetch = global.fetch;
  let requestHeaders = null;

  global.fetch = async (_url, options) => {
    requestHeaders = options.headers;

    return {
      ok: true,
      json: async () => ({
        candidates: [
          {
            content: {
              parts: [
                {
                  text: "This transaction would approve an unknown spender. That is risky because it exposes treasury tokens to external control. Reject the pending transaction now.",
                },
              ],
            },
          },
        ],
      }),
    };
  };

  try {
    const brief = await generateIncidentBrief(
      buildIncident(),
      buildRunbook(),
      {
        AI_BRIEF_PROVIDER: "gemini",
        GEMINI_API_KEY: "gemini-key",
      },
    );

    assert.match(brief.text, /approve an unknown spender/i);
    assert.equal(brief.provider, "gemini");
    assert.equal(requestHeaders["x-goog-api-key"], "gemini-key");
  } finally {
    global.fetch = previousFetch;
  }
});

test("generateIncidentBrief supports local Ollama", async () => {
  const previousFetch = global.fetch;

  global.fetch = async () => ({
    ok: true,
    json: async () => ({
      response:
        "This transaction would let an unknown spender move tokens. That is risky because it grants control over treasury assets. Reject the pending Safe transaction now.",
    }),
  });

  try {
    const brief = await generateIncidentBrief(
      buildIncident(),
      buildRunbook(),
      {
        AI_BRIEF_PROVIDER: "ollama",
        OLLAMA_BASE_URL: "http://127.0.0.1:11434/api/generate",
        OLLAMA_MODEL: "gemma3:4b",
      },
    );

    assert.match(brief.text, /unknown spender move tokens/i);
    assert.equal(brief.provider, "ollama");
  } finally {
    global.fetch = previousFetch;
  }
});
