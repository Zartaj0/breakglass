const test = require("node:test");
const assert = require("node:assert/strict");

const {
  investigateIncident,
} = require("../packages/ai/src/investigator");

function buildIncident() {
  return {
    triggerType: "suspicious_approval",
    severity: "high",
    safeAddress: "0xSafe000000000000000000000000000000000001",
    network: "base-sepolia",
    title: "Suspicious approval pending",
    summary: "Unknown spender requested token approval.",
    evidence: {
      reasons: [{ code: "unknown_spender", message: "The spender is not allowlisted." }],
      approval: {
        method: "approve",
        spender: "0xSpender0000000000000000000000000000000001",
      },
    },
    source: {
      transaction: {
        to: "0xToken000000000000000000000000000000000001",
      },
    },
  };
}

function buildRunbook() {
  return {
    steps: [
      {
        kind: "invalidate_pending_approval",
        description: "Reject the queued approval at the same nonce.",
      },
    ],
  };
}

test("investigateIncident prefers native multi-turn Gemini agent over gather-then-reason when Gemini key is present", async () => {
  const previousFetch = global.fetch;
  const calledUrls = [];

  global.fetch = async (url) => {
    const urlString = String(url);
    calledUrls.push(urlString);

    // Gemini multi-turn: first call returns a tool_use request
    if (urlString.includes("generativelanguage.googleapis.com") && !calledUrls.filter((u) => u.includes("generativelanguage")).length > 1) {
      if (calledUrls.filter((u) => u.includes("generativelanguage")).length === 1) {
        return {
          ok: true,
          json: async () => ({
            candidates: [{
              content: {
                parts: [{ functionCall: { name: "get_safe_info", args: { safeAddress: "0xSafe000000000000000000000000000000000001", network: "base-sepolia" } } }],
              },
            }],
          }),
        };
      }
      // Second call: Gemini returns final text verdict
      return {
        ok: true,
        json: async () => ({
          candidates: [{
            content: {
              parts: [{ text: '{"verdict":"HALT","riskLevel":"high","keyFindings":["Unknown spender"],"operatorRecommendation":"Reject it."}' }],
            },
          }],
        }),
      };
    }

    // Gemini first call (detect by count)
    if (urlString.includes("generativelanguage.googleapis.com")) {
      const geminiCallCount = calledUrls.filter((u) => u.includes("generativelanguage")).length;
      if (geminiCallCount === 1) {
        return {
          ok: true,
          json: async () => ({
            candidates: [{
              content: {
                parts: [{ functionCall: { name: "get_safe_info", args: { safeAddress: "0xSafe000000000000000000000000000000000001", network: "base-sepolia" } } }],
              },
            }],
          }),
        };
      }
      return {
        ok: true,
        json: async () => ({
          candidates: [{
            content: {
              parts: [{ text: '{"verdict":"HALT","riskLevel":"high","keyFindings":["Unknown spender"],"operatorRecommendation":"Reject it."}' }],
            },
          }],
        }),
      };
    }

    if (urlString.includes("/safes/") && urlString.endsWith("/")) {
      return { ok: true, json: async () => ({ threshold: 2, owners: ["0x1", "0x2"], nonce: 5, modules: [] }) };
    }

    throw new Error(`Unexpected fetch URL in multi-turn test: ${urlString}`);
  };

  try {
    const result = await investigateIncident(buildIncident(), buildRunbook(), {
      GEMINI_API_KEY: "gemini-key",
    });
    assert.equal(result.provider, "gemini");
    assert.ok(result.toolCalls.length > 0, "multi-turn agent should have made at least one tool call");
    assert.ok(calledUrls.some((u) => u.includes("generativelanguage")), "should have called Gemini API");
  } finally {
    global.fetch = previousFetch;
  }
});

test("investigateIncident uses novel investigation prompt for unknown_transaction incidents", async () => {
  const previousFetch = global.fetch;
  const seenPrompts = [];

  global.fetch = async (url, options = {}) => {
    const urlString = String(url);

    if (urlString.includes("openrouter.ai")) {
      const body = JSON.parse(options.body ?? "{}");
      const userMessage = body?.messages?.find((m) => m.role === "user");
      if (userMessage?.content) seenPrompts.push(userMessage.content);
      return {
        ok: true,
        json: async () => ({
          choices: [{ message: { content: '{"verdict":"HALT","riskLevel":"critical","keyFindings":["Hidden delegatecall"],"threatHypothesis":"Proxy upgrade attack","operatorRecommendation":"Do not sign."}' } }],
        }),
      };
    }

    if (urlString.includes("/safes/") && urlString.endsWith("/")) {
      return { ok: true, json: async () => ({ threshold: 2, owners: ["0x1", "0x2"], nonce: 5, modules: [] }) };
    }
    if (urlString.includes("/contracts/")) {
      return { status: 404, ok: false, json: async () => ({}) };
    }
    if (urlString.includes("/multisig-transactions/")) {
      return { ok: true, json: async () => ({ count: 0, results: [] }) };
    }
    if (urlString.includes("4byte.directory")) {
      return { ok: true, json: async () => ({ results: [] }) };
    }

    throw new Error(`Unexpected fetch URL in unknown_transaction test: ${urlString}`);
  };

  const unknownIncident = {
    triggerType: "unknown_transaction",
    severity: "critical",
    safeAddress: "0xSafe000000000000000000000000000000000001",
    network: "base-sepolia",
    title: "Uncategorized Safe transaction requires investigation",
    summary: "multiSend to MultiSend contract did not match a deterministic incident class.",
    evidence: {
      anomaly: {
        target: "0x40a2accbd92bca938b02010e17a5b8929b49130d",
        method: "multiSend",
        operation: "CALL",
        isDelegateCall: false,
        calldataBytes: 196,
      },
      reasons: [{ code: "uncategorized_contract_call", message: "Not covered by a high-confidence detector." }],
      transaction: { to: "0x40a2accbd92bca938b02010e17a5b8929b49130d", nonce: 44 },
    },
  };

  try {
    const result = await investigateIncident(unknownIncident, buildRunbook(), {
      OPENROUTER: "openrouter-key",
    });
    assert.equal(result.provider, "openrouter");
    assert.ok(
      seenPrompts.some((p) => p.includes("threat hypothesis") || p.includes("Threat vectors")),
      "novel investigation prompt should mention threat hypothesis",
    );
  } finally {
    global.fetch = previousFetch;
  }
});

test("investigateIncident sends SAFE_API_KEY to Safe token metadata lookup", async () => {
  const previousFetch = global.fetch;
  const seenAuthHeaders = [];

  global.fetch = async (url, options = {}) => {
    const urlString = String(url);

    if (urlString.includes("/tokens/")) {
      seenAuthHeaders.push(options.headers?.Authorization ?? null);
      return {
        ok: true,
        json: async () => ({ name: "Wrapped Ether", symbol: "WETH", decimals: 18 }),
      };
    }

    if (urlString.includes("/safes/") && urlString.endsWith("/")) {
      return {
        ok: true,
        json: async () => ({ threshold: 2, owners: ["0x1", "0x2"], nonce: 5, modules: [] }),
      };
    }

    if (urlString.includes("/contracts/")) {
      return {
        status: 404,
        ok: false,
        json: async () => ({}),
      };
    }

    if (urlString.includes("/multisig-transactions/")) {
      return {
        ok: true,
        json: async () => ({ count: 0, results: [] }),
      };
    }

    if (urlString.includes("openrouter.ai")) {
      return {
        ok: true,
        json: async () => ({
          choices: [
            {
              message: {
                content: "{\"verdict\":\"HALT\",\"riskLevel\":\"high\",\"keyFindings\":[\"Unknown spender\"],\"operatorRecommendation\":\"Reject it.\"}",
              },
            },
          ],
        }),
      };
    }

    throw new Error(`Unexpected fetch URL in test: ${urlString}`);
  };

  try {
    const result = await investigateIncident(buildIncident(), buildRunbook(), {
      SAFE_API_KEY: "safe-api-key",
      OPENROUTER: "openrouter-key",
    });

    assert.equal(result.provider, "openrouter");
    assert.deepEqual(seenAuthHeaders, ["Bearer safe-api-key"]);
  } finally {
    global.fetch = previousFetch;
  }
});
