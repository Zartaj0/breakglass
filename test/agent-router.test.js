const test = require("node:test");
const assert = require("node:assert/strict");

const {
  listServices,
  createRouterState,
  getService,
  routeToService,
} = require("../apps/agent-router/src/server");

test("router tracks peer-specific services and forwards MCP requests", async () => {
  const previousFetch = global.fetch;
  const state = createRouterState();
  state.set(
    "breakglass-review",
    new Map([
      [
        "reviewer-a",
        {
          name: "breakglass-review",
          peerId: "reviewer-a",
          endpoint: "http://127.0.0.1:7100/mcp",
          registeredAt: new Date().toISOString(),
          healthy: true,
        },
      ],
    ]),
  );
  const service = getService(state, "breakglass-review", "reviewer-a");

  try {
    global.fetch = async () => ({
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            ok: true,
          },
        }),
    });

    const services = listServices(state);
    const payload = await routeToService(
      service,
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
        params: {},
      },
      "peer-a",
    );

    assert.equal(services["breakglass-review"].peers["reviewer-a"].endpoint, service.endpoint);
    assert.equal(payload.response.result.ok, true);
  } finally {
    global.fetch = previousFetch;
  }
});

test("router resolves peer-specific services from the registry", () => {
  const state = createRouterState();
  state.set(
    "breakglass-review",
    new Map([
      [
        "reviewer-a",
        {
          name: "breakglass-review",
          peerId: "reviewer-a",
          endpoint: "http://127.0.0.1:7100/mcp",
          registeredAt: new Date().toISOString(),
          healthy: true,
        },
      ],
      [
        "reviewer-b",
        {
          name: "breakglass-review",
          peerId: "reviewer-b",
          endpoint: "http://127.0.0.1:7101/mcp",
          registeredAt: new Date().toISOString(),
          healthy: true,
        },
      ],
    ]),
  );

  assert.equal(getService(state, "breakglass-review", "reviewer-a").endpoint, "http://127.0.0.1:7100/mcp");
  assert.equal(getService(state, "breakglass-review", "reviewer-b").endpoint, "http://127.0.0.1:7101/mcp");
  assert.equal(listServices(state)["breakglass-review"].peerCount, 2);
});
