const test = require("node:test");
const assert = require("node:assert/strict");

const {
  resolveKeeperHubConfig,
  simulateRunbook,
} = require("../packages/integrations/src/keeperhub-client");

test("throws when webhook mode is requested without a webhook URL", async () => {
  const config = resolveKeeperHubConfig({
    KEEPERHUB_MODE: "webhook",
  });

  await assert.rejects(
    () =>
      simulateRunbook(
        {
          incidentId: "incident-1",
        },
        {
          runbookId: "runbook-1",
          steps: [
            {
              stepId: "invalidate-pending-approval",
              kind: "invalidate_pending_approval",
            },
          ],
        },
        config,
      ),
    /KEEPERHUB_WEBHOOK_URL is required/,
  );
});

test("falls back to local simulation when KeeperHub webhook fails", async () => {
  const previousFetch = global.fetch;

  global.fetch = async () => ({
    ok: false,
    status: 410,
    text: async () => JSON.stringify({ error: "Workflow is disabled" }),
  });

  try {
    const simulated = await simulateRunbook(
      {
        incidentId: "incident-1",
      },
      {
        runbookId: "runbook-1",
        steps: [
          {
            stepId: "invalidate-pending-approval",
            kind: "invalidate_pending_approval",
            metadata: { nonce: 7 },
          },
        ],
      },
      resolveKeeperHubConfig({
        KEEPERHUB_MODE: "webhook",
        KEEPERHUB_WEBHOOK_URL: "https://keeperhub.example/webhook",
      }),
    );

    assert.equal(simulated.provider.degraded, true);
    assert.equal(simulated.runbook.steps[0].simulation.mode, "webhook_fallback");
    assert.match(simulated.runbook.steps[0].simulation.webhookError, /Workflow is disabled/i);
  } finally {
    global.fetch = previousFetch;
  }
});
