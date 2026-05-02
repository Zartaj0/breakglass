const {
  readBooleanLike,
  toNumber,
  toStringValue,
} = require("../../shared/src/models");

function resolveKeeperHubConfig(env = process.env) {
  return {
    mode:
      toStringValue(env.KEEPERHUB_MODE, "local").trim().toLowerCase() === "webhook"
        ? "webhook"
        : "local",
    webhookUrl: env.KEEPERHUB_WEBHOOK_URL ?? null,
    apiKey: env.KEEPERHUB_API_KEY ?? null,
    timeoutMs: toNumber(env.KEEPERHUB_TIMEOUT_MS, 15000),
    includeFullPayload: readBooleanLike(env.KEEPERHUB_INCLUDE_FULL_PAYLOAD),
  };
}

function buildLocalSimulationResult(step, incident) {
  const base = {
    stepId: step.stepId,
    mode: "local",
    incidentId: incident.incidentId,
  };

  switch (step.kind) {
    case "invalidate_pending_approval":
      return {
        status: "ready_to_propose",
        summary:
          "Replacement transaction is safe to propose. Risk drops if enough owners sign before the suspicious approval executes.",
        artifact: {
          ...base,
          actionability: "high",
          expectedOutcome: "queued approval invalidated",
          simulatedNonce: step.metadata?.nonce ?? null,
        },
      };
    case "revoke_approval":
      return {
        status: "conditional",
        summary:
          "Allowance reset is valid, but it only matters if the spender still has live approval onchain.",
        artifact: {
          ...base,
          actionability: "medium",
          expectedOutcome: "allowance reset to zero",
          token: step.metadata?.token ?? null,
          spender: step.metadata?.spender ?? null,
        },
      };
    case "harden_safe_configuration":
      return {
        status: "manual_review_required",
        summary:
          "Hardening actions are recommended follow-up steps after containment, not the first automated response.",
        artifact: {
          ...base,
          actionability: "review",
          expectedOutcome: "threshold raise, module cleanup, or fund migration",
          options: step.metadata?.options ?? [],
        },
      };
    default:
      return {
        status: "review_required",
        summary: "Step requires operator review before it can be simulated safely.",
        artifact: {
          ...base,
          actionability: "review",
        },
      };
  }
}

async function postWebhookJson(url, payload, config) {
  const headers = {
    "content-type": "application/json",
    accept: "application/json",
  };

  if (config.apiKey) {
    headers.authorization = `Bearer ${config.apiKey}`;
  }

  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(config.timeoutMs),
  });

  const text = await response.text();
  let body;

  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = {
      raw: text,
    };
  }

  if (!response.ok) {
    throw new Error(
      `KeeperHub webhook failed with ${response.status}: ${text.slice(0, 400)}`,
    );
  }

  return body;
}

async function simulateStep(step, incident, runbook, config) {
  if (config.mode === "webhook" && !config.webhookUrl) {
    throw new Error(
      "KEEPERHUB_WEBHOOK_URL is required when KEEPERHUB_MODE=webhook.",
    );
  }

  if (config.mode !== "webhook") {
    return buildLocalSimulationResult(step, incident);
  }

  const payload = {
    action: "simulate_runbook_step",
    incidentId: incident.incidentId,
    runbookId: runbook.runbookId,
    stepId: step.stepId,
    stepKind: step.kind,
    step,
  };

  if (config.includeFullPayload) {
    payload.incident = incident;
    payload.runbook = runbook;
  }

  let body;

  try {
    body = await postWebhookJson(config.webhookUrl, payload, config);
  } catch (webhookError) {
    const reason = webhookError instanceof Error ? webhookError.message : String(webhookError);
    console.error(`[keeperhub] webhook call failed, falling back to local simulation: ${reason}`);
    const local = buildLocalSimulationResult(step, incident);
    return {
      ...local,
      mode: "webhook_fallback",
      fallbackUsed: true,
      webhookError: reason,
    };
  }

  return {
    status: toStringValue(
      body.status ?? body.simulationStatus,
      "submitted_to_keeperhub",
    ),
    summary: toStringValue(
      body.summary ?? body.message,
      "Simulation request submitted to KeeperHub.",
    ),
    mode: "webhook",
    fallbackUsed: false,
    keeperhubRunId: body.executionId ?? body.runId ?? body.workflowRunId ?? null,
    artifact: body,
  };
}

async function simulateRunbook(
  incident,
  runbook,
  config = resolveKeeperHubConfig(),
) {
  const artifacts = [];
  const steps = [];

  for (const step of runbook.steps) {
    const result = await simulateStep(step, incident, runbook, config);

    artifacts.push({
      stepId: step.stepId,
      status: result.status,
      summary: result.summary,
      mode: result.mode ?? config.mode,
      fallbackUsed: result.fallbackUsed ?? false,
      webhookError: result.webhookError ?? null,
      keeperhubRunId: result.keeperhubRunId ?? null,
      artifact: result.artifact,
    });

    steps.push({
      ...step,
      simulation: {
        ...(step.simulation ?? {}),
        provider: "keeperhub",
        status: result.status,
        mode: result.mode ?? config.mode,
        summary: result.summary,
        fallbackUsed: result.fallbackUsed ?? false,
        webhookError: result.webhookError ?? null,
        keeperhubRunId: result.keeperhubRunId ?? null,
      },
    });
  }

  return {
    provider: {
      name: "keeperhub",
      mode: config.mode,
      webhookUrl: config.mode === "webhook" ? config.webhookUrl : null,
      configured:
        config.mode === "webhook" ? Boolean(config.webhookUrl) : true,
      degraded: artifacts.some((artifact) => artifact.fallbackUsed),
    },
    artifacts,
    runbook: {
      ...runbook,
      steps,
      metadata: {
        ...(runbook.metadata ?? {}),
        keeperhubMode: config.mode,
      },
    },
  };
}

module.exports = {
  resolveKeeperHubConfig,
  simulateRunbook,
};
