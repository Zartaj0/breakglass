const {
  getPendingTransactions,
  resolveSafeSourceConfig,
} = require("../../../packages/integrations/src/safe-client");
const {
  detectAllIncidents,
  resolveAllPolicyConfigs,
} = require("../../../packages/policies/src/index");
const {
  compileRunbook,
} = require("../../../packages/runbooks/src/index");
const {
  buildIncidentReceipt,
  readBooleanLike,
} = require("../../../packages/shared/src/models");
const {
  buildPeerReviewBlockArtifact,
  resolveAgentMeshConfig,
  reviewIncidentWithPeers,
  shouldAllowExecution,
} = require("../../../packages/agent-mesh/src/axl-client");
const {
  resolveKeeperHubConfig,
  simulateRunbook,
} = require("../../../packages/integrations/src/keeperhub-client");
const {
  isExecutableStep,
  executeMitigationStep,
  resolveSafeExecutionConfig,
} = require("../../../packages/integrations/src/safe-remediation");
const {
  createStoragePointer,
  resolveReceiptStorageConfig,
  writeLatestReport,
  writeReceiptMirror,
} = require("../../../packages/storage-0g/src/client");
const {
  investigateIncident,
} = require("../../../packages/ai/src/investigator");

function clonePlainData(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function selectFirstExecutableStep(runbook) {
  const firstStep = runbook?.steps?.[0] ?? null;
  return firstStep && isExecutableStep(firstStep) ? firstStep : null;
}

function buildPipelineOptions(options = {}) {
  return {
    existingResultsByIncidentId: options.existingResultsByIncidentId ?? {},
    refreshKnownIncidents: Boolean(options.refreshKnownIncidents),
    incidentReuseWindowMs: Number(options.incidentReuseWindowMs ?? 0),
    now: options.now instanceof Date ? options.now : new Date(),
  };
}

function getLastProcessedAt(existingResult) {
  return (
    existingResult?.monitor?.lastProcessedAt ??
    existingResult?.cache?.processedAt ??
    existingResult?.receipt?.createdAt ??
    null
  );
}

function shouldReuseIncidentResult(existingResult, pipelineOptions) {
  if (!existingResult || pipelineOptions.refreshKnownIncidents) {
    return false;
  }

  if (pipelineOptions.incidentReuseWindowMs <= 0) {
    return false;
  }

  const lastProcessedAt = getLastProcessedAt(existingResult);

  if (!lastProcessedAt) {
    return false;
  }

  const ageMs = pipelineOptions.now.getTime() - Date.parse(lastProcessedAt);

  return ageMs >= 0 && ageMs < pipelineOptions.incidentReuseWindowMs;
}

function buildReusedIncidentResult(existingResult, pipelineOptions) {
  const cloned = clonePlainData(existingResult);
  const lastProcessedAt = getLastProcessedAt(existingResult);
  const ageMs = lastProcessedAt
    ? Math.max(0, pipelineOptions.now.getTime() - Date.parse(lastProcessedAt))
    : null;

  return {
    ...cloned,
    cache: {
      reused: true,
      processedAt: lastProcessedAt,
      reusedAt: pipelineOptions.now.toISOString(),
      ageMs,
      reuseWindowMs: pipelineOptions.incidentReuseWindowMs,
    },
  };
}

function buildReadinessSummary({
  pending,
  keeperhubConfig,
  executionConfig,
  storageConfig,
  agentMeshConfig,
  results,
}) {
  const fallbackWarnings = [];
  let keeperhubWebhookHealthy = keeperhubConfig.mode === "webhook";
  let storage0GHealthy = storageConfig.mode === "0g";

  if (pending.source?.kind !== "safe_api") {
    fallbackWarnings.push("safe_ingestion_fixture_mode");
  }

  if (keeperhubConfig.mode !== "webhook") {
    fallbackWarnings.push("keeperhub_local_mode");
  }

  if (storageConfig.mode !== "0g") {
    fallbackWarnings.push("storage_file_mode");
  }

  if (executionConfig.mode !== "live") {
    fallbackWarnings.push("safe_execution_dry_run");
  }

  if (agentMeshConfig.mode === "mcp") {
    for (const result of results) {
      if (result.peerReview?.decision === "degraded") {
        fallbackWarnings.push("gensyn_peer_review_unavailable");
      }

      if (
        agentMeshConfig.requireQuorumForExecution &&
        result.peerReview?.executionGate === "block"
      ) {
        fallbackWarnings.push("gensyn_peer_quorum_not_met");
      }
    }
  }

  for (const result of results) {
    if ((result.runbook?.steps ?? []).some((step) => step.simulation?.fallbackUsed)) {
      fallbackWarnings.push("keeperhub_webhook_failed");
      keeperhubWebhookHealthy = false;
    }

    if (result.receipt.storagePointer?.kind === "local_file") {
      fallbackWarnings.push("receipt_local_file_pointer");
      storage0GHealthy = false;
    }

    if (result.receipt.storagePointer?.status === "not_configured") {
      fallbackWarnings.push("storage_not_configured");
      storage0GHealthy = false;
    }

    if (result.receipt.storagePointer?.status === "failed") {
      fallbackWarnings.push("storage_upload_failed");
      storage0GHealthy = false;
    }
  }

  return {
    safeIngestionLive: pending.source?.kind === "safe_api",
    keeperhubWebhookMode: keeperhubConfig.mode === "webhook",
    keeperhubWebhookHealthy,
    safeExecutionLive: executionConfig.mode === "live",
    storage0GMode: storageConfig.mode === "0g",
    storage0GHealthy,
    gensynAxlMode: agentMeshConfig.mode === "mcp",
    fallbackWarnings: Array.from(new Set(fallbackWarnings)),
  };
}

function deriveFinalStatus(executionArtifact) {
  if (!executionArtifact) return "simulated_only";
  if (executionArtifact.status === "executed") return "mitigation_executed";
  if (executionArtifact.status === "already_executed") return "mitigation_executed";
  if (executionArtifact.status === "blocked_by_peer_review") return "awaiting_peer_consensus";
  if (
    executionArtifact.status === "proposed_and_confirmed" ||
    executionArtifact.status === "proposed_waiting_for_confirmations"
  ) {
    return "mitigation_proposed";
  }
  if (executionArtifact.status === "prepared") return "execution_prepared";
  return "operator_review_required";
}

function buildReasoningSummary(incident, runbook, executionArtifact, peerReview) {
  const firstStep = runbook.steps[0];
  const peerSummary =
    peerReview?.provider?.mode === "mcp" ? ` ${peerReview.summary}` : "";

  if (!executionArtifact) {
    return `${incident.title}. ${firstStep.description} No automatic execution was attempted in this run.${peerSummary}`;
  }

  if (executionArtifact.status === "blocked_by_peer_review") {
    return `${incident.title}. Automatic execution was halted because peer reviewer quorum was not satisfied over AXL.${peerSummary}`;
  }

  if (executionArtifact.status === "executed") {
    return `${incident.title}. The first containment step was executed on the Safe and a receipt was persisted.${peerSummary}`;
  }

  if (executionArtifact.status === "already_executed") {
    return `${incident.title}. The required containment transaction had already been executed on the Safe before this run.${peerSummary}`;
  }

  if (executionArtifact.status === "proposed_and_confirmed") {
    return `${incident.title}. The containment transaction was proposed and fully confirmed, but execution was not requested.${peerSummary}`;
  }

  if (executionArtifact.status === "proposed_waiting_for_confirmations") {
    return `${incident.title}. The containment transaction was proposed, but additional Safe owner confirmations are still required.${peerSummary}`;
  }

  return `${incident.title}. A real mitigation transaction was prepared, but live execution is not configured in this environment.${peerSummary}`;
}

async function runSingleIncident({
  incident,
  keeperhubConfig,
  executionConfig,
  storageConfig,
  agentMeshConfig,
  autoExecuteFirstStep,
  briefConfigInput,
  existingResult,
  pipelineOptions,
}) {
  if (shouldReuseIncidentResult(existingResult, pipelineOptions)) {
    return buildReusedIncidentResult(existingResult, pipelineOptions);
  }

  const compiledRunbook = compileRunbook(incident);
  const [peerReview, investigation] = await Promise.all([
    reviewIncidentWithPeers(incident, compiledRunbook, agentMeshConfig),
    investigateIncident(incident, compiledRunbook, briefConfigInput),
  ]);
  const simulated = await simulateRunbook(incident, compiledRunbook, keeperhubConfig);
  const firstExecutableStep = selectFirstExecutableStep(simulated.runbook);
  const executionAllowed = shouldAllowExecution(peerReview, agentMeshConfig);
  const executionArtifact =
    autoExecuteFirstStep && firstExecutableStep
      ? executionAllowed
        ? await executeMitigationStep(firstExecutableStep, incident, executionConfig)
        : buildPeerReviewBlockArtifact(peerReview, executionConfig)
      : null;
  const finalStatus = deriveFinalStatus(executionArtifact);

  const draftReceipt = buildIncidentReceipt({
    incident,
    runbook: simulated.runbook,
    finalStatus,
    simulationArtifacts: simulated.artifacts,
    executionArtifacts: executionArtifact,
    operatorDecision: autoExecuteFirstStep
      ? "attempt_first_executable_step"
      : "simulate_only",
    reasoningSummary: buildReasoningSummary(
      incident,
      simulated.runbook,
      executionArtifact,
      peerReview,
    ),
    storagePointer: null,
    metadata: {
      keeperhub: simulated.provider,
      executionMode: executionConfig.mode,
      agentMesh: peerReview.provider,
    },
  });

  const storagePointer = await createStoragePointer(draftReceipt, storageConfig);
  const receipt = { ...draftReceipt, storagePointer };
  const localReceiptPath = await writeReceiptMirror(receipt, storageConfig);

  return {
    incident,
    brief: investigation.text,
    briefStatus: investigation,
    investigation,
    runbook: simulated.runbook,
    simulation: simulated.provider,
    peerReview,
    execution: executionArtifact,
    receipt,
    localReceiptPath,
    cache: {
      reused: false,
      processedAt: pipelineOptions.now.toISOString(),
      reuseWindowMs: pipelineOptions.incidentReuseWindowMs,
    },
  };
}

async function runIncidentPipeline(env = process.env, options = {}) {
  const pipelineOptions = buildPipelineOptions(options);
  const sourceConfig = resolveSafeSourceConfig(env);
  const policyConfigs = resolveAllPolicyConfigs(env);
  const keeperhubConfig = resolveKeeperHubConfig(env);
  const executionConfig = resolveSafeExecutionConfig(env);
  const storageConfig = resolveReceiptStorageConfig(env);
  const agentMeshConfig = resolveAgentMeshConfig(env);
  const autoExecuteFirstStep = readBooleanLike(env.BREAKGLASS_AUTO_EXECUTE_FIRST_STEP);
  const pending = await getPendingTransactions(sourceConfig);
  const incidents = detectAllIncidents(pending.transactions, policyConfigs);
  const results = [];

  for (const incident of incidents) {
    results.push(
      await runSingleIncident({
        incident,
        keeperhubConfig,
        executionConfig,
        storageConfig,
        agentMeshConfig,
        autoExecuteFirstStep,
        briefConfigInput: env,
        existingResult:
          pipelineOptions.existingResultsByIncidentId?.[incident.incidentId] ?? null,
        pipelineOptions,
      }),
    );
  }

  const report = {
    generatedAt: new Date().toISOString(),
    source: pending.source,
    safeAddress: pending.safeAddress,
    network: pending.network,
    transactionsScanned: pending.transactions.length,
    incidentsDetected: incidents.length,
    keeperhub: { mode: keeperhubConfig.mode },
    agentMesh: {
      mode: agentMeshConfig.mode,
      peerCount: agentMeshConfig.peers.length,
      service: agentMeshConfig.service,
      minApprovals: agentMeshConfig.minApprovals,
      requireQuorumForExecution: agentMeshConfig.requireQuorumForExecution,
    },
    execution: {
      mode: executionConfig.mode,
      autoExecuteFirstStep,
    },
    storage: {
      mode: storageConfig.mode,
      artifactDir: storageConfig.artifactDir,
    },
    readiness: buildReadinessSummary({
      pending,
      keeperhubConfig,
      executionConfig,
      storageConfig,
      agentMeshConfig,
      results,
    }),
    incidents: results,
  };

  const reportPath = await writeLatestReport(report, storageConfig);
  return { ...report, reportPath };
}

module.exports = { runIncidentPipeline };
