const {
  INCIDENT_SOURCE_STAGE,
  RUNBOOK_STEP_STATUS,
  buildRunbookPlan,
  buildRunbookStep,
} = require("../../shared/src/models");

function compileUnknownTransactionRunbook(incident) {
  const ev = incident.evidence?.anomaly ?? {};
  const transaction = incident.source?.transaction ?? {};
  const safeTxHash = transaction.safeTxHash ?? incident.source?.safeTxHash ?? null;

  return buildRunbookPlan({
    incident,
    templateId: "unknown-transaction-v1",
    title: "Unknown transaction investigation plan",
    summary:
      "Investigation-first response for a pending Safe transaction that did not match a deterministic incident class. Gather evidence, confirm proposer intent, and halt signing until the transaction is understood.",
    steps: [
      buildRunbookStep({
        stepId: "investigate-unknown-transaction",
        kind: "investigate_unknown_transaction",
        description: `Use the investigation agent to analyze ${ev.method ?? "the opaque transaction"} targeting ${ev.target ?? "the unknown contract"} and produce a structured HALT / INVESTIGATE / APPROVE verdict before any additional signatures are added.`,
        simulation: {
          provider: "keeperhub",
          status: "pending",
          action: "simulate_unknown_transaction_investigation",
        },
        execution: {
          provider: "safe",
          status: "manual_review_required",
          action: "review_unknown_transaction",
        },
        metadata: {
          method: ev.method ?? null,
          target: ev.target ?? null,
          safeTxHash,
          operation: ev.operation ?? null,
        },
      }),
      buildRunbookStep({
        stepId: "collect-proposer-explanation",
        kind: "collect_proposer_explanation",
        description:
          "Get an out-of-band explanation from the proposer and verify the target contract, beneficiary, and intended outcome. Do not continue signing until the explanation matches the on-chain transaction.",
        dependsOn: ["investigate-unknown-transaction"],
        status: RUNBOOK_STEP_STATUS.PLANNED,
        simulation: {
          provider: "keeperhub",
          status: "pending",
          action: "simulate_proposer_confirmation",
        },
        execution: {
          provider: "safe",
          status: "manual_review_required",
          action: "collect_operator_confirmation",
        },
        metadata: {
          target: ev.target ?? null,
          method: ev.method ?? null,
        },
      }),
      buildRunbookStep({
        stepId: "escalate-human-review",
        kind: "escalate_human_review",
        description:
          "If the investigation verdict is HALT or the proposer explanation is incomplete, freeze signing and escalate to a human security review. Only re-classify into a deterministic containment path once the transaction intent is understood.",
        dependsOn: ["collect-proposer-explanation"],
        status: RUNBOOK_STEP_STATUS.PLANNED,
        simulation: {
          provider: "keeperhub",
          status: "pending",
          action: "simulate_human_review_escalation",
        },
        execution: {
          provider: "safe",
          status: "recommended_only",
          action: "escalate_unknown_transaction_review",
        },
        metadata: {
          options: ["pause_signing", "route_to_security", "reclassify_if_known_pattern"],
        },
      }),
    ],
    metadata: {
      incidentClass: incident.triggerType,
      sourceSafeTxHash: safeTxHash,
      sourceStage: incident.sourceStage ?? INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION,
    },
  });
}

module.exports = {
  compileUnknownTransactionRunbook,
};
