const {
  INCIDENT_SOURCE_STAGE,
  RUNBOOK_STEP_STATUS,
  buildRunbookPlan,
  buildRunbookStep,
} = require("../../shared/src/models");

function compileThresholdReductionRunbook(incident) {
  const ev = incident.evidence?.threshold ?? {};
  const transaction = incident.source?.transaction ?? {};
  const safeTxHash = transaction.safeTxHash ?? incident.source?.safeTxHash ?? null;

  return buildRunbookPlan({
    incident,
    templateId: "threshold-reduction-v1",
    title: "Threshold reduction mitigation plan",
    summary:
      "Deterministic response for a pending Safe threshold reduction: reject the queued change before it weakens the multisig requirement.",
    steps: [
      buildRunbookStep({
        stepId: "invalidate-pending-reduction",
        kind: "invalidate_pending_transaction",
        description: `Propose a Safe rejection transaction at nonce ${transaction.nonce} to block the threshold reduction from reaching execution.`,
        simulation: {
          provider: "keeperhub",
          status: "pending",
          action: "simulate_invalidate_pending_transaction",
        },
        execution: {
          provider: "safe",
          status: "awaiting_operator_approval",
          action: "execute_invalidate_pending_transaction",
        },
        metadata: {
          nonce: transaction.nonce ?? null,
          safeTxHash,
          proposedThreshold: ev.proposedThreshold ?? null,
        },
      }),
      buildRunbookStep({
        stepId: "verify-threshold-policy",
        kind: "verify_threshold_policy",
        description:
          "Confirm the current threshold still meets the minimum signing requirement policy. If it was already reduced in a prior transaction, restore it.",
        dependsOn: ["invalidate-pending-reduction"],
        status: RUNBOOK_STEP_STATUS.CONDITIONAL,
        simulation: {
          provider: "keeperhub",
          status: "pending",
          action: "simulate_threshold_verification",
        },
        execution: {
          provider: "safe",
          status: "manual_review_required",
          action: "execute_threshold_restore",
        },
        metadata: {
          condition: "current_threshold_below_minimum",
        },
      }),
      buildRunbookStep({
        stepId: "harden-after-threshold-incident",
        kind: "harden_safe_configuration",
        description:
          "Review pending transactions that may now be executable at a lower threshold. Cancel any that should require more signatures.",
        dependsOn: ["verify-threshold-policy"],
        simulation: {
          provider: "keeperhub",
          status: "pending",
          action: "simulate_safe_hardening",
        },
        execution: {
          provider: "safe",
          status: "recommended_only",
          action: "execute_safe_hardening",
        },
        metadata: {
          options: ["cancel_now_unilateral_txs", "raise_threshold_back", "move_funds_to_fallback_safe"],
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

module.exports = { compileThresholdReductionRunbook };
