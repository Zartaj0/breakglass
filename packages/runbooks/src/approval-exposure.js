const {
  INCIDENT_SOURCE_STAGE,
  RUNBOOK_STEP_STATUS,
  buildRunbookPlan,
  buildRunbookStep,
} = require("../../shared/src/models");

function compileApprovalExposureRunbook(incident) {
  const approval = incident.evidence?.approval ?? {};
  const transaction = incident.source?.transaction ?? {};
  const safeTxHash = transaction.safeTxHash ?? incident.source?.safeTxHash ?? null;
  const sourceStage = incident.sourceStage ?? INCIDENT_SOURCE_STAGE.UNKNOWN;
  const isPendingProposal =
    sourceStage === INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION;
  const firstStepId = isPendingProposal
    ? "invalidate-pending-approval"
    : "revoke-primary-approval";
  const secondStepId = isPendingProposal
    ? "revoke-live-approval"
    : "verify-residual-approval";

  const steps = [
    buildRunbookStep({
      stepId: firstStepId,
      kind: isPendingProposal
        ? "invalidate_pending_approval"
        : "revoke_approval",
      description: isPendingProposal
        ? `Propose a Safe rejection transaction at nonce ${transaction.nonce} to invalidate the pending approval before it executes.`
        : `Submit a zero-value approval reset against token ${transaction.to} for spender ${approval.spender ?? "unknown spender"}.`,
      simulation: {
        provider: "keeperhub",
        status: "pending",
        action: isPendingProposal
          ? "simulate_invalidate_pending_approval"
          : "simulate_revoke_approval",
      },
      execution: {
        provider: "safe",
        status: "awaiting_operator_approval",
        action: isPendingProposal
          ? "execute_invalidate_pending_approval"
          : "execute_revoke_approval",
      },
      metadata: {
        spender: approval.spender ?? null,
        token: transaction.to ?? null,
        nonce: transaction.nonce ?? null,
        safeTxHash,
      },
    }),
    buildRunbookStep({
      stepId: secondStepId,
      kind: "revoke_approval",
      description: isPendingProposal
        ? `If the approval already landed onchain or the pending proposal executes before containment, submit approve(${approval.spender ?? "spender"}, 0) to remove spender access.`
        : "If the spender still has allowance after containment, submit a zero-value approval reset immediately.",
      dependsOn: [firstStepId],
      status: RUNBOOK_STEP_STATUS.CONDITIONAL,
      simulation: {
        provider: "keeperhub",
        status: "pending",
        action: "simulate_revoke_approval",
      },
      execution: {
        provider: "safe",
        status: "manual_review_required",
        action: "execute_revoke_approval",
      },
      metadata: {
        condition: isPendingProposal
          ? "allowance_is_live_or_source_tx_executed"
          : "residual_allowance_detected",
        spender: approval.spender ?? null,
        token: transaction.to ?? null,
      },
    }),
    buildRunbookStep({
      stepId: "raise-threshold-or-move-funds",
      kind: "harden_safe_configuration",
      description:
        "After containment, disable any risky module if relevant, then raise the Safe threshold or move assets to a fallback Safe if exposure remains.",
      dependsOn: [secondStepId],
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
        options: [
          "disable_module_if_relevant",
          "raise_threshold",
          "move_funds_to_fallback_safe",
        ],
      },
    }),
  ];

  return buildRunbookPlan({
    incident,
    templateId: "approval-exposure-v1",
    title: "Approval exposure mitigation plan",
    summary:
      isPendingProposal
        ? "Deterministic mitigation for a suspicious pending Safe approval: invalidate the queued proposal first, revoke any live allowance if needed, then harden the Safe."
        : "Deterministic mitigation for malicious spender exposure: revoke the live allowance first, then harden the Safe.",
    steps,
    metadata: {
      incidentClass: incident.triggerType,
      sourceSafeTxHash: safeTxHash,
      sourceStage,
    },
  });
}

module.exports = {
  compileApprovalExposureRunbook,
};
