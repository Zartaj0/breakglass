const {
  INCIDENT_SOURCE_STAGE,
  RUNBOOK_STEP_STATUS,
  buildRunbookPlan,
  buildRunbookStep,
} = require("../../shared/src/models");

function compileLargeTransferRunbook(incident) {
  const ev = incident.evidence?.transfer ?? {};
  const transaction = incident.source?.transaction ?? {};
  const safeTxHash = transaction.safeTxHash ?? incident.source?.safeTxHash ?? null;

  return buildRunbookPlan({
    incident,
    templateId: "large-transfer-v1",
    title: "Large transfer mitigation plan",
    summary:
      "Deterministic response for a pending large asset transfer: reject the transfer, verify the recipient, and investigate the origin of the request.",
    steps: [
      buildRunbookStep({
        stepId: "invalidate-pending-transfer",
        kind: "invalidate_pending_transaction",
        description: `Propose a Safe rejection transaction at nonce ${transaction.nonce} to block the transfer of ${ev.humanAmount ?? "assets"} to ${ev.recipient ?? "unknown address"}.`,
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
          recipient: ev.recipient ?? null,
          amount: ev.amount ?? null,
          humanAmount: ev.humanAmount ?? null,
          isEth: ev.isEth ?? false,
        },
      }),
      buildRunbookStep({
        stepId: "verify-recipient",
        kind: "verify_recipient_ownership",
        description: `Confirm that ${ev.recipient ?? "the recipient"} is a trusted address owned by the protocol or team. Require a separate out-of-band confirmation from the proposer.`,
        dependsOn: ["invalidate-pending-transfer"],
        status: RUNBOOK_STEP_STATUS.PLANNED,
        simulation: {
          provider: "keeperhub",
          status: "pending",
          action: "simulate_recipient_verification",
        },
        execution: {
          provider: "safe",
          status: "manual_review_required",
          action: "verify_and_resubmit_transfer",
        },
        metadata: {
          recipient: ev.recipient ?? null,
        },
      }),
      buildRunbookStep({
        stepId: "investigate-transfer-origin",
        kind: "investigate_transfer_origin",
        description:
          "Determine who proposed this transfer, through what mechanism, and whether any signing keys have been compromised. File an incident report before re-attempting the transfer.",
        dependsOn: ["verify-recipient"],
        status: RUNBOOK_STEP_STATUS.PLANNED,
        simulation: {
          provider: "keeperhub",
          status: "pending",
          action: "simulate_origin_investigation",
        },
        execution: {
          provider: "safe",
          status: "recommended_only",
          action: "execute_investigation_followup",
        },
        metadata: {
          options: ["rotate_compromised_keys", "add_transfer_guard", "move_funds_to_fallback_safe"],
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

module.exports = { compileLargeTransferRunbook };
