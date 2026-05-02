const {
  INCIDENT_SOURCE_STAGE,
  RUNBOOK_STEP_STATUS,
  buildRunbookPlan,
  buildRunbookStep,
} = require("../../shared/src/models");

function compileOwnershipChangeRunbook(incident) {
  const ev = incident.evidence?.ownership ?? {};
  const transaction = incident.source?.transaction ?? {};
  const safeTxHash = transaction.safeTxHash ?? incident.source?.safeTxHash ?? null;

  return buildRunbookPlan({
    incident,
    templateId: "ownership-change-v1",
    title: "Ownership change mitigation plan",
    summary:
      "Deterministic response for a pending Safe ownership modification: reject the queued change, audit the current owner set, then review threshold and access controls.",
    steps: [
      buildRunbookStep({
        stepId: "invalidate-pending-change",
        kind: "invalidate_pending_transaction",
        description: `Propose a Safe rejection transaction at nonce ${transaction.nonce} to block the ownership change before it can be signed by enough owners.`,
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
          affectedOwner: ev.affectedOwner ?? null,
          method: ev.method ?? null,
        },
      }),
      buildRunbookStep({
        stepId: "audit-owner-set",
        kind: "audit_ownership_set",
        description:
          "Review all current Safe owners and confirm each address is still trusted. Remove any compromised or unknown owners immediately.",
        dependsOn: ["invalidate-pending-change"],
        status: RUNBOOK_STEP_STATUS.PLANNED,
        simulation: {
          provider: "keeperhub",
          status: "pending",
          action: "simulate_ownership_audit",
        },
        execution: {
          provider: "safe",
          status: "manual_review_required",
          action: "execute_ownership_remediation",
        },
        metadata: {},
      }),
      buildRunbookStep({
        stepId: "harden-after-ownership-incident",
        kind: "harden_safe_configuration",
        description:
          "After the immediate threat is contained, raise the signing threshold if it was at risk of falling below policy minimum, and rotate any compromised signing keys.",
        dependsOn: ["audit-owner-set"],
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
          options: ["raise_threshold", "rotate_signing_keys", "move_funds_to_fallback_safe"],
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

module.exports = { compileOwnershipChangeRunbook };
