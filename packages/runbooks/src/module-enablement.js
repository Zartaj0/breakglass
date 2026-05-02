const {
  INCIDENT_SOURCE_STAGE,
  RUNBOOK_STEP_STATUS,
  buildRunbookPlan,
  buildRunbookStep,
} = require("../../shared/src/models");

function compileModuleEnablementRunbook(incident) {
  const ev = incident.evidence?.module ?? {};
  const transaction = incident.source?.transaction ?? {};
  const safeTxHash = transaction.safeTxHash ?? incident.source?.safeTxHash ?? null;

  return buildRunbookPlan({
    incident,
    templateId: "module-enablement-v1",
    title: "Module enablement mitigation plan",
    summary:
      "Deterministic response for a pending Safe module enablement: reject the enablement before it grants unrestricted execution access.",
    steps: [
      buildRunbookStep({
        stepId: "invalidate-pending-enablement",
        kind: "invalidate_pending_transaction",
        description: `Propose a Safe rejection transaction at nonce ${transaction.nonce} to block the module from being enabled before enough owners sign.`,
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
          moduleAddress: ev.address ?? null,
        },
      }),
      buildRunbookStep({
        stepId: "audit-module-code",
        kind: "audit_module_code",
        description: `Review the code and permissions of module ${ev.address ?? "unknown"} to determine if it poses an ongoing risk. Check if this or any other suspicious modules are already enabled.`,
        dependsOn: ["invalidate-pending-enablement"],
        status: RUNBOOK_STEP_STATUS.PLANNED,
        simulation: {
          provider: "keeperhub",
          status: "pending",
          action: "simulate_module_audit",
        },
        execution: {
          provider: "safe",
          status: "manual_review_required",
          action: "execute_module_disable",
        },
        metadata: {
          moduleAddress: ev.address ?? null,
        },
      }),
      buildRunbookStep({
        stepId: "harden-after-module-incident",
        kind: "harden_safe_configuration",
        description:
          "After containment, enumerate all currently enabled modules and disable any that are not on the approved list. Consider raising the signing threshold.",
        dependsOn: ["audit-module-code"],
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
          options: ["disable_unknown_modules", "raise_threshold", "move_funds_to_fallback_safe"],
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

module.exports = { compileModuleEnablementRunbook };
