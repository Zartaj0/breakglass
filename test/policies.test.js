const test = require("node:test");
const assert = require("node:assert/strict");

const {
  detectOwnershipChangeIncident,
  resolveOwnershipPolicyConfig,
} = require("../packages/policies/src/ownership-change");
const {
  detectThresholdReductionIncident,
  resolveThresholdPolicyConfig,
} = require("../packages/policies/src/threshold-reduction");
const {
  detectModuleEnablementIncident,
  resolveModulePolicyConfig,
} = require("../packages/policies/src/module-enablement");
const {
  detectLargeTransferIncident,
  resolveTransferPolicyConfig,
} = require("../packages/policies/src/large-transfer");

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function makeTx(overrides = {}) {
  return {
    safeTxHash: "0xabc",
    safeAddress: "0xsafe",
    network: "base-sepolia",
    to: "0xdestination",
    value: "0",
    nonce: 5,
    confirmationsCollected: 1,
    confirmationsRequired: 2,
    dataDecoded: null,
    ...overrides,
  };
}

function decodeParams(params) {
  return {
    parameters: params.map(([name, value]) => ({ name, value })),
  };
}

// ---------------------------------------------------------------------------
// ownership-change
// ---------------------------------------------------------------------------

test("detects addOwnerWithThreshold with unknown owner as CRITICAL", () => {
  const policy = resolveOwnershipPolicyConfig({
    BREAKGLASS_ALLOWED_OWNERS: "0xknownowner",
    BREAKGLASS_MIN_THRESHOLD: "2",
  });

  const tx = makeTx({
    dataDecoded: {
      method: "addOwnerWithThreshold",
      ...decodeParams([["owner", "0xunknownowner"], ["_threshold", "2"]]),
    },
  });

  const incident = detectOwnershipChangeIncident(tx, policy);

  assert.ok(incident, "should detect incident");
  assert.equal(incident.severity, "critical");
  assert.equal(incident.triggerType, "ownership_change");
  const codes = incident.evidence.reasons.map((r) => r.code);
  assert.ok(codes.includes("unknown_owner_addition"));
});

test("detects removeOwner as HIGH when no allowlist is set", () => {
  const policy = resolveOwnershipPolicyConfig({
    BREAKGLASS_ALLOWED_OWNERS: "",
    BREAKGLASS_MIN_THRESHOLD: "2",
  });

  const tx = makeTx({
    dataDecoded: {
      method: "removeOwner",
      ...decodeParams([["owner", "0xsomeowner"], ["_threshold", "2"]]),
    },
  });

  const incident = detectOwnershipChangeIncident(tx, policy);

  assert.ok(incident, "should detect incident");
  assert.equal(incident.severity, "high");
  assert.equal(incident.triggerType, "ownership_change");
});

test("ignores transactions that are not ownership changes", () => {
  const policy = resolveOwnershipPolicyConfig({});
  const tx = makeTx({ dataDecoded: { method: "approve", ...decodeParams([]) } });
  assert.equal(detectOwnershipChangeIncident(tx, policy), null);
});

// ---------------------------------------------------------------------------
// threshold-reduction
// ---------------------------------------------------------------------------

test("detects changeThreshold to 1 as CRITICAL", () => {
  const policy = resolveThresholdPolicyConfig({ BREAKGLASS_MIN_THRESHOLD: "2" });

  const tx = makeTx({
    dataDecoded: {
      method: "changeThreshold",
      ...decodeParams([["_threshold", "1"]]),
    },
  });

  const incident = detectThresholdReductionIncident(tx, policy);

  assert.ok(incident, "should detect incident");
  assert.equal(incident.severity, "critical");
  assert.equal(incident.triggerType, "threshold_reduction");
  assert.equal(incident.evidence.threshold.proposedThreshold, 1);
});

test("detects changeThreshold below minThreshold as HIGH", () => {
  const policy = resolveThresholdPolicyConfig({ BREAKGLASS_MIN_THRESHOLD: "3" });

  const tx = makeTx({
    dataDecoded: {
      method: "changeThreshold",
      ...decodeParams([["_threshold", "2"]]),
    },
  });

  const incident = detectThresholdReductionIncident(tx, policy);

  assert.ok(incident, "should detect incident");
  assert.equal(incident.severity, "high");
});

test("ignores non-threshold transactions", () => {
  const policy = resolveThresholdPolicyConfig({});
  const tx = makeTx({ dataDecoded: { method: "addOwnerWithThreshold", ...decodeParams([]) } });
  assert.equal(detectThresholdReductionIncident(tx, policy), null);
});

// ---------------------------------------------------------------------------
// module-enablement
// ---------------------------------------------------------------------------

test("detects enableModule with unknown module as CRITICAL", () => {
  const policy = resolveModulePolicyConfig({
    BREAKGLASS_ALLOWED_MODULES: "0xapprovedmodule",
  });

  const tx = makeTx({
    dataDecoded: {
      method: "enableModule",
      ...decodeParams([["module", "0xunknownmodule"]]),
    },
  });

  const incident = detectModuleEnablementIncident(tx, policy);

  assert.ok(incident, "should detect incident");
  assert.equal(incident.severity, "critical");
  assert.equal(incident.triggerType, "module_enablement");
  assert.equal(incident.evidence.module.isUnknown, true);
});

test("detects enableModule as HIGH when allowlist is empty", () => {
  const policy = resolveModulePolicyConfig({ BREAKGLASS_ALLOWED_MODULES: "" });

  const tx = makeTx({
    dataDecoded: {
      method: "enableModule",
      ...decodeParams([["module", "0xanymodule"]]),
    },
  });

  const incident = detectModuleEnablementIncident(tx, policy);

  assert.ok(incident, "should detect incident");
  assert.equal(incident.severity, "high");
});

test("ignores non-enableModule transactions", () => {
  const policy = resolveModulePolicyConfig({});
  const tx = makeTx({ dataDecoded: { method: "disableModule", ...decodeParams([]) } });
  assert.equal(detectModuleEnablementIncident(tx, policy), null);
});

// ---------------------------------------------------------------------------
// large-transfer
// ---------------------------------------------------------------------------

test("detects native ETH transfer exceeding threshold as MEDIUM", () => {
  const policy = resolveTransferPolicyConfig({
    BREAKGLASS_MAX_ETH_TRANSFER: "1000000000000000000", // 1 ETH
    BREAKGLASS_ALLOWED_RECIPIENTS: "",
  });

  // 2 ETH transfer — no calldata
  const tx = makeTx({ value: "2000000000000000000", dataDecoded: null });

  const incident = detectLargeTransferIncident(tx, policy);

  assert.ok(incident, "should detect incident");
  assert.equal(incident.severity, "medium");
  assert.equal(incident.triggerType, "large_transfer");
  assert.equal(incident.evidence.transfer.isEth, true);
});

test("detects ERC-20 transfer to unknown recipient as HIGH", () => {
  const policy = resolveTransferPolicyConfig({
    BREAKGLASS_MAX_TOKEN_TRANSFER: "1000000000000000000", // 1 token unit
    BREAKGLASS_ALLOWED_RECIPIENTS: "0xapprovedrecipient",
  });

  const tx = makeTx({
    to: "0xtokencontract",
    value: "0",
    dataDecoded: {
      method: "transfer",
      ...decodeParams([["recipient", "0xunknownrecipient"], ["amount", "2000000000000000000"]]),
    },
  });

  const incident = detectLargeTransferIncident(tx, policy);

  assert.ok(incident, "should detect incident");
  assert.equal(incident.severity, "high");
  assert.equal(incident.evidence.transfer.unknownRecipient, true);
});

test("ignores ERC-20 transfer below threshold", () => {
  const policy = resolveTransferPolicyConfig({
    BREAKGLASS_MAX_TOKEN_TRANSFER: "100000000000000000000", // 100 tokens
    BREAKGLASS_ALLOWED_RECIPIENTS: "",
  });

  const tx = makeTx({
    to: "0xtokencontract",
    value: "0",
    dataDecoded: {
      method: "transfer",
      ...decodeParams([["recipient", "0xsomerecipient"], ["amount", "1000000000000000000"]]), // 1 token
    },
  });

  assert.equal(detectLargeTransferIncident(tx, policy), null);
});

test("ignores unrelated transactions (e.g. approve)", () => {
  const policy = resolveTransferPolicyConfig({});
  const tx = makeTx({
    value: "0",
    dataDecoded: { method: "approve", ...decodeParams([["spender", "0xabc"], ["value", "99999999"]]) },
  });
  assert.equal(detectLargeTransferIncident(tx, policy), null);
});
