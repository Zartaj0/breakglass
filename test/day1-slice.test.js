const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  normalizeSafePendingTransaction,
} = require("../packages/shared/src/models");
const {
  detectSuspiciousApprovalIncidents,
  resolvePolicyConfig,
} = require("../packages/policies/src/suspicious-approval");
const {
  compileApprovalExposureRunbook,
} = require("../packages/runbooks/src/approval-exposure");

function loadFixtureTransactions() {
  const fixturePath = path.resolve(
    __dirname,
    "..",
    "apps",
    "watcher",
    "fixtures",
    "pending-transactions.json",
  );
  const payload = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  return payload.transactions;
}

test("normalizes fixture transactions into shared pending-tx schema", () => {
  const [transaction] = loadFixtureTransactions().map((raw) =>
    normalizeSafePendingTransaction(raw, {
      network: "base-sepolia",
    }),
  );

  assert.equal(transaction.safeAddress, "0x7a5b0f2a641fd36f8450ed8d3b4e8a1d6339a4f5");
  assert.equal(transaction.operationLabel, "CALL");
  assert.equal(transaction.dataDecoded.method, "approve");
  assert.equal(transaction.confirmationsCollected, 1);
});

test("detects one suspicious approval incident from the day-1 fixture", () => {
  const transactions = loadFixtureTransactions().map((raw) =>
    normalizeSafePendingTransaction(raw, {
      network: "base-sepolia",
    }),
  );
  const incidents = detectSuspiciousApprovalIncidents(
    transactions,
    resolvePolicyConfig({
      BREAKGLASS_ALLOWED_SPENDERS:
        "0x1111111111111111111111111111111111111111",
      BREAKGLASS_APPROVAL_THRESHOLD: "100000000000000000000000",
    }),
  );

  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].triggerType, "suspicious_approval");
  assert.equal(incidents[0].severity, "critical");
});

test("compiles the deterministic approval exposure runbook", () => {
  const transactions = loadFixtureTransactions().map((raw) =>
    normalizeSafePendingTransaction(raw, {
      network: "base-sepolia",
    }),
  );
  const [incident] = detectSuspiciousApprovalIncidents(
    transactions,
    resolvePolicyConfig({
      BREAKGLASS_ALLOWED_SPENDERS:
        "0x1111111111111111111111111111111111111111",
      BREAKGLASS_APPROVAL_THRESHOLD: "100000000000000000000000",
    }),
  );

  const runbook = compileApprovalExposureRunbook(incident);

  assert.equal(runbook.templateId, "approval-exposure-v1");
  assert.equal(runbook.steps.length, 3);
  assert.deepEqual(runbook.steps[1].dependsOn, ["invalidate-pending-approval"]);
  assert.equal(runbook.steps[0].kind, "invalidate_pending_approval");
});

test("detects high-value increaseAllowance approvals using addedValue", () => {
  const transaction = normalizeSafePendingTransaction(
    {
      safeTxHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
      safe: "0x7A5b0F2a641fD36f8450eD8D3B4E8A1D6339a4F5",
      to: "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      value: "0",
      operation: 0,
      nonce: 44,
      confirmationsRequired: 2,
      confirmationsCollected: 1,
      dataDecoded: {
        method: "increaseAllowance",
        parameters: [
          {
            name: "spender",
            type: "address",
            value: "0xDeaDbeEF00000000000000000000000000000000",
          },
          {
            name: "addedValue",
            type: "uint256",
            value: "500000000000000000000000",
          },
        ],
      },
    },
    {
      network: "base-sepolia",
    },
  );

  const [incident] = detectSuspiciousApprovalIncidents(
    [transaction],
    resolvePolicyConfig({
      BREAKGLASS_ALLOWED_SPENDERS:
        "0x1111111111111111111111111111111111111111",
      BREAKGLASS_APPROVAL_THRESHOLD: "100000000000000000000000",
    }),
  );

  assert.equal(incident.triggerType, "suspicious_approval");
  assert.match(
    JSON.stringify(incident.evidence.reasons),
    /high_value_approval/,
  );
});

test("keeps incident ids stable across policy changes for the same transaction", () => {
  const transactions = loadFixtureTransactions().map((raw) =>
    normalizeSafePendingTransaction(raw, {
      network: "base-sepolia",
    }),
  );
  const [firstIncident] = detectSuspiciousApprovalIncidents(
    transactions,
    resolvePolicyConfig({
      BREAKGLASS_ALLOWED_SPENDERS: "",
      BREAKGLASS_APPROVAL_THRESHOLD: "100000000000000000000000",
    }),
  );
  const [secondIncident] = detectSuspiciousApprovalIncidents(
    transactions,
    resolvePolicyConfig({
      BREAKGLASS_ALLOWED_SPENDERS:
        "0xdeadbeef00000000000000000000000000000000",
      BREAKGLASS_APPROVAL_THRESHOLD: "1",
    }),
  );

  assert.equal(firstIncident.incidentId, secondIncident.incidentId);
});
