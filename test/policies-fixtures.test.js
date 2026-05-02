const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");

const {
  normalizeSafePendingTransaction,
} = require("../packages/shared/src/models");
const {
  detectAllIncidents,
  resolveAllPolicyConfigs,
} = require("../packages/policies/src/index");

function loadFixtureTransactions() {
  const payload = JSON.parse(
    fs.readFileSync("test/fixtures/safe-policy-transactions.json", "utf8"),
  );

  return payload.transactions.map((transaction) =>
    normalizeSafePendingTransaction(transaction, {
      network: "base-sepolia",
      safeAddress: transaction.safe,
    }),
  );
}

test("detectAllIncidents flags all 4 non-approval Safe policy fixtures", () => {
  const incidents = detectAllIncidents(
    loadFixtureTransactions(),
    resolveAllPolicyConfigs({
      BREAKGLASS_ALLOWED_OWNERS: "0x1111111111111111111111111111111111111111",
      BREAKGLASS_MIN_THRESHOLD: "2",
      BREAKGLASS_ALLOWED_MODULES: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      BREAKGLASS_MAX_ETH_TRANSFER: "1000000000000000000",
      BREAKGLASS_MAX_TOKEN_TRANSFER: "1000000000000000000000",
      BREAKGLASS_ALLOWED_RECIPIENTS: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      BREAKGLASS_ALLOWED_SPENDERS: "",
      BREAKGLASS_APPROVAL_THRESHOLD: "100000000000000000000000",
    }),
  );

  const triggerTypes = incidents.map((incident) => incident.triggerType).sort();

  assert.deepEqual(triggerTypes, [
    "large_transfer",
    "module_enablement",
    "ownership_change",
    "threshold_reduction",
  ]);
});
