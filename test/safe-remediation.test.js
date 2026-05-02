const test = require("node:test");
const assert = require("node:assert/strict");

const {
  parseAlreadyExecutedSafeError,
  resolveSafeExecutionConfig,
} = require("../packages/integrations/src/safe-remediation");

test("builds Safe SDK tx-service URL with /api for Base Sepolia", () => {
  const config = resolveSafeExecutionConfig({
    SAFE_NETWORK: "base-sepolia",
    SAFE_API_CHAIN: "base-sepolia",
    SAFE_API_KEY: "test-key",
  });

  assert.equal(
    config.txServiceUrl,
    "https://api.safe.global/tx-service/basesep/api",
  );
});

test("normalizes explicit tx-service URLs to the SDK base path", () => {
  const config = resolveSafeExecutionConfig({
    SAFE_NETWORK: "base-sepolia",
    SAFE_TX_SERVICE_URL: "https://api.safe.global/tx-service/basesep/api/v2",
  });

  assert.equal(
    config.txServiceUrl,
    "https://api.safe.global/tx-service/basesep/api",
  );
});

test("preserves a checksummed Safe address for Safe SDK calls", () => {
  const config = resolveSafeExecutionConfig({
    SAFE_NETWORK: "base-sepolia",
    SAFE_ADDRESS: "0xead39d939a83a8e57a61b9ebf4209142df8ed690",
  });

  assert.equal(
    config.safeAddress,
    "0xead39d939A83A8e57a61b9ebf4209142Df8ED690",
  );
});

test("parses Safe tx-service already executed errors into a stable execution artifact", () => {
  const artifact = parseAlreadyExecutedSafeError(
    new Error(
      "Tx with safe-tx-hash=0xc5748d3acddd66c7464053b06c156b8a9dfd6b3d41780a45d7d4f6e2f3b824c8 for safe=0xead39d939A83A8e57a61b9ebf4209142Df8ED690 was already executed in tx-hash=0x36ad66f048982665279a2d6f884d80b620003b3cc156b461b0b20a779fd9dd29",
    ),
    "0xc5748d3acddd66c7464053b06c156b8a9dfd6b3d41780a45d7d4f6e2f3b824c8",
  );

  assert.deepEqual(artifact, {
    provider: "safe",
    mode: "live",
    status: "already_executed",
    safeTxHash: "0xc5748d3acddd66c7464053b06c156b8a9dfd6b3d41780a45d7d4f6e2f3b824c8",
    executionTxHash: "0x36ad66f048982665279a2d6f884d80b620003b3cc156b461b0b20a779fd9dd29",
    reason: "The containment transaction was already executed on the Safe before this run.",
  });
});
