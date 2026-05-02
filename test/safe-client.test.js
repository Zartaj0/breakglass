const test = require("node:test");
const assert = require("node:assert/strict");

const {
  buildSafeApiErrorMessage,
  resolveSafeSourceConfig,
  toChecksumAddress,
} = require("../packages/integrations/src/safe-client");
const { readBooleanLike } = require("../packages/shared/src/models");

test("explains 404 errors for fresh Safes without indexed transaction history", () => {
  const message = buildSafeApiErrorMessage(404, "", {
    safeAddress: "0xsafe",
    chain: "base-sepolia",
  });

  assert.match(message, /could not find 0xsafe on base-sepolia/i);
  assert.match(message, /propose one pending Safe transaction first/i);
});

test("explains 401 errors as Safe API auth issues", () => {
  const message = buildSafeApiErrorMessage(401, "", {
    safeAddress: "0xsafe",
    chain: "base-sepolia",
  });

  assert.match(message, /401 Unauthorized/i);
  assert.match(message, /SAFE_API_KEY/i);
});

test("resolves Base Sepolia to the Safe tx-service slug basesep", () => {
  const config = resolveSafeSourceConfig({
    SAFE_PENDING_SOURCE: "live",
    SAFE_NETWORK: "base-sepolia",
  });

  assert.equal(config.chain, "basesep");
});

test("checksums lowercase Safe addresses before live API reads", () => {
  assert.equal(
    toChecksumAddress("0xead39d939a83a8e57a61b9ebf4209142df8ed690"),
    "0xead39d939A83A8e57a61b9ebf4209142Df8ED690",
  );
});

test("readBooleanLike tolerates surrounding whitespace", () => {
  assert.equal(readBooleanLike("true "), true);
  assert.equal(readBooleanLike(" false "), false);
});
