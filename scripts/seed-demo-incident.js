const SafeApiKit = require("@safe-global/api-kit").default;
const Safe = require("@safe-global/protocol-kit").default;
const { Interface, MaxUint256, Wallet } = require("ethers");

const { loadDotEnv } = require("../packages/shared/src/load-env");
const {
  resolveSafeExecutionConfig,
} = require("../packages/integrations/src/safe-remediation");
const { normalizeAddress } = require("../packages/shared/src/models");

loadDotEnv({ override: true });

const DEFAULT_WETH9_ADDRESS = "0x4200000000000000000000000000000000000006";
const DEFAULT_SPENDER = "0xdeadbeef00000000000000000000000000000000";

function resolveSeedConfig(env = process.env) {
  const safeConfig = resolveSafeExecutionConfig(env);

  return {
    ...safeConfig,
    tokenAddress: normalizeAddress(
      env.BREAKGLASS_DEMO_TOKEN_ADDRESS ?? DEFAULT_WETH9_ADDRESS,
    ),
    spender: normalizeAddress(env.BREAKGLASS_DEMO_SPENDER ?? DEFAULT_SPENDER),
    amount:
      env.BREAKGLASS_DEMO_APPROVAL_AMOUNT ?? MaxUint256.toString(),
    origin:
      env.BREAKGLASS_DEMO_ORIGIN ??
      "BreakGlass Demo Seed - Suspicious Approval",
  };
}

function ensureSeedRequirements(config) {
  if (!config.safeAddress) {
    throw new Error("SAFE_ADDRESS is required.");
  }

  if (!config.rpcUrl) {
    throw new Error("SAFE_RPC_URL is required.");
  }

  if (!config.ownerPrivateKey) {
    throw new Error("SAFE_OWNER_PRIVATE_KEY is required.");
  }

  if (!config.txServiceUrl) {
    throw new Error(
      "SAFE_TX_SERVICE_URL or SAFE_API_KEY is required to propose the demo transaction.",
    );
  }

  if (!config.tokenAddress) {
    throw new Error("BREAKGLASS_DEMO_TOKEN_ADDRESS is required.");
  }

  if (!config.spender) {
    throw new Error("BREAKGLASS_DEMO_SPENDER is required.");
  }
}

function buildApprovalCalldata(spender, amount) {
  const iface = new Interface([
    "function approve(address spender, uint256 value)",
  ]);

  return iface.encodeFunctionData("approve", [spender, BigInt(amount)]);
}

async function createClients(config) {
  const protocolKit = await Safe.init({
    provider: config.rpcUrl,
    signer: config.ownerPrivateKey,
    safeAddress: config.safeAddress,
  });

  const apiKit = new SafeApiKit({
    chainId: BigInt(config.chainId),
    txServiceUrl: config.txServiceUrl,
    apiKey: config.apiKey || undefined,
  });

  return {
    protocolKit,
    apiKit,
  };
}

async function seedSuspiciousApproval(config = resolveSeedConfig()) {
  ensureSeedRequirements(config);

  const { protocolKit, apiKit } = await createClients(config);
  const proposerAddress = new Wallet(config.ownerPrivateKey).address;
  const data = buildApprovalCalldata(config.spender, config.amount);

  const safeTransaction = await protocolKit.createTransaction({
    transactions: [
      {
        to: config.tokenAddress,
        value: "0",
        data,
        operation: 0,
      },
    ],
  });

  const safeTxHash = await protocolKit.getTransactionHash(safeTransaction);
  const proposerSignature = await protocolKit.signHash(safeTxHash);

  await apiKit.proposeTransaction({
    safeAddress: config.safeAddress,
    safeTransactionData: safeTransaction.data,
    safeTxHash,
    senderAddress: proposerAddress,
    senderSignature: proposerSignature.data,
    origin: config.origin,
  });

  return {
    safeAddress: config.safeAddress,
    network: config.network,
    tokenAddress: config.tokenAddress,
    spender: config.spender,
    amount: config.amount,
    safeTxHash,
    proposerAddress,
    txServiceUrl: config.txServiceUrl,
    nextStep:
      "Run SAFE_PENDING_SOURCE=live node apps/watcher/src/cli.js or node apps/orchestrator/src/cli.js to detect the pending approval.",
  };
}

async function main() {
  const result = await seedSuspiciousApproval();
  console.log(JSON.stringify(result, null, 2));
}

if (require.main === module) {
  main().catch((error) => {
    console.error("[breakglass-seed-demo-incident] failed");
    console.error(error instanceof Error ? error.stack : error);
    process.exitCode = 1;
  });
}

module.exports = {
  buildApprovalCalldata,
  resolveSeedConfig,
  seedSuspiciousApproval,
};
