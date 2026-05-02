const SafeApiKit = require("@safe-global/api-kit").default;
const Safe = require("@safe-global/protocol-kit").default;
const { Interface, Wallet, getAddress } = require("ethers");

const {
  SAFE_API_CHAIN_SLUGS,
} = require("./safe-client");
const {
  normalizeAddress,
  readBooleanLike,
  toNumber,
  toStringValue,
} = require("../../shared/src/models");

const SAFE_CHAIN_IDS = {
  // Mainnets
  arbitrum: 42161,
  avalanche: 43114,
  base: 8453,
  blast: 81457,
  bsc: 56,
  celo: 42220,
  ethereum: 1,
  gnosis: 100,
  linea: 59144,
  mainnet: 1,
  mantle: 5000,
  mode: 34443,
  optimism: 10,
  polygon: 137,
  "polygon-zkevm": 1101,
  scroll: 534352,
  worldchain: 480,
  zksync: 324,
  // Testnets
  "base-sepolia": 84532,
  "arbitrum-sepolia": 421614,
  "optimism-sepolia": 11155420,
  sepolia: 11155111,
  holesky: 17000,
};

const EXECUTABLE_STEP_KINDS = new Set([
  "invalidate_pending_approval",
  "invalidate_pending_transaction",
  "revoke_approval",
]);

function parseCsv(value) {
  if (!value) {
    return [];
  }

  return String(value)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function toChecksumAddress(value) {
  if (!value) {
    return null;
  }

  try {
    return getAddress(String(value).trim());
  } catch {
    return null;
  }
}

function normalizeTxServiceUrl(value) {
  if (!value) {
    return null;
  }

  return String(value)
    .replace(/\/api\/v2\/?$/, "/api")
    .replace(/\/api\/v1\/?$/, "/api")
    .replace(/\/v2\/?$/, "")
    .replace(/\/v1\/?$/, "")
    .replace(/\/$/, "");
}

function parseAlreadyExecutedSafeError(error, safeTxHash) {
  const message =
    error instanceof Error ? error.message : error ? String(error) : "";

  const match = message.match(
    /Tx with safe-tx-hash=(0x[a-fA-F0-9]+).*already executed in tx-hash=(0x[a-fA-F0-9]+)/,
  );

  if (!match) {
    return null;
  }

  return {
    provider: "safe",
    mode: "live",
    status: "already_executed",
    safeTxHash: safeTxHash ?? match[1],
    executionTxHash: match[2],
    reason:
      "The containment transaction was already executed on the Safe before this run.",
  };
}

function resolveSafeExecutionConfig(env = process.env) {
  const network = toStringValue(env.SAFE_NETWORK, "base-sepolia").trim().toLowerCase();
  const explicitChain = toStringValue(env.SAFE_API_CHAIN, "").trim().toLowerCase();
  const chain =
    (explicitChain ? SAFE_API_CHAIN_SLUGS[explicitChain] ?? explicitChain : null) ??
    SAFE_API_CHAIN_SLUGS[network] ??
    SAFE_API_CHAIN_SLUGS[network.toLowerCase()] ??
    network;
  const chainId = toNumber(
    env.SAFE_CHAIN_ID,
    SAFE_CHAIN_IDS[network] ?? SAFE_CHAIN_IDS[chain] ?? 84532,
  );
  const txServiceUrl =
    normalizeTxServiceUrl(env.SAFE_TX_SERVICE_URL) ??
    (env.SAFE_API_KEY ? `https://api.safe.global/tx-service/${chain}/api` : null);

  return {
    mode:
      toStringValue(env.SAFE_EXECUTION_MODE, "dry-run").trim().toLowerCase() === "live"
        ? "live"
        : "dry-run",
    network,
    chain,
    chainId,
    safeAddress: toChecksumAddress(env.SAFE_ADDRESS),
    rpcUrl: env.SAFE_RPC_URL ?? null,
    apiKey: env.SAFE_API_KEY ?? null,
    txServiceUrl,
    ownerPrivateKey: env.SAFE_OWNER_PRIVATE_KEY ?? null,
    confirmingOwnerKeys: parseCsv(env.SAFE_CONFIRMING_OWNER_KEYS),
    executeWhenReady: readBooleanLike(env.SAFE_EXECUTE_WHEN_READY),
    origin: toStringValue(env.BREAKGLASS_ORIGIN, "BreakGlass"),
  };
}

function isExecutableStep(step) {
  return EXECUTABLE_STEP_KINDS.has(step.kind);
}

function buildDryRunPreview(step, incident, config) {
  const preview = {
    safeAddress: incident.safeAddress ?? config.safeAddress ?? null,
    chainId: config.chainId,
    network: config.network,
    kind: step.kind,
  };

  if (
    step.kind === "invalidate_pending_approval" ||
    step.kind === "invalidate_pending_transaction"
  ) {
    return {
      ...preview,
      to: incident.safeAddress ?? config.safeAddress ?? null,
      value: "0",
      data: "0x",
      nonce: step.metadata?.nonce ?? incident.source?.transaction?.nonce ?? null,
    };
  }

  if (step.kind === "revoke_approval") {
    const token = step.metadata?.token ?? incident.source?.transaction?.to ?? null;
    const spender =
      step.metadata?.spender ?? incident.evidence?.approval?.spender ?? null;
    const method = incident.evidence?.approval?.method ?? "approve";
    const data = encodeRevokeApprovalData(method, spender);

    return {
      ...preview,
      to: token,
      value: "0",
      data,
      token,
      spender,
      method,
    };
  }

  return preview;
}

function encodeRevokeApprovalData(method, spender) {
  if (!spender) {
    throw new Error("Cannot encode approval reset without a spender address.");
  }

  if (method === "setApprovalForAll") {
    const iface = new Interface([
      "function setApprovalForAll(address operator, bool approved)",
    ]);
    return iface.encodeFunctionData("setApprovalForAll", [spender, false]);
  }

  const iface = new Interface([
    "function approve(address spender, uint256 value)",
  ]);
  return iface.encodeFunctionData("approve", [spender, 0n]);
}

async function buildSafeTransaction(protocolKit, step, incident) {
  if (
    step.kind === "invalidate_pending_approval" ||
    step.kind === "invalidate_pending_transaction"
  ) {
    const nonce = toNumber(
      step.metadata?.nonce ?? incident.source?.transaction?.nonce,
      -1,
    );

    if (nonce < 0) {
      throw new Error("Incident does not include a valid Safe nonce to reject.");
    }

    return protocolKit.createRejectionTransaction(nonce);
  }

  if (step.kind === "revoke_approval") {
    const token = normalizeAddress(
      step.metadata?.token ?? incident.source?.transaction?.to,
    );
    const spender = normalizeAddress(
      step.metadata?.spender ?? incident.evidence?.approval?.spender,
    );
    const method = incident.evidence?.approval?.method ?? "approve";

    if (!token) {
      throw new Error("Cannot build revoke transaction without a token address.");
    }

    const data = encodeRevokeApprovalData(method, spender);

    return protocolKit.createTransaction({
      transactions: [
        {
          to: token,
          value: "0",
          data,
          operation: 0,
        },
      ],
    });
  }

  throw new Error(`Unsupported remediation step kind: ${step.kind}`);
}

async function createLiveClients(config) {
  if (!config.safeAddress) {
    throw new Error("SAFE_ADDRESS is required for live Safe remediation.");
  }

  if (!config.rpcUrl) {
    throw new Error("SAFE_RPC_URL is required for live Safe remediation.");
  }

  if (!config.ownerPrivateKey) {
    throw new Error("SAFE_OWNER_PRIVATE_KEY is required for live Safe remediation.");
  }

  if (!config.txServiceUrl) {
    throw new Error(
      "SAFE_TX_SERVICE_URL or SAFE_API_KEY is required for Safe transaction service access.",
    );
  }

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

async function executeMitigationStep(
  step,
  incident,
  config = resolveSafeExecutionConfig(),
) {
  if (!isExecutableStep(step)) {
    return {
      provider: "safe",
      mode: config.mode,
      status: "skipped",
      reason: `Step kind ${step.kind} is not executable in the current MVP.`,
    };
  }

  if (config.mode !== "live") {
    return {
      provider: "safe",
      mode: "dry-run",
      status: "prepared",
      summary:
        "Prepared a real Safe transaction blueprint. Switch SAFE_EXECUTION_MODE=live with signer credentials to propose it.",
      preview: buildDryRunPreview(step, incident, config),
    };
  }

  const { protocolKit, apiKit } = await createLiveClients(config);
  const safeInfo = await apiKit.getSafeInfo(config.safeAddress);
  const safeTransaction = await buildSafeTransaction(protocolKit, step, incident);
  const safeTxHash = await protocolKit.getTransactionHash(safeTransaction);
  const proposerSignature = await protocolKit.signHash(safeTxHash);
  const proposerAddress = new Wallet(config.ownerPrivateKey).address;
  let alreadyExecutedArtifact = null;

  try {
    await apiKit.proposeTransaction({
      safeAddress: config.safeAddress,
      safeTransactionData: safeTransaction.data,
      safeTxHash,
      senderAddress: proposerAddress,
      senderSignature: proposerSignature.data,
      origin: config.origin,
    });
  } catch (error) {
    alreadyExecutedArtifact = parseAlreadyExecutedSafeError(error, safeTxHash);

    if (!alreadyExecutedArtifact) {
      throw error;
    }
  }

  if (alreadyExecutedArtifact) {
    return {
      ...alreadyExecutedArtifact,
      preview: buildDryRunPreview(step, incident, config),
      threshold: toNumber(safeInfo.threshold, 0),
      confirmationsCollected: null,
      confirmedOwners: [],
      executionResponse: null,
    };
  }

  const confirmedOwners = new Set([proposerAddress.toLowerCase()]);

  for (const confirmingOwnerKey of config.confirmingOwnerKeys) {
    const confirmerAddress = new Wallet(confirmingOwnerKey).address;
    const confirmer = await Safe.init({
      provider: config.rpcUrl,
      signer: confirmingOwnerKey,
      safeAddress: config.safeAddress,
    });
    const confirmationSignature = await confirmer.signHash(safeTxHash);

    await apiKit.confirmTransaction(safeTxHash, confirmationSignature.data);
    confirmedOwners.add(confirmerAddress.toLowerCase());
  }

  const threshold = toNumber(safeInfo.threshold, confirmedOwners.size);
  const executionReady = confirmedOwners.size >= threshold;
  let executionTxHash = null;
  let executionResponse = null;

  if (config.executeWhenReady && executionReady) {
    const serviceTransaction = await apiKit.getTransaction(safeTxHash);
    const result = await protocolKit.executeTransaction(serviceTransaction);

    executionTxHash = result.hash ?? null;
    executionResponse = result.transactionResponse ?? null;
  }

  return {
    provider: "safe",
    mode: "live",
    status:
      executionTxHash !== null
        ? "executed"
        : executionReady
          ? "proposed_and_confirmed"
          : "proposed_waiting_for_confirmations",
    safeTxHash,
    executionTxHash,
    threshold,
    confirmationsCollected: confirmedOwners.size,
    confirmedOwners: Array.from(confirmedOwners),
    preview: buildDryRunPreview(step, incident, config),
    executionResponse,
  };
}

module.exports = {
  EXECUTABLE_STEP_KINDS,
  executeMitigationStep,
  isExecutableStep,
  parseAlreadyExecutedSafeError,
  resolveSafeExecutionConfig,
};
