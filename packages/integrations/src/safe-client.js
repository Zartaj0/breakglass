const fs = require("node:fs/promises");
const path = require("node:path");
const { getAddress } = require("ethers");

const {
  normalizeSafePendingTransaction,
  toNumber,
  toStringValue,
} = require("../../shared/src/models");

const SAFE_API_CHAIN_SLUGS = {
  // Mainnets
  arbitrum: "arb1",
  avalanche: "avax",
  base: "base",
  blast: "blastmainnet",
  bsc: "bnb",
  celo: "celo",
  ethereum: "eth",
  gnosis: "gno",
  linea: "linea",
  mainnet: "eth",
  mantle: "mantle",
  mode: "mode",
  optimism: "oeth",
  polygon: "matic",
  "polygon-zkevm": "zkevm",
  scroll: "scr",
  worldchain: "worldchain",
  zksync: "zksync",
  // Testnets
  "base-sepolia": "basesep",
  "arbitrum-sepolia": "arbsep",
  "optimism-sepolia": "opsep",
  sepolia: "sep",
  holesky: "holesky",
};

function resolveSafeSourceConfig(env = process.env) {
  const network = toStringValue(env.SAFE_NETWORK, "base-sepolia").trim().toLowerCase();
  const explicitChain = toStringValue(env.SAFE_API_CHAIN, "").trim().toLowerCase();
  const chain =
    (explicitChain ? SAFE_API_CHAIN_SLUGS[explicitChain] ?? explicitChain : null) ??
    SAFE_API_CHAIN_SLUGS[network] ??
    SAFE_API_CHAIN_SLUGS[network.toLowerCase()] ??
    network;

  return {
    source:
      toStringValue(env.SAFE_PENDING_SOURCE, "fixture").trim().toLowerCase() === "live"
        ? "live"
        : "fixture",
    safeAddress: env.SAFE_ADDRESS ?? null,
    network,
    chain,
    apiKey: env.SAFE_API_KEY ?? null,
    apiBaseUrl: env.SAFE_API_BASE_URL ?? null,
    limit: toNumber(env.SAFE_PENDING_LIMIT, 20),
    fixturePath:
      env.WATCHER_FIXTURE_PATH ??
      path.join("apps", "watcher", "fixtures", "pending-transactions.json"),
  };
}

function resolveWorkspacePath(relativeOrAbsolutePath) {
  if (path.isAbsolute(relativeOrAbsolutePath)) {
    return relativeOrAbsolutePath;
  }

  return path.resolve(process.cwd(), relativeOrAbsolutePath);
}

async function readFixturePayload(fixturePath) {
  const resolvedPath = resolveWorkspacePath(fixturePath);
  const raw = await fs.readFile(resolvedPath, "utf8");
  const payload = JSON.parse(raw);

  return {
    payload,
    resolvedPath,
  };
}

function extractTransactions(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (Array.isArray(payload?.transactions)) {
    return payload.transactions;
  }

  if (Array.isArray(payload?.results)) {
    return payload.results;
  }

  return [];
}

function ensureSafeApiBaseUrl(config) {
  if (config.apiBaseUrl) {
    return config.apiBaseUrl.replace(/\/$/, "");
  }

  return `https://api.safe.global/tx-service/${config.chain}/api/v2`;
}

function toChecksumAddress(value) {
  if (!value) {
    return null;
  }

  try {
    return getAddress(String(value).trim());
  } catch {
    return value;
  }
}

function buildSafeApiErrorMessage(status, body, config) {
  if (status === 401) {
    return "Safe API rejected the request with 401 Unauthorized. Check SAFE_API_KEY or SAFE_TX_SERVICE_URL.";
  }

  if (status === 404) {
    return `Safe Transaction Service could not find ${config.safeAddress} on ${config.chain}. This usually means the Safe has no indexed transaction history yet. Propose one pending Safe transaction first, then rerun BreakGlass.`;
  }

  return `Safe API request failed with ${status}: ${body.slice(0, 400)}`;
}

async function fetchPendingTransactionsFromSafeApi(config) {
  if (!config.safeAddress) {
    throw new Error("SAFE_ADDRESS is required for live Safe fetching.");
  }

  const baseUrl = ensureSafeApiBaseUrl(config);
  const safeAddress = toChecksumAddress(config.safeAddress);
  const url = new URL(
    `${baseUrl}/safes/${safeAddress}/multisig-transactions/`,
  );
  url.searchParams.set("executed", "false");
  url.searchParams.set("limit", String(config.limit));
  url.searchParams.set("ordering", "-nonce");

  const headers = {
    Accept: "application/json",
  };

  if (config.apiKey) {
    headers.Authorization = `Bearer ${config.apiKey}`;
  }

  const response = await fetch(url, {
    headers,
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(buildSafeApiErrorMessage(response.status, body, config));
  }

  return response.json();
}

async function getPendingTransactions(config = resolveSafeSourceConfig()) {
  const fetchedAt = new Date().toISOString();
  let payload;
  let sourceDetails;

  if (config.source === "live") {
    payload = await fetchPendingTransactionsFromSafeApi(config);
    sourceDetails = {
      kind: "safe_api",
      apiBaseUrl: ensureSafeApiBaseUrl(config),
      chain: config.chain,
    };
  } else {
    const fixture = await readFixturePayload(config.fixturePath);
    payload = fixture.payload;
    sourceDetails = {
      kind: "fixture",
      fixturePath: fixture.resolvedPath,
    };
  }

  const transactions = extractTransactions(payload).map((transaction) =>
    normalizeSafePendingTransaction(transaction, {
      network: config.network,
      safeAddress: config.safeAddress,
    }),
  );
  const inferredSafeAddress =
    config.safeAddress ?? transactions[0]?.safeAddress ?? null;

  return {
    fetchedAt,
    source: sourceDetails,
    safeAddress: inferredSafeAddress,
    network: config.network,
    transactions,
    rawCount: toNumber(payload?.count, transactions.length),
  };
}

module.exports = {
  SAFE_API_CHAIN_SLUGS,
  buildSafeApiErrorMessage,
  getPendingTransactions,
  resolveSafeSourceConfig,
  toChecksumAddress,
};
