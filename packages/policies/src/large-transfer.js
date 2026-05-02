const {
  INCIDENT_SEVERITY,
  INCIDENT_SOURCE_STAGE,
  INCIDENT_TRIGGER_TYPES,
  buildIncidentCase,
  getParameterMap,
  normalizeAddress,
  toNumber,
  toStringValue,
} = require("../../shared/src/models");

const TRANSFER_METHODS = new Set(["transfer", "transferFrom"]);

const DEFAULT_MAX_ETH = "1000000000000000000"; // 1 ETH in wei
const DEFAULT_MAX_TOKEN = "100000000000000000000000"; // 100k tokens (18 dec)

function toBigInt(value, fallback = 0n) {
  try {
    if (value === null || value === undefined || value === "") return fallback;
    return BigInt(String(value));
  } catch {
    return fallback;
  }
}

function parseAddressSet(rawValue) {
  if (!rawValue) return new Set();
  return new Set(
    String(rawValue)
      .split(",")
      .map((v) => normalizeAddress(v))
      .filter(Boolean),
  );
}

function resolveTransferPolicyConfig(env = process.env) {
  return {
    maxEthWei: toBigInt(env.BREAKGLASS_MAX_ETH_TRANSFER, toBigInt(DEFAULT_MAX_ETH)),
    maxTokenUnits: toBigInt(env.BREAKGLASS_MAX_TOKEN_TRANSFER, toBigInt(DEFAULT_MAX_TOKEN)),
    allowedRecipients: parseAddressSet(env.BREAKGLASS_ALLOWED_RECIPIENTS),
  };
}

function detectLargeTransferIncident(transaction, policyConfig) {
  const method = transaction.dataDecoded?.method ?? "";
  const ethValue = toBigInt(transaction.value, 0n);

  let transferAmount = 0n;
  let recipient = null;
  let isEth = false;

  if (ethValue > 0n && !transaction.dataDecoded) {
    // Native ETH transfer (no calldata)
    transferAmount = ethValue;
    recipient = normalizeAddress(transaction.to);
    isEth = true;
  } else if (TRANSFER_METHODS.has(method)) {
    const params = getParameterMap(transaction);
    if (method === "transfer") {
      recipient = normalizeAddress(params.get("recipient") ?? params.get("to") ?? params.get("_to"));
      transferAmount = toBigInt(params.get("amount") ?? params.get("value") ?? params.get("_value"), 0n);
    } else if (method === "transferFrom") {
      recipient = normalizeAddress(params.get("recipient") ?? params.get("to") ?? params.get("_to"));
      transferAmount = toBigInt(params.get("amount") ?? params.get("value") ?? params.get("_value"), 0n);
    }
  } else {
    return null;
  }

  const threshold = isEth ? policyConfig.maxEthWei : policyConfig.maxTokenUnits;
  if (transferAmount <= threshold) return null;

  const unknownRecipient =
    recipient &&
    policyConfig.allowedRecipients.size > 0 &&
    !policyConfig.allowedRecipients.has(recipient);

  const severity = unknownRecipient ? INCIDENT_SEVERITY.HIGH : INCIDENT_SEVERITY.MEDIUM;

  const asset = isEth ? "ETH" : `token at ${transaction.to}`;
  const humanAmount = isEth
    ? `${(Number(transferAmount) / 1e18).toFixed(4)} ETH`
    : transferAmount.toString();

  const reasons = [
    {
      code: unknownRecipient ? "large_transfer_unknown_recipient" : "large_transfer",
      severity,
      message: unknownRecipient
        ? `Transferring ${humanAmount} of ${asset} to ${recipient}, which is not on the recipient allowlist.`
        : `Transferring ${humanAmount} of ${asset} — exceeds the configured transfer threshold.`,
    },
  ];

  return buildIncidentCase({
    safeAddress: transaction.safeAddress,
    network: transaction.network,
    triggerType: INCIDENT_TRIGGER_TYPES.LARGE_TRANSFER,
    sourceStage: INCIDENT_SOURCE_STAGE.PENDING_TRANSACTION,
    severity,
    title: "Large asset transfer pending",
    summary: `Pending transfer of ${humanAmount} to ${recipient ?? "unknown address"}.`,
    source: {
      kind: "safe_pending_transaction",
      safeTxHash: transaction.safeTxHash,
      transaction,
    },
    identity: {
      safeTxHash: transaction.safeTxHash ?? null,
      safeAddress: transaction.safeAddress,
      network: transaction.network,
      triggerType: INCIDENT_TRIGGER_TYPES.LARGE_TRANSFER,
      recipient: recipient ?? null,
      isEth,
      nonce: transaction.nonce,
    },
    evidence: {
      transfer: {
        recipient,
        amount: transferAmount.toString(),
        humanAmount,
        isEth,
        token: isEth ? null : transaction.to,
        unknownRecipient,
      },
      reasons,
      transaction: {
        to: transaction.to,
        nonce: transaction.nonce,
        confirmationsCollected: transaction.confirmationsCollected,
        confirmationsRequired: transaction.confirmationsRequired,
      },
    },
  });
}

function detectLargeTransferIncidents(transactions, policyConfig = resolveTransferPolicyConfig()) {
  return transactions
    .map((tx) => detectLargeTransferIncident(tx, policyConfig))
    .filter(Boolean);
}

module.exports = {
  TRANSFER_METHODS,
  detectLargeTransferIncident,
  detectLargeTransferIncidents,
  resolveTransferPolicyConfig,
};
