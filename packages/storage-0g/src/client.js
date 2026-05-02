const fs = require("node:fs/promises");
const path = require("node:path");

const { Indexer, MemData } = require("@0glabs/0g-ts-sdk");
const { JsonRpcProvider, Wallet, Contract, Interface, AbiCoder } = require("ethers");

// The deployed Flow proxy uses a different submit selector than the SDK expects.
// The SDK was built for selector 0xef3e12dc ("submit((uint256,bytes,(bytes32,uint256)[]))").
// The live testnet proxy routes to implementation 0xF99cccc4B74F5dF79391EEa4E2A12Dae6084292F
// where the submit function has selector 0x6d7ad0fc.
const FLOW_SUBMIT_SELECTOR = "0x6d7ad0fc";

// ABI fragment matching the submission struct shape the SDK builds
const SUBMIT_IFACE = new Interface([
  "function _submit((uint256 length, bytes tags, (bytes32 root, uint256 height)[] nodes)) returns (bytes32)",
]);

function resolveReceiptStorageConfig(env = process.env) {
  const artifactDir = path.resolve(
    process.cwd(),
    env.BREAKGLASS_ARTIFACT_DIR ?? "artifacts",
  );

  return {
    mode:
      String(env.BREAKGLASS_RECEIPT_STORAGE ?? "file").trim().toLowerCase() === "0g"
        ? "0g"
        : "file",
    artifactDir,
    receiptDir: path.join(artifactDir, "receipts"),
    reportPath: path.join(artifactDir, "latest-report.json"),
    zeroGRpcUrl: env.ZERO_G_RPC_URL ?? "https://evmrpc-testnet.0g.ai",
    zeroGIndexerUrl:
      env.ZERO_G_INDEXER_URL ?? "https://indexer-storage-testnet-turbo.0g.ai",
    zeroGPrivateKey: env.ZERO_G_PRIVATE_KEY ?? null,
  };
}

function buildLocalReceiptPath(receiptId, config) {
  return path.join(config.receiptDir, `${receiptId}.json`);
}

async function writeReceiptMirror(receipt, config = resolveReceiptStorageConfig()) {
  await fs.mkdir(config.receiptDir, { recursive: true });
  const filePath = buildLocalReceiptPath(receipt.receiptId, config);
  await fs.writeFile(filePath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  return filePath;
}

async function writeLatestReport(report, config = resolveReceiptStorageConfig()) {
  await fs.mkdir(config.artifactDir, { recursive: true });
  await fs.writeFile(
    config.reportPath,
    `${JSON.stringify(report, null, 2)}\n`,
    "utf8",
  );
  return config.reportPath;
}

async function readReceiptMirror(receiptId, config = resolveReceiptStorageConfig()) {
  const filePath = buildLocalReceiptPath(receiptId, config);
  const raw = await fs.readFile(filePath, "utf8");
  return { filePath, receipt: JSON.parse(raw) };
}

// Submit the file on-chain using the correct selector for the live testnet proxy,
// then wait for storage nodes to index it, then upload segments.
async function uploadTo0G(data, config) {
  const provider = new JsonRpcProvider(config.zeroGRpcUrl);
  const signer = new Wallet(config.zeroGPrivateKey, provider);
  const indexer = new Indexer(config.zeroGIndexerUrl);

  const memData = new MemData(data);
  const [tree, treeErr] = await memData.merkleTree();
  if (treeErr) throw new Error(`0G merkle tree error: ${treeErr}`);

  const rootHash = tree.rootHash();
  const [submission, subErr] = await memData.createSubmission("0x");
  if (subErr) throw new Error(`0G submission build error: ${subErr}`);

  // Encode calldata with the correct live selector
  const innerEncoded = SUBMIT_IFACE.encodeFunctionData("_submit", [[
    submission.length,
    submission.tags,
    submission.nodes.map((n) => [n.root, n.height]),
  ]]);
  const calldata = FLOW_SUBMIT_SELECTOR + innerEncoded.slice(10);

  // Get the Flow address from an indexer node
  const [uploader, uplErr] = await indexer.newUploaderFromIndexerNodes(
    config.zeroGRpcUrl, signer, 1, { gasPrice: 0, gasLimit: 3000000 },
  );
  if (uplErr) throw new Error(`0G uploader init error: ${uplErr}`);

  const flowAddr = uploader.flow.target ?? uploader.flow.address;

  // Submit on-chain
  const tx = await signer.sendTransaction({
    to: flowAddr,
    data: calldata,
    value: 0n,
    gasLimit: 3000000,
  });
  const receipt = await tx.wait();
  if (!receipt || receipt.status !== 1) {
    throw new Error(`0G submit tx failed: status ${receipt?.status}`);
  }
  const txHash = receipt.hash;

  // Poll storage nodes until they index our submission (max 60s)
  let fileInfo = null;
  for (let i = 0; i < 12; i++) {
    await new Promise((r) => setTimeout(r, 5000));
    for (const node of uploader.nodes) {
      try {
        const info = await node.getFileInfo(rootHash, false);
        if (info !== null) { fileInfo = info; break; }
      } catch { /* node not ready yet */ }
    }
    if (fileInfo) break;
  }

  if (!fileInfo) {
    // Submission is on-chain but nodes haven't indexed it yet — return partial success
    return {
      kind: "0g_storage",
      status: "submitted",
      rootHash,
      txHash,
      note: "On-chain submit confirmed. Segment upload pending node indexing.",
      indexerUrl: config.zeroGIndexerUrl,
      rpcUrl: config.zeroGRpcUrl,
    };
  }

  // Upload segments to storage nodes
  const tasks = await uploader.splitTasks(fileInfo, tree, {
    taskSize: 10,
    expectedReplica: 1,
  });

  if (tasks && tasks.length > 0) {
    const results = await uploader.processTasksInParallel(memData, tree, tasks);
    for (const r of results) {
      if (r instanceof Error) throw new Error(`0G segment upload error: ${r.message}`);
    }
  }

  return {
    kind: "0g_storage",
    status: "stored",
    rootHash,
    txHash,
    indexerUrl: config.zeroGIndexerUrl,
    rpcUrl: config.zeroGRpcUrl,
  };
}

async function createStoragePointer(receipt, config = resolveReceiptStorageConfig()) {
  if (config.mode !== "0g") {
    return {
      kind: "local_file",
      path: buildLocalReceiptPath(receipt.receiptId, config),
    };
  }

  if (!config.zeroGPrivateKey) {
    return {
      kind: "0g_storage",
      status: "not_configured",
      reason: "ZERO_G_PRIVATE_KEY is required for 0G uploads.",
      indexerUrl: config.zeroGIndexerUrl,
      rpcUrl: config.zeroGRpcUrl,
    };
  }

  try {
    const data = Buffer.from(JSON.stringify(receipt, null, 2), "utf8");
    return await uploadTo0G(data, config);
  } catch (error) {
    return {
      kind: "0g_storage",
      status: "failed",
      reason: error instanceof Error ? error.message : String(error),
      indexerUrl: config.zeroGIndexerUrl,
      rpcUrl: config.zeroGRpcUrl,
    };
  }
}

module.exports = {
  buildLocalReceiptPath,
  createStoragePointer,
  readReceiptMirror,
  resolveReceiptStorageConfig,
  writeLatestReport,
  writeReceiptMirror,
};
