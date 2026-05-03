const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  handleRequest,
  MonitorService,
  renderPage,
} = require("../apps/dashboard/src/server");
const {
  writeReceiptMirror,
  resolveReceiptStorageConfig,
} = require("../packages/storage-0g/src/client");

// ---------------------------------------------------------------------------
// renderPage
// ---------------------------------------------------------------------------

test("renders the dashboard page with safes and incidents", () => {
  const safes = [
    {
      address: "0xsafeaddress1234567890",
      network: "base-sepolia",
      status: "critical",
      incidents: [{}],
      lastChecked: new Date().toISOString(),
      error: null,
    },
  ];

  const allIncidents = [
    {
      incident: {
        incidentId: "incident-1",
        title: "Suspicious approval pending in Safe queue",
        summary: "approve to 0xspender triggered three signals",
        severity: "critical",
        triggerType: "suspicious_approval",
        safeAddress: "0xsafeaddress1234567890",
        network: "base-sepolia",
      },
      brief: "This transaction grants 0xspender unlimited access to USDC. It is risky because the spender is unknown. Reject it immediately.",
      runbook: {
        steps: [
          {
            kind: "invalidate_pending_approval",
            description: "Reject the pending approval.",
            simulation: { status: "ready_to_propose", keeperhubRunId: null },
          },
        ],
      },
      peerReview: {
        provider: { mode: "mcp" },
        decision: "approve",
        approvals: 1,
        requiredApprovals: 1,
        executionGate: "pass",
        summary: "peer approved invalidate_pending_approval",
      },
      monitor: {
        firstSeenAt: "2026-04-28T00:00:00.000Z",
        lastSeenAt: "2026-04-28T00:00:30.000Z",
        seenCount: 2,
        processedCount: 1,
        freshness: "cached",
      },
    },
  ];

  const html = renderPage(safes, allIncidents);

  assert.match(html, /BreakGlass/);
  assert.match(html, /Monitor a Safe/);
  assert.match(html, /Monitored Safes/);
  assert.match(html, /Active Incidents/);
  assert.match(html, /Start Monitoring/);
  assert.match(html, /Seed Demo Incident/);
  assert.match(html, /Propose Containment/);
  assert.match(html, /Suspicious approval pending in Safe queue/);
  assert.match(html, /invalidate_pending_approval/);
  assert.match(html, /Gensyn AXL/);
  assert.match(html, /AI Analysis/);
  assert.match(html, /seen 2x/);
  assert.match(html, /System Status/);
  assert.match(html, /Incident History/);
});

test("renders empty-state messages when no safes or incidents", () => {
  const html = renderPage([], []);

  assert.match(html, /No Safes monitored yet/);
  assert.match(html, /No active incidents/);
  assert.match(html, /No incident history yet/);
});

test("renders AI availability note when briefs are configured but unavailable", () => {
  const html = renderPage([], [
    {
      incident: {
        incidentId: "incident-ai-note",
        title: "Suspicious approval pending in Safe queue",
        summary: "approve to unknown spender triggered one signal",
        severity: "high",
        triggerType: "suspicious_approval",
        safeAddress: "0xsafeaddress1234567890",
        network: "base-sepolia",
      },
      brief: null,
      briefStatus: {
        configured: true,
        error: "Your credit balance is too low",
      },
      runbook: { steps: [] },
      peerReview: { provider: { mode: "disabled" } },
      monitor: {},
    },
  ]);

  assert.match(html, /unavailable/i);
  assert.match(html, /credit balance is too low/i);
});

test("renders KeeperHub fallback reason when webhook simulation degrades", () => {
  const html = renderPage([], [
    {
      incident: {
        incidentId: "incident-kh-fallback",
        title: "Suspicious approval pending in Safe queue",
        summary: "approve to unknown spender triggered one signal",
        severity: "high",
        triggerType: "suspicious_approval",
        safeAddress: "0xsafeaddress1234567890",
        network: "base-sepolia",
      },
      brief: null,
      runbook: {
        steps: [
          {
            kind: "invalidate_pending_approval",
            description: "Reject the pending approval.",
            simulation: {
              status: "ready_to_propose",
              fallbackUsed: true,
              webhookError: "KeeperHub webhook failed with 410: Workflow is disabled",
            },
          },
        ],
      },
      peerReview: { provider: { mode: "disabled" } },
      monitor: {},
    },
  ]);

  assert.match(html, /KeeperHub fallback/i);
  assert.match(html, /Workflow is disabled/i);
});

test("renders human-review-only incidents without an active containment button", () => {
  const html = renderPage([], [
    {
      incident: {
        incidentId: "incident-unknown-1",
        title: "Uncategorized Safe transaction requires investigation",
        summary: "Opaque calldata to an unknown target did not match a deterministic class.",
        severity: "high",
        triggerType: "unknown_transaction",
        safeAddress: "0xsafeaddress1234567890",
        network: "base-sepolia",
      },
      brief: null,
      investigation: {
        provider: "nvidia",
        configured: true,
        verdict: "INVESTIGATE",
        keyFindings: ["Opaque calldata"],
        operatorRecommendation: "Pause signing and review intent.",
        toolCalls: [],
      },
      runbook: {
        steps: [
          {
            kind: "investigate_unknown_transaction",
            description: "Investigate this transaction before further signatures are added.",
          },
        ],
      },
      peerReview: { provider: { mode: "disabled" } },
      monitor: {},
    },
  ]);

  assert.match(html, /Human Review Required/);
  assert.match(html, /Unknown Transaction/);
});

// ---------------------------------------------------------------------------
// MonitorService in-memory behaviour
// ---------------------------------------------------------------------------

test("addSafe registers a safe and returns ok:true", async () => {
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
  });
  const result = await monitor.addSafe("0xABC123", "base-sepolia", false);
  assert.equal(result.ok, true);
  assert.equal(monitor.safes.length, 1);
  assert.equal(monitor.safes[0].network, "base-sepolia");
  // clear the interval so the test doesn't hang
  for (const s of monitor.safes) if (s._intervalId) clearInterval(s._intervalId);
});

test("addSafe returns already_monitored when duplicate", async () => {
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
  });
  await monitor.addSafe("0xABC123", "base-sepolia", false);
  const second = await monitor.addSafe("0xABC123", "base-sepolia", false);
  assert.equal(second.ok, false);
  assert.equal(second.reason, "already_monitored");
  for (const s of monitor.safes) if (s._intervalId) clearInterval(s._intervalId);
});

test("removeSafe removes an existing safe", async () => {
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
  });
  await monitor.addSafe("0xABC123", "base-sepolia", false);
  const result = await monitor.removeSafe("0xABC123");
  assert.equal(result.ok, true);
  assert.equal(monitor.safes.length, 0);
});

test("removeSafe returns not_found for unknown address", async () => {
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
  });
  const result = await monitor.removeSafe("0xdeadbeef");
  assert.equal(result.ok, false);
  assert.equal(result.reason, "not_found");
});

test("MonitorService preserves incident lifecycle metadata across cached polls", async () => {
  let callCount = 0;
  const timestamps = [
    new Date("2026-04-28T00:00:00.000Z"),
    new Date("2026-04-28T00:00:30.000Z"),
    new Date("2026-04-28T00:01:00.000Z"),
    new Date("2026-04-28T00:01:30.000Z"),
  ];
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
    pollIntervalMs: 999999,
    now: () => timestamps.shift() ?? new Date("2026-04-28T00:02:00.000Z"),
    runIncidentPipeline: async (_env, options = {}) => {
      callCount += 1;
      return {
        transactionsScanned: 1,
        incidents: [
          {
            incident: {
              incidentId: "incident-1",
              title: "Suspicious approval pending in Safe queue",
              summary: "approve to 0xspender triggered one signal",
              severity: "high",
              triggerType: "suspicious_approval",
              safeAddress: "0xabc123",
              network: "base-sepolia",
            },
            brief: null,
            runbook: { steps: [] },
            peerReview: { provider: { mode: "disabled" } },
            execution: null,
            receipt: { createdAt: "2026-04-28T00:00:00.000Z", receiptId: "receipt-1" },
            cache: { reused: Boolean(options.existingResultsByIncidentId?.["incident-1"]) },
          },
        ],
      };
    },
  });

  await monitor.addSafe("0xABC123", "base-sepolia", false);
  for (const s of monitor.safes) if (s._intervalId) clearInterval(s._intervalId);

  await monitor._poll("0xabc123");
  await monitor._poll("0xabc123");

  assert.equal(callCount, 2);
  assert.equal(monitor.incidents[0].monitor.firstSeenAt, "2026-04-28T00:00:30.000Z");
  assert.equal(monitor.incidents[0].monitor.seenCount, 2);
  assert.equal(monitor.incidents[0].monitor.processedCount, 1);
  assert.equal(monitor.incidents[0].monitor.freshness, "cached");
});

test("recordContainmentResult stores execution state for an active incident", async () => {
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
    pollIntervalMs: 999999,
    now: () => new Date("2026-04-28T00:00:00.000Z"),
    runIncidentPipeline: async () => ({
      transactionsScanned: 1,
      incidents: [
        {
          incident: {
            incidentId: "incident-2",
            title: "Safe ownership structure change pending",
            summary: "swapOwner would alter ownership",
            severity: "critical",
            triggerType: "ownership_change",
            safeAddress: "0xdef456",
            network: "base-sepolia",
          },
          brief: null,
          runbook: { steps: [] },
          peerReview: { provider: { mode: "disabled" } },
          execution: null,
          receipt: { createdAt: "2026-04-28T00:00:00.000Z", receiptId: "receipt-2" },
          cache: { reused: false },
        },
      ],
    }),
  });

  await monitor.addSafe("0xDEF456", "base-sepolia", false);
  for (const s of monitor.safes) if (s._intervalId) clearInterval(s._intervalId);
  await monitor._poll("0xdef456");

  await monitor.recordContainmentResult("incident-2", {
    status: "proposed_and_confirmed",
    safeTxHash: "0xcontainment",
  });

  assert.equal(monitor.incidents[0].execution.status, "proposed_and_confirmed");
  assert.equal(monitor.incidents[0].monitor.lastContainmentStatus, "proposed_and_confirmed");
  assert.equal(monitor.incidents[0].monitor.containmentAttempts, 1);
  assert.equal(monitor.history[0].history.state, "contained");
});

test("MonitorService stores resolved incidents in history", async () => {
  let callCount = 0;
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
    now: () => new Date("2026-04-28T00:00:00.000Z"),
    runIncidentPipeline: async () => {
      callCount += 1;

      return {
        transactionsScanned: 1,
        incidents: callCount === 1
          ? [
            {
              incident: {
                incidentId: "incident-3",
                title: "Large transfer pending",
                summary: "large transfer detected",
                severity: "high",
                triggerType: "large_transfer",
                safeAddress: "0xfeed",
                network: "base-sepolia",
              },
              brief: null,
              runbook: { steps: [] },
              peerReview: { provider: { mode: "disabled" } },
              execution: null,
              receipt: { createdAt: "2026-04-28T00:00:00.000Z", receiptId: "receipt-3" },
              cache: { reused: false },
            },
          ]
          : [],
      };
    },
  });

  await monitor.addSafe("0xFEED", "base-sepolia", false);
  await monitor._poll("0xfeed");
  await monitor._poll("0xfeed");

  assert.equal(monitor.incidents.length, 0);
  assert.equal(monitor.history.length, 1);
  assert.equal(monitor.history[0].history.state, "resolved");
});

// ---------------------------------------------------------------------------
// HTTP API — handleRequest
// ---------------------------------------------------------------------------

function makeRes() {
  const chunks = [];
  const res = {
    statusCode: null,
    headers: null,
    writeHead(code, headers) { this.statusCode = code; this.headers = headers; },
    end(chunk = "") { chunks.push(chunk); },
    body() { return JSON.parse(chunks.join("")); },
  };
  return res;
}

function makeReq(method, url, body = null) {
  const chunks = body ? [Buffer.from(JSON.stringify(body))] : [];
  const req = { method, url, [Symbol.asyncIterator]: async function* () { yield* chunks; } };
  return req;
}

function makeArtifactDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "breakglass-monitor-"));
}

test("POST /api/safes adds a safe and returns ok:true", async () => {
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
  });
  const req = makeReq("POST", "/api/safes", { address: "0xDEF456", network: "sepolia" });
  const res = makeRes();
  await handleRequest(req, res, monitor);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body().ok, true);
  assert.equal(monitor.safes.length, 1);
  for (const s of monitor.safes) if (s._intervalId) clearInterval(s._intervalId);
});

test("POST /api/safes returns 400 when address is missing", async () => {
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
  });
  const req = makeReq("POST", "/api/safes", { network: "sepolia" });
  const res = makeRes();
  await handleRequest(req, res, monitor);
  assert.equal(res.statusCode, 400);
  assert.equal(res.body().reason, "address_required");
});

test("GET /api/safes returns the current watchlist", async () => {
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
  });
  await monitor.addSafe("0xAAA", "ethereum", false);
  const req = makeReq("GET", "/api/safes");
  const res = makeRes();
  await handleRequest(req, res, monitor);
  assert.equal(res.statusCode, 200);
  const payload = res.body();
  assert.equal(payload.safes.length, 1);
  assert.equal(payload.safes[0].network, "ethereum");
  for (const s of monitor.safes) if (s._intervalId) clearInterval(s._intervalId);
});

test("GET /api/history returns persisted incident history", async () => {
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
    runIncidentPipeline: async () => ({
      transactionsScanned: 1,
      incidents: [
        {
          incident: {
            incidentId: "incident-history-1",
            title: "Ownership change pending",
            summary: "addOwnerWithThreshold detected",
            severity: "critical",
            triggerType: "ownership_change",
            safeAddress: "0x123",
            network: "ethereum",
          },
          brief: null,
          runbook: { steps: [] },
          peerReview: { provider: { mode: "disabled" } },
          execution: null,
          receipt: { createdAt: "2026-04-28T00:00:00.000Z", receiptId: "receipt-history-1" },
          cache: { reused: false },
        },
      ],
    }),
  });

  await monitor.addSafe("0x123", "ethereum", false);
  await monitor._poll("0x123");

  const req = makeReq("GET", "/api/history");
  const res = makeRes();
  await handleRequest(req, res, monitor);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body().history.length, 1);
  assert.equal(res.body().history[0].incident.incidentId, "incident-history-1");
});

test("GET /api/report returns serializable monitor state", async () => {
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
  });
  await monitor.addSafe("0xAAA111", "base-sepolia", false);

  const req = makeReq("GET", "/api/report");
  const res = makeRes();
  await handleRequest(req, res, monitor);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body().safes[0].address, "0xaaa111");
  assert.equal(res.body().runtimeStatus.safeApi.label, "Safe API");
});

test("POST /api/demo/seed seeds a demo incident and refreshes monitoring", async () => {
  const calls = [];
  const monitor = {
    seedIncident: async () => ({
      safeAddress: "0xSeed123",
      network: "base-sepolia",
      safeTxHash: "0xseedtx",
    }),
    addSafe: async (address, network) => {
      calls.push(["addSafe", address, network]);
      return { ok: true };
    },
    forcePoll: async (address) => {
      calls.push(["forcePoll", address]);
      return { ok: true };
    },
    safes: [],
    incidents: [],
    history: [],
    artifactDir: makeArtifactDir(),
  };

  const req = makeReq("POST", "/api/demo/seed");
  const res = makeRes();
  await handleRequest(req, res, monitor);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body().ok, true);
  assert.deepEqual(calls, [
    ["addSafe", "0xSeed123", "base-sepolia"],
    ["forcePoll", "0xSeed123"],
  ]);
});

test("DELETE /api/safes/:addr removes a safe", async () => {
  const monitor = new MonitorService({
    artifactDir: makeArtifactDir(),
    autoStartPolling: false,
  });
  await monitor.addSafe("0xBBB", "base-sepolia", false);
  const req = makeReq("DELETE", "/api/safes/0xBBB");
  const res = makeRes();
  await handleRequest(req, res, monitor);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body().ok, true);
  assert.equal(monitor.safes.length, 0);
});

test("GET /api/receipts/:id returns a mirrored receipt", async () => {
  const artifactDir = makeArtifactDir();
  const monitor = new MonitorService({
    artifactDir,
    autoStartPolling: false,
  });
  const storageConfig = resolveReceiptStorageConfig({
    BREAKGLASS_ARTIFACT_DIR: artifactDir,
  });

  await writeReceiptMirror(
    {
      receiptId: "receipt-local-1",
      incidentId: "incident-local-1",
      storagePointer: { kind: "local_file" },
    },
    storageConfig,
  );

  const req = makeReq("GET", "/api/receipts/receipt-local-1");
  const res = makeRes();
  await handleRequest(req, res, monitor);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body().receipt.receiptId, "receipt-local-1");
});
