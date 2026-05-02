# BreakGlass

BreakGlass is a self-hosted Safe incident-response console.

You run it locally, open a browser dashboard, add one or more Safe addresses, and BreakGlass continuously polls the Safe queue for risky pending transactions. When it finds one, it explains the risk in plain English, compiles a deterministic containment runbook, sends the runbook steps to KeeperHub, and lets an operator propose the first mitigation from the UI.

Built for `ETHGlobal Open Agents 2026`.

## What The Product Is

BreakGlass is not a chat wallet and it is not a free-form AI planner.

It is a Safe treasury first responder:

1. Monitor pending Safe transactions
2. Detect known incident classes
3. Compile the correct deterministic containment runbook
4. Explain the issue in plain English
5. Simulate the runbook through KeeperHub
6. Optionally collect Gensyn peer review
7. Let an operator propose containment through Safe

## What The User Does

The primary user is a Safe treasury operator.

Their flow is:

1. Open BreakGlass in the browser
2. Add a Safe address and network
3. Wait for the monitor to poll the Safe queue
4. Read the incident card if a risky pending transaction is found
5. Review the containment runbook
6. Click `Propose Containment` if they want BreakGlass to submit the first mitigation

## What Runs Where

- `Dashboard`: the actual product UI at `http://127.0.0.1:3030`
- `Dashboard server`: also the backend monitor and API server
- `CLI`: used for startup, testing, seeding demo incidents, and one-off debugging

If you are just using the product, you should mostly think in terms of:

- start the product
- open the browser
- add a Safe
- respond to incidents

## Incident Classes

BreakGlass currently detects 5 incident classes:

| Trigger | What It Catches |
|---|---|
| `suspicious_approval` | token approvals to unknown or dangerous spenders |
| `ownership_change` | add owner, remove owner, swap owner |
| `threshold_reduction` | lowering the Safe threshold below policy |
| `module_enablement` | enabling an unknown Safe module |
| `large_transfer` | ETH or ERC-20 transfers above configured limits |

Each incident type maps to a deterministic runbook compiler. The LLM explains the incident. The code decides the containment steps.

## Quick Start

```bash
npm install
cp .env.example .env
```

Fill in at least:

- `SAFE_API_KEY`
- one AI provider:
  - `AI_BRIEF_PROVIDER=gemini` and `GEMINI_API_KEY`
  - or `AI_BRIEF_PROVIDER=anthropic` and `ANTHROPIC_API_KEY`
  - or `AI_BRIEF_PROVIDER=ollama` and a local Ollama instance

Then start the product:

```bash
npm run product:start
```

Open:

```text
http://127.0.0.1:3030
```

If you also want the local Gensyn reviewer mesh:

```bash
npm run product:start:full
```

## Main Commands

```bash
npm run product:start
```

Start the dashboard and backend monitor.

```bash
npm run product:start:full
```

Start the dashboard plus the local Gensyn router and reviewer nodes.

```bash
npm run seed:incident
```

Create a demo suspicious approval on the configured testnet Safe.

```bash
npm run orchestrator:run
```

Run the full pipeline once from the CLI for debugging.

```bash
npm run demo:check
```

Read the latest report and summarize which integrations are live vs degraded.

## Dashboard Features

The dashboard lets you:

- add a Safe address and network
- see system status for Safe, AI briefs, KeeperHub, Safe execution, receipt storage, and Gensyn
- see monitored Safes and their latest poll status
- see active incident cards with:
  - severity
  - detector signals
  - AI brief
  - KeeperHub step runs
  - Gensyn peer review
  - receipt link
- trigger containment from the UI
- inspect incident history

Safes persist in `artifacts/watchlist.json`.

Monitor state persists in:

- `artifacts/monitor-state.json`
- `artifacts/incident-history.json`
- `artifacts/latest-report.json`

## Live Execution

To make containment proposals real instead of dry-run previews, set:

```bash
SAFE_EXECUTION_MODE=live
SAFE_RPC_URL=https://...
SAFE_OWNER_PRIVATE_KEY=0x...
SAFE_API_KEY=...
```

Optional:

- `SAFE_CONFIRMING_OWNER_KEYS` for automatic extra confirmations
- `SAFE_EXECUTE_WHEN_READY=true` to execute when threshold is met

## Optional Integrations

### KeeperHub

```bash
KEEPERHUB_MODE=webhook
KEEPERHUB_WEBHOOK_URL=https://...
```

BreakGlass POSTs each runbook step to the webhook. A blank enabled webhook workflow is enough for the current integration.

### Gensyn AXL

Use `npm run product:start:full` for the local mesh, or configure the router/reviewer env vars manually.

### 0G

```bash
BREAKGLASS_RECEIPT_STORAGE=0g
ZERO_G_PRIVATE_KEY=0x...
```

The adapter is implemented, but live 0G testnet uploads are still unreliable in the current build. Local file receipts remain the default safe path.

## Policy Configuration

```bash
BREAKGLASS_ALLOWED_SPENDERS=0x...
BREAKGLASS_APPROVAL_THRESHOLD=100000000000000000000000

BREAKGLASS_ALLOWED_OWNERS=0x...,0x...
BREAKGLASS_MIN_THRESHOLD=2

BREAKGLASS_ALLOWED_MODULES=0x...

BREAKGLASS_MAX_ETH_TRANSFER=1000000000000000000
BREAKGLASS_MAX_TOKEN_TRANSFER=10000000000000000000000
BREAKGLASS_ALLOWED_RECIPIENTS=0x...,0x...
```

## Repo Map

| Path | Role |
|---|---|
| `apps/dashboard` | browser UI, monitor loops, HTTP API |
| `apps/orchestrator` | detect → runbook → simulate → execute pipeline |
| `apps/agent-router` | local Gensyn MCP router |
| `apps/agent-reviewer` | local Gensyn reviewer node |
| `packages/policies` | incident detectors |
| `packages/runbooks` | deterministic runbook compilers |
| `packages/ai` | Gemini / Anthropic / Ollama brief generation |
| `packages/integrations` | Safe and KeeperHub integrations |
| `packages/agent-mesh` | peer-review logic over AXL-style routing |
| `packages/storage-0g` | receipt persistence and optional 0G adapter |
| `packages/shared` | shared env/model utilities |

## Tests

```bash
npm test
```

Current status: `66 passing tests`.

## Current Scope

This repo is a strong hackathon product, not a finished hosted SaaS.

What is solid:

- multi-chain Safe monitoring from the browser
- deterministic runbooks
- live Safe ingestion
- live Gemini briefs
- live KeeperHub webhook step submission
- containment proposal flow
- optional local Gensyn peer review

What is still limited:

- the product is self-hosted, not managed cloud software
- 0G uploads are implemented but not yet reliable on the current testnet path
- Gensyn is strongest in local mesh mode today, not as a fully deployed distributed network product

## Design Principle

The LLM explains. The code decides.

BreakGlass does not let an LLM invent treasury actions. AI is used to explain the incident to humans. Containment logic comes from deterministic runbook compilers keyed to the incident type.
