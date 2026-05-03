# BreakGlass

**24/7 Safe treasury guardian.** Add any Safe address in the browser, and BreakGlass monitors it continuously — automatically containing 5 high-confidence Safe incident classes while using an investigation agent to assess novel or uncategorized pending transactions.

Built for `ETHGlobal Open Agents 2026`.

---

## For End Users

Visit the BreakGlass dashboard. That's it.

1. Enter your Safe address and select the network
2. Click **Start Monitoring**
3. BreakGlass polls your Safe every 30 seconds across any of 22 supported chains
4. When a risky pending transaction appears, you see an incident card — what it is, why it's risky, and whether containment or human review is required
5. For known high-confidence incidents, click **Propose Containment** to submit a rejection transaction directly to your Safe queue

No API keys. No terminal. No configuration.

---

## 5 Containment Classes + Unknown Transaction Investigation

| Trigger | What Gets Caught |
|---|---|
| Suspicious Approval | Token spending approval to unknown or unlimited spender |
| Ownership Change | `addOwnerWithThreshold`, `removeOwner`, `swapOwner` |
| Threshold Reduction | `changeThreshold` below minimum or to 1 |
| Module Enablement | `enableModule` with unknown contract |
| Large Transfer | ETH or ERC-20 transfer above configured limit |

Any other pending Safe transaction with non-trivial calldata is routed into an `unknown_transaction` investigation path. BreakGlass gathers Safe evidence, asks an LLM for a structured `HALT / INVESTIGATE / APPROVE` verdict, and requires human review before containment.

---

## How Containment Works

When you click **Propose Containment**, BreakGlass submits a rejection transaction at the same nonce as the suspicious pending transaction. This invalidates it — the malicious tx can no longer execute once the rejection gets enough co-signatures. Your co-signers approve it the same way they approve any Safe transaction.

BreakGlass is the first responder. Your multisig stays in control.

---

## For Operators (Deploying BreakGlass)

If you are hosting BreakGlass for your team:

### 1. Set credentials once

```bash
cp .env.example .env
```

```bash
# Required
SAFE_API_KEY=           # from app.safe.global → Settings → API Keys

# Containment (required for real Safe proposals)
SAFE_EXECUTION_MODE=live
SAFE_RPC_URL=https://...
SAFE_OWNER_PRIVATE_KEY=0x...

# AI investigation cascade (configure any subset)
GEMINI_API_KEY=         # free tier, first choice
ANTHROPIC_API_KEY=      # Claude fallback
NVIDIA=                 # Nvidia NIM fallback
MISTRAL=                # Mistral fallback
OPENROUTER=             # OpenRouter fallback

# Optional sponsor integrations
KEEPERHUB_MODE=webhook
KEEPERHUB_WEBHOOK_URL=https://...

BREAKGLASS_RECEIPT_STORAGE=0g
ZERO_G_PRIVATE_KEY=0x...

GENSYN_AXL_MODE=mcp
GENSYN_AXL_PEER_IDS=reviewer-a,reviewer-b
```

### 2. Start

```bash
npm install
npm run product:start          # dashboard only
npm run product:start:full     # dashboard + Gensyn peer review mesh
npm run demo:start             # same as product:start:full, best local demo entrypoint
```

Open `http://localhost:3030`. Users add their Safe addresses. For the hackathon demo, use the in-app `Seed Demo Incident` button to create a suspicious approval and refresh the monitor without leaving the browser.

---

## Supported Chains

**Mainnets:** Ethereum, Base, Arbitrum, Optimism, Polygon, BSC, Gnosis, Avalanche, zkSync Era, Polygon zkEVM, Linea, Scroll, Blast, Mode, Mantle, Celo, Worldchain

**Testnets:** Base Sepolia, Sepolia, Holesky, Arbitrum Sepolia, Optimism Sepolia

---

## Architecture

```
User adds Safe → MonitorService polls every 30s
                    ↓
              Safe Transaction API (22 chains)
                    ↓
       5 high-confidence detectors + unknown catch-all
                    ↓
              Deterministic runbook compiler
                    ↓
         ┌──────────────────────────────────┐
         │ KeeperHub   — step simulation    │
         │ Investigation agent — evidence + verdict │
         │ Gensyn AXL  — peer review        │
         │ 0G Storage  — on-chain receipt   │
         └──────────────────────────────────┘
                    ↓
      Incident card + containment or human review
```

---

## Sponsor Integrations

| Sponsor | Integration |
|---|---|
| **KeeperHub** | Every runbook step POSTed to KeeperHub webhook. Real execution IDs per step. |
| **0G** | Incident receipts anchored on-chain. Real txHash and rootHash per incident. |
| **Gensyn** | Two AXL reviewer nodes independently review the deterministic first step over AXL before live containment proceeds. |
| **Anthropic / Gemini / Nvidia / Mistral / OpenRouter** | Investigation agent gathers Safe evidence, forms a structured risk verdict, and falls back across multiple providers automatically. |

---

## Tests

```bash
npm test   # 69 tests, 0 failures
```

---

## Design Principle

The AI investigates. The code constrains execution.

BreakGlass uses LLMs to gather and interpret Safe evidence, especially for uncategorized pending transactions. But safety-critical containment remains deterministic — compiled from fixed runbook templates keyed to the incident class, with explicit limits on what can execute automatically.
