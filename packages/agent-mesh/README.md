# packages/agent-mesh

This package holds the optional Gensyn AXL layer for BreakGlass.

The rule is still strict:
- AXL must not invent treasury actions
- AXL should reinforce the deterministic safety model

Current use:
- the orchestrator calls remote reviewer nodes over AXL MCP
- each reviewer independently reviews the incident and proposed first step
- the main node records those attestations in the receipt
- optional quorum can block automatic Safe execution

The point is not novelty.

The point is:
- decentralized peer review
- separate-node communication
- a meaningful extra safety check before onchain automation
