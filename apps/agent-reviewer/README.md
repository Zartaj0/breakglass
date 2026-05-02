# apps/agent-reviewer

Purpose:
- expose BreakGlass review logic as an MCP tool
- register that tool with the local Gensyn AXL MCP router
- let other AXL nodes independently attest the first containment step

Typical flow:
- start an AXL node
- start `npm run router:serve`
- run `node apps/agent-reviewer/src/server.js`
- use the reviewer's peer ID from another node via `/mcp/{peerId}/breakglass-review`
