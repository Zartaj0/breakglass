# apps/watcher

Purpose:
- fetch Safe pending transactions
- normalize them into the shared schema
- detect the chosen incident trigger
- emit `IncidentCase` plus a deterministic runbook

Usage:

```bash
node apps/watcher/src/cli.js
```

Environment:
- `SAFE_PENDING_SOURCE=fixture|live`
- `SAFE_ADDRESS`
- `SAFE_NETWORK`
- `SAFE_API_KEY` for production-rate Safe API access
- `BREAKGLASS_ALLOWED_SPENDERS`
- `BREAKGLASS_APPROVAL_THRESHOLD`
