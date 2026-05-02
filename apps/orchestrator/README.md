# apps/orchestrator

Purpose:

- fetch pending Safe transactions through the shared integrations layer
- detect incidents through the policy engine
- compile deterministic runbooks
- request AI incident briefs
- submit runbook steps to KeeperHub
- request optional Gensyn peer review
- prepare or execute the first containment step through Safe
- persist a receipt locally, with optional 0G upload

This is the operational core of BreakGlass.
