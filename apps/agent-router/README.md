# apps/agent-router

Purpose:
- replace the reference AXL MCP router with a small Node service
- register local MCP services
- forward `/route` requests from the AXL node to those services

Endpoints:
- `POST /register`
- `DELETE /register/{service}`
- `POST /route`
- `GET /services`
- `GET /health`
