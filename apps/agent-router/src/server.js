const http = require("node:http");

const { loadDotEnv } = require("../../../packages/shared/src/load-env");

loadDotEnv({ override: true });

function resolveRouterConfig(env = process.env) {
  return {
    host: env.GENSYN_AXL_ROUTER_HOST || "127.0.0.1",
    port: Number(env.GENSYN_AXL_ROUTER_PORT || 9003),
  };
}

function sendJson(res, statusCode, value) {
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
  });
  res.end(`${JSON.stringify(value, null, 2)}\n`);
}

async function readRequestBody(req) {
  const chunks = [];

  for await (const chunk of req) {
    chunks.push(chunk);
  }

  return Buffer.concat(chunks).toString("utf8");
}

function createRouterState() {
  return new Map();
}

function ensureServiceBucket(state, serviceName) {
  if (!state.has(serviceName)) {
    state.set(serviceName, new Map());
  }

  return state.get(serviceName);
}

function getService(state, serviceName, peerId = null) {
  const bucket = state.get(serviceName);

  if (!bucket || bucket.size === 0) {
    return null;
  }

  if (peerId && bucket.has(peerId)) {
    return bucket.get(peerId);
  }

  return Array.from(bucket.values())[0] ?? null;
}

async function routeToService(service, payload, fromPeerId) {
  const response = await fetch(service.endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "x-from-peer-id": fromPeerId,
      "x-service": service.name,
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(30000),
  });

  if (response.status === 204) {
    service.healthy = true;
    return {
      response: null,
      error: null,
    };
  }

  const text = await response.text();

  if (!response.ok) {
    service.healthy = false;
    return {
      response: null,
      error: `Service error: ${response.status}`,
    };
  }

  service.healthy = true;

  if (!text) {
    return {
      response: null,
      error: null,
    };
  }

  try {
    return {
      response: JSON.parse(text),
      error: null,
    };
  } catch {
    service.healthy = false;
    return {
      response: null,
      error: "Service returned invalid JSON",
    };
  }
}

function listServices(state) {
  return Object.fromEntries(
    Array.from(state.entries()).map(([serviceName, bucket]) => [
      serviceName,
      {
        peerCount: bucket.size,
        peers: Object.fromEntries(
          Array.from(bucket.entries()).map(([peerId, service]) => [
            peerId,
            {
              endpoint: service.endpoint,
              registered_at: service.registeredAt,
              healthy: service.healthy,
            },
          ]),
        ),
      },
    ]),
  );
}

function createRouterServer(state = createRouterState()) {
  return http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/health") {
      return sendJson(res, 200, {
        status: "ok",
        service_count: state.size,
      });
    }

    if (req.method === "GET" && req.url === "/services") {
      return sendJson(res, 200, listServices(state));
    }

    if (req.method === "GET" && req.url === "/topology") {
      const peers = [];

      for (const [serviceName, bucket] of state.entries()) {
        for (const [peerId, service] of bucket.entries()) {
          peers.push({
            peer_id: peerId,
            service: serviceName,
            endpoint: service.endpoint,
            healthy: service.healthy,
          });
        }
      }

      return sendJson(res, 200, {
        our_public_key: "local-router",
        peers,
      });
    }

    if (req.method === "POST" && req.url === "/register") {
      try {
        const body = JSON.parse(await readRequestBody(req));
        const serviceName = body.service;
        const endpoint = body.endpoint;
        const peerId =
          body.peerId || body.peer_id || body.reviewerLabel || body.reviewer_label;

        if (!serviceName || !endpoint || !peerId) {
          return sendJson(res, 400, {
            error: "'service', 'endpoint', and 'peerId' are required",
          });
        }

        const bucket = ensureServiceBucket(state, serviceName);

        bucket.set(peerId, {
          name: serviceName,
          peerId,
          endpoint,
          registeredAt: new Date().toISOString(),
          healthy: true,
        });

        return sendJson(res, 200, {
          status: "registered",
          service: serviceName,
          peerId,
        });
      } catch (error) {
        return sendJson(res, 400, {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    const deleteMatch = req.url?.match(/^\/register\/([^/]+)\/([^/]+)$/);
    if (req.method === "DELETE" && deleteMatch) {
      const serviceName = decodeURIComponent(deleteMatch[1]);
      const peerId = decodeURIComponent(deleteMatch[2]);
      const bucket = state.get(serviceName);

      if (!bucket || !bucket.has(peerId)) {
        return sendJson(res, 404, {
          error: `Service not found: ${serviceName}/${peerId}`,
        });
      }

      bucket.delete(peerId);

      if (bucket.size === 0) {
        state.delete(serviceName);
      }

      return sendJson(res, 200, {
        status: "deregistered",
        service: serviceName,
        peerId,
      });
    }

    if (req.method === "POST" && req.url === "/route") {
      try {
        const body = JSON.parse(await readRequestBody(req));
        const serviceName = body.service;
        const peerId = body.peerId || body.peer_id || null;
        const payload = body.request;
        const fromPeerId = body.from_peer_id || "unknown";

        if (!serviceName) {
          return sendJson(res, 400, {
            response: null,
            error: "Missing 'service' field",
          });
        }

        const service = getService(state, serviceName, peerId);

        if (!service) {
          return sendJson(res, 404, {
            response: null,
            error: `Service not found: ${serviceName}${peerId ? `/${peerId}` : ""}`,
          });
        }

        const routed = await routeToService(service, payload, fromPeerId);

        return sendJson(res, routed.error ? 502 : 200, routed);
      } catch (error) {
        return sendJson(res, 400, {
          response: null,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    const mcpMatch = req.url?.match(/^\/mcp\/([^/]+)\/([^/]+)$/);
    if (req.method === "POST" && mcpMatch) {
      try {
        const peerId = decodeURIComponent(mcpMatch[1]);
        const serviceName = decodeURIComponent(mcpMatch[2]);
        const payload = JSON.parse(await readRequestBody(req));
        const service = getService(state, serviceName, peerId);

        if (!service) {
          return sendJson(res, 404, {
            response: null,
            error: `Service not found: ${serviceName}/${peerId}`,
          });
        }

        const routed = await routeToService(service, payload, "router");
        return sendJson(res, routed.error ? 502 : 200, routed.response ?? {});
      } catch (error) {
        return sendJson(res, 400, {
          response: null,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return sendJson(res, 404, {
      error: "Not found",
    });
  });
}

function startRouterServer() {
  const config = resolveRouterConfig();
  const server = createRouterServer();

  server.listen(config.port, config.host, () => {
    console.log(
      JSON.stringify(
        {
          routerUrl: `http://${config.host}:${config.port}`,
        },
        null,
        2,
      ),
    );
  });

  return server;
}

if (require.main === module) {
  startRouterServer();
}

module.exports = {
  createRouterServer,
  createRouterState,
  getService,
  listServices,
  routeToService,
  resolveRouterConfig,
  startRouterServer,
};
