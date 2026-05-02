const http = require("node:http");

const { loadDotEnv } = require("../../../packages/shared/src/load-env");
const {
  REVIEW_SERVICE_NAME,
  handleReviewerRpc,
} = require("../../../packages/agent-mesh/src/reviewer");

loadDotEnv({ override: true });

function resolveReviewerServerConfig(env = process.env) {
  const host = env.GENSYN_AXL_REVIEWER_HOST || "127.0.0.1";
  const port = Number(env.GENSYN_AXL_REVIEWER_PORT || 7100);
  const path = env.GENSYN_AXL_REVIEWER_PATH || "/mcp";
  const routerUrl = String(
    env.GENSYN_AXL_ROUTER_URL || "http://127.0.0.1:9003",
  ).replace(/\/+$/, "");

  return {
    host,
    port,
    path,
    healthPath: env.GENSYN_AXL_REVIEWER_HEALTH_PATH || "/health",
    reviewerId: env.GENSYN_AXL_REVIEWER_ID || `${host}:${port}`,
    reviewerLabel:
      env.GENSYN_AXL_REVIEWER_LABEL || `breakglass-reviewer-${port}`,
    serviceName: env.GENSYN_AXL_SERVICE || REVIEW_SERVICE_NAME,
    routerUrl,
    registerWithRouter:
      String(env.GENSYN_AXL_REGISTER_WITH_ROUTER || "true")
        .trim()
        .toLowerCase() === "true",
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

async function registerWithRouter(config) {
  if (!config.registerWithRouter) {
    return;
  }

  const response = await fetch(`${config.routerUrl}/register`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({
      service: config.serviceName,
      peerId: config.reviewerLabel,
      endpoint: `http://${config.host}:${config.port}${config.path}`,
    }),
    signal: AbortSignal.timeout(5000),
  });

  if (!response.ok) {
    throw new Error(
      `AXL router registration failed with ${response.status}.`,
    );
  }
}

async function deregisterFromRouter(config) {
  if (!config.registerWithRouter) {
    return;
  }

  try {
    await fetch(
      `${config.routerUrl}/register/${config.serviceName}/${encodeURIComponent(config.reviewerLabel)}`,
      {
      method: "DELETE",
      signal: AbortSignal.timeout(3000),
      },
    );
  } catch {
    // Best effort cleanup for local demo processes.
  }
}

function createReviewerServer(config = resolveReviewerServerConfig()) {
  return http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === config.healthPath) {
      return sendJson(res, 200, {
        ok: true,
        service: config.serviceName,
        reviewerId: config.reviewerId,
        reviewerLabel: config.reviewerLabel,
      });
    }

    if (req.method === "POST" && (req.url === config.path || req.url?.startsWith(`${config.path}/`))) {
      try {
        const rawBody = await readRequestBody(req);
        const body = rawBody ? JSON.parse(rawBody) : {};
        const response = handleReviewerRpc(body, {
          reviewerId: config.reviewerId,
          reviewerLabel: config.reviewerLabel,
        });

        return sendJson(res, 200, response);
      } catch (error) {
        return sendJson(res, 400, {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return sendJson(res, 404, {
      error: "Not found",
    });
  });
}

async function startReviewerServer() {
  const config = resolveReviewerServerConfig();
  const server = createReviewerServer(config);

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, config.host, resolve);
  });

  try {
    await registerWithRouter(config);
  } catch (error) {
    server.close();
    throw error;
  }

  const shutdown = async () => {
    await deregisterFromRouter(config);
    server.close();
  };

  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);

  console.log(
    JSON.stringify(
      {
        reviewerUrl: `http://${config.host}:${config.port}${config.path}`,
        serviceName: config.serviceName,
        reviewerId: config.reviewerId,
        reviewerLabel: config.reviewerLabel,
        routerUrl: config.routerUrl,
      },
      null,
      2,
    ),
  );

  return server;
}

if (require.main === module) {
  startReviewerServer().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}

module.exports = {
  createReviewerServer,
  resolveReviewerServerConfig,
  startReviewerServer,
};
