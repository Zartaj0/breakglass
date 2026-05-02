const { spawn } = require("node:child_process");
const path = require("node:path");

const cwd = process.cwd();
const node = process.execPath;
const baseEnv = { ...process.env };

const services = [
  {
    name: "router",
    script: path.join("apps", "agent-router", "src", "server.js"),
    env: {},
  },
  {
    name: "reviewer-a",
    script: path.join("apps", "agent-reviewer", "src", "server.js"),
    env: {
      GENSYN_AXL_REVIEWER_PORT: "7100",
      GENSYN_AXL_REVIEWER_LABEL: "reviewer-a",
    },
  },
  {
    name: "reviewer-b",
    script: path.join("apps", "agent-reviewer", "src", "server.js"),
    env: {
      GENSYN_AXL_REVIEWER_PORT: "7101",
      GENSYN_AXL_REVIEWER_LABEL: "reviewer-b",
    },
  },
];

const children = services.map((service) => {
  const child = spawn(node, [service.script], {
    cwd,
    env: {
      ...baseEnv,
      ...service.env,
    },
    stdio: "inherit",
  });

  child.on("exit", (code, signal) => {
    if (code !== 0 && signal !== "SIGINT" && signal !== "SIGTERM") {
      console.error(`[gensyn-mesh] ${service.name} exited with code ${code ?? "null"}.`);
    }
  });

  return child;
});

function shutdown(signal) {
  for (const child of children) {
    if (!child.killed) {
      child.kill(signal);
    }
  }
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

