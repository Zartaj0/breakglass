const { spawn } = require("node:child_process");
const path = require("node:path");

const args = new Set(process.argv.slice(2));
const withGensyn = args.has("--with-gensyn");
const showHelp = args.has("--help") || args.has("-h");
const children = [];
let shuttingDown = false;

function startNodeScript(label, relativeScriptPath) {
  const child = spawn(process.execPath, [relativeScriptPath], {
    cwd: process.cwd(),
    stdio: "inherit",
    env: process.env,
  });

  child.on("exit", (code, signal) => {
    if (shuttingDown) {
      return;
    }

    const reason =
      signal !== null ? `signal ${signal}` : `code ${code ?? "null"}`;
    console.error(`[breakglass-product] ${label} exited unexpectedly (${reason}).`);
    shutdown(1);
  });

  children.push(child);
  return child;
}

function shutdown(exitCode = 0) {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;

  for (const child of children) {
    if (!child.killed) {
      child.kill("SIGTERM");
    }
  }

  setTimeout(() => process.exit(exitCode), 250);
}

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));

if (showHelp) {
  console.log(`Usage:
  npm run product:start
  npm run product:start:full
  node scripts/start-local-product.js [--with-gensyn]

Options:
  --with-gensyn   start the local Gensyn router and reviewer nodes
  --help, -h      show this message
`);
  process.exit(0);
}

console.log("[breakglass-product] starting dashboard...");
startNodeScript("dashboard", path.join("apps", "dashboard", "src", "server.js"));

if (withGensyn) {
  console.log("[breakglass-product] starting local Gensyn mesh...");
  startNodeScript("gensyn-mesh", path.join("scripts", "start-gensyn-dev-mesh.js"));
}

console.log(
  withGensyn
    ? "[breakglass-product] dashboard + local Gensyn mesh running."
    : "[breakglass-product] dashboard running. Start with --with-gensyn if you want peer review locally.",
);
