const fs = require("node:fs/promises");
const path = require("node:path");

const EDITABLE_RUNTIME_KEYS = [
  "SAFE_API_KEY",
  "AI_BRIEF_PROVIDER",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_MODEL",
  "GEMINI_API_KEY",
  "GEMINI_MODEL",
  "OLLAMA_BASE_URL",
  "OLLAMA_MODEL",
  "AI_BRIEF_TIMEOUT_MS",
  "KEEPERHUB_MODE",
  "KEEPERHUB_WEBHOOK_URL",
  "KEEPERHUB_API_KEY",
  "KEEPERHUB_INCLUDE_FULL_PAYLOAD",
  "KEEPERHUB_TIMEOUT_MS",
  "SAFE_EXECUTION_MODE",
  "SAFE_RPC_URL",
  "SAFE_OWNER_PRIVATE_KEY",
  "SAFE_CONFIRMING_OWNER_KEYS",
  "SAFE_EXECUTE_WHEN_READY",
  "BREAKGLASS_RECEIPT_STORAGE",
  "ZERO_G_PRIVATE_KEY",
  "ZERO_G_RPC_URL",
  "ZERO_G_INDEXER_URL",
  "GENSYN_AXL_MODE",
  "GENSYN_AXL_API_BASE_URL",
  "GENSYN_AXL_PEER_IDS",
  "GENSYN_AXL_MIN_APPROVALS",
  "GENSYN_AXL_REQUIRE_QUORUM_FOR_EXECUTION",
];

function resolveRuntimeSettingsPath(env = process.env) {
  const artifactDir = path.resolve(
    process.cwd(),
    env.BREAKGLASS_ARTIFACT_DIR ?? "artifacts",
  );

  return path.join(artifactDir, "runtime-settings.json");
}

function sanitizeRuntimeSettings(input = {}) {
  const output = {};

  for (const key of EDITABLE_RUNTIME_KEYS) {
    if (!(key in input)) {
      continue;
    }

    const value = input[key];

    if (typeof value === "boolean") {
      output[key] = value ? "true" : "false";
      continue;
    }

    if (value === null || value === undefined) {
      continue;
    }

    const stringValue = String(value).trim();

    if (!stringValue) {
      continue;
    }

    output[key] = stringValue;
  }

  return output;
}

async function readRuntimeSettings(env = process.env) {
  const filePath = resolveRuntimeSettingsPath(env);

  try {
    const raw = await fs.readFile(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return sanitizeRuntimeSettings(parsed);
  } catch {
    return {};
  }
}

async function writeRuntimeSettings(values, env = process.env) {
  const filePath = resolveRuntimeSettingsPath(env);
  const artifactDir = path.dirname(filePath);
  const sanitized = sanitizeRuntimeSettings(values);

  await fs.mkdir(artifactDir, { recursive: true });
  await fs.writeFile(`${filePath}`, `${JSON.stringify(sanitized, null, 2)}\n`, "utf8");

  return {
    filePath,
    settings: sanitized,
  };
}

function applyRuntimeSettingsToEnv(settings, env = process.env) {
  for (const [key, value] of Object.entries(sanitizeRuntimeSettings(settings))) {
    env[key] = value;
  }

  return env;
}

function pickRuntimeSettings(env = process.env) {
  const picked = {};

  for (const key of EDITABLE_RUNTIME_KEYS) {
    picked[key] = env[key] ?? "";
  }

  return picked;
}

module.exports = {
  EDITABLE_RUNTIME_KEYS,
  applyRuntimeSettingsToEnv,
  pickRuntimeSettings,
  readRuntimeSettings,
  resolveRuntimeSettingsPath,
  sanitizeRuntimeSettings,
  writeRuntimeSettings,
};
