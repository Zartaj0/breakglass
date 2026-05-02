const fs = require("node:fs");
const path = require("node:path");

function parseEnvLine(line) {
  const trimmed = line.trim();

  if (!trimmed || trimmed.startsWith("#")) {
    return null;
  }

  const separatorIndex = trimmed.indexOf("=");
  if (separatorIndex === -1) {
    return null;
  }

  const key = trimmed.slice(0, separatorIndex).trim();
  let value = trimmed.slice(separatorIndex + 1).trim();

  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1);
  }

  return {
    key,
    value,
  };
}

function loadDotEnv({
  cwd = process.cwd(),
  filename = ".env",
  override = false,
} = {}) {
  const envPath = path.resolve(cwd, filename);

  if (!fs.existsSync(envPath)) {
    return {
      envPath,
      loaded: false,
    };
  }

  const raw = fs.readFileSync(envPath, "utf8");
  const lines = raw.split(/\r?\n/);
  let applied = 0;

  for (const line of lines) {
    const parsed = parseEnvLine(line);

    if (!parsed) {
      continue;
    }

    if (!override && process.env[parsed.key] !== undefined) {
      continue;
    }

    process.env[parsed.key] = parsed.value;
    applied += 1;
  }

  return {
    envPath,
    loaded: true,
    applied,
  };
}

module.exports = {
  loadDotEnv,
  parseEnvLine,
};
