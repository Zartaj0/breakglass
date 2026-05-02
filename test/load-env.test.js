const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  loadDotEnv,
  parseEnvLine,
} = require("../packages/shared/src/load-env");

test("parseEnvLine ignores comments and blank lines", () => {
  assert.equal(parseEnvLine(""), null);
  assert.equal(parseEnvLine("   "), null);
  assert.equal(parseEnvLine("# comment"), null);
});

test("parseEnvLine parses quoted and unquoted values", () => {
  assert.deepEqual(parseEnvLine("FOO=bar"), {
    key: "FOO",
    value: "bar",
  });
  assert.deepEqual(parseEnvLine('BAR="baz qux"'), {
    key: "BAR",
    value: "baz qux",
  });
});

test("loadDotEnv loads values without overriding existing process env by default", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "breakglass-env-"));
  const envPath = path.join(dir, ".env");
  fs.writeFileSync(envPath, "ALPHA=one\nBETA=two\n", "utf8");

  const previousAlpha = process.env.ALPHA;
  const previousBeta = process.env.BETA;
  process.env.ALPHA = "existing";
  delete process.env.BETA;

  try {
    const result = loadDotEnv({ cwd: dir });
    assert.equal(result.loaded, true);
    assert.equal(process.env.ALPHA, "existing");
    assert.equal(process.env.BETA, "two");
  } finally {
    if (previousAlpha === undefined) {
      delete process.env.ALPHA;
    } else {
      process.env.ALPHA = previousAlpha;
    }

    if (previousBeta === undefined) {
      delete process.env.BETA;
    } else {
      process.env.BETA = previousBeta;
    }
  }
});
