import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";

import { fileURLToPath } from "node:url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(__dirname, "..", "src");

/**
 * Recursively collect all .js files under `dir`.
 */
async function walkDir(dir) {
  const out = [];
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await walkDir(full)));
    } else if (entry.isFile() && full.endsWith(".js")) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Directories and individual files that must NOT import from @rezprotocol/node.
 * src/client/index.js is intentionally excluded (backward-compat re-exports).
 */
const CHECKED_DIRS = [
  "src/client",
  "src/errors",
  "src/events",
  "src/transport",
  "src/connection",
  "src/auth",
  "src/pool",
  "src/capabilities",
  "src/observability",
];

const CHECKED_FILES = [];

async function collectTargetFiles() {
  const files = [];
  for (const dir of CHECKED_DIRS) {
    files.push(...(await walkDir(path.join(SRC, path.relative("src", dir)))));
  }
  for (const rel of CHECKED_FILES) {
    files.push(path.resolve(path.dirname(SRC), rel));
  }
  return files;
}

test("checked SDK source files must not import from @rezprotocol/node", async () => {
  const files = await collectTargetFiles();
  assert.ok(files.length > 0, "expected to find source files to check");

  const violations = [];
  for (const file of files) {
    const text = await fs.readFile(file, "utf8");
    if (
      text.includes('from "@rezprotocol/node') ||
      text.includes('require("@rezprotocol/node')
    ) {
      violations.push(path.relative(SRC, file));
    }
  }

  assert.deepEqual(
    violations,
    [],
    `These SDK files import from @rezprotocol/node (should be removed):\n${violations.join("\n")}`,
  );
});
