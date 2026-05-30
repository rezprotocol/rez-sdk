import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const SRC = path.resolve("src");

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile() && full.endsWith(".js")) out.push(full);
  }
  return out;
}

function stripComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

function extractSpecifiers(text) {
  const stripped = stripComments(text);
  const out = [];
  const importFromRe = /^\s*import\s+[^;]*?\s+from\s+["']([^"']+)["']/gm;
  const exportFromRe = /^\s*export\s+[^;]*?\s+from\s+["']([^"']+)["']/gm;
  const dynamicImportRe = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;

  for (const re of [importFromRe, exportFromRe, dynamicImportRe]) {
    let m;
    while ((m = re.exec(stripped)) != null) out.push(m[1]);
  }
  return out;
}

function hasPathSegment(p, segment) {
  const norm = p.replace(/\\/g, "/");
  return norm.split("/").includes(segment);
}

test("rez-sdk must not contain a chat domain folder", () => {
  // Hard ban on any chat-domain subtree living in the SDK.
  const bannedRoots = [
    path.join(SRC, "chat"),
    path.join(SRC, "server", "chat"),
    path.join(SRC, "domain", "chat"),
  ];

  const existing = bannedRoots.filter((p) => fs.existsSync(p));
  assert.deepEqual(
    existing,
    [],
    `Remove chat domain code from rez-sdk. Found:\n${existing.map((p) => `- ${p}`).join("\n")}`
  );
});

test("rez-sdk must not contain files under any */chat/* path", () => {
  const files = walk(SRC);
  const violations = files
    .filter((f) => hasPathSegment(f, "chat"))
    .map((f) => path.relative(SRC, f));

  assert.deepEqual(
    violations,
    [],
    `rez-sdk contains files in a chat path:\n${violations.join("\n")}`
  );
});

test("rez-sdk must not import chat-domain modules or rez-chat", () => {
  const files = walk(SRC);
  const violations = [];

  for (const file of files) {
    const specifiers = extractSpecifiers(fs.readFileSync(file, "utf8"));
    for (const raw of specifiers) {
      const s = String(raw || "").trim().replace(/\\/g, "/");

      // No dependency on the app workspace.
      if (s === "rez-chat" || s.startsWith("rez-chat/")) {
        violations.push(`${path.relative(SRC, file)} -> ${s}`);
        continue;
      }

      // No obvious chat-domain imports by path.
      if (s.includes("/chat/") || s.endsWith("/chat")) {
        violations.push(`${path.relative(SRC, file)} -> ${s}`);
        continue;
      }

      // Ban workspace-relative "reach across" imports.
      if (s.includes("../rez-chat/") || s.includes("/rez-chat/")) {
        violations.push(`${path.relative(SRC, file)} -> workspace path import ${s}`);
      }
    }
  }

  assert.deepEqual(violations, [], violations.join("\n"));
});

// Optional: cheap smell test against chat nouns bleeding into rez-sdk filenames.
// Keep this list short + high-signal to avoid false positives.
// The capabilities/ directory is explicitly allowed to use domain nouns
// because it is the SDK public surface for these domains.
const CHAT_NOUNS = ["Thread", "Message", "Invite", "Group", "Contact", "Composer"];
test("rez-sdk must not contain chat-domain nouns in filenames", () => {
  const files = walk(SRC);
  const violations = [];
  for (const file of files) {
    if (hasPathSegment(file, "capabilities")) continue;
    const base = path.basename(file, path.extname(file));
    if (CHAT_NOUNS.some((n) => base.includes(n))) {
      violations.push(path.relative(SRC, file));
    }
  }
  assert.deepEqual(violations, [], `Chat nouns in rez-sdk filenames:\n${violations.join("\n")}`);
});
