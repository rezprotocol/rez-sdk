import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createFrameCodec } from "../src/transport/FrameCodec.js";
import { resolveSessionIdentity } from "../src/protocol/index.js";
import { RezPayloadSendParams } from "../src/client/RezPayloadSendParams.js";
import { randomToken, randomUuid } from "../src/util/randomId.js";
import { MailboxCapability } from "../src/capabilities/MailboxCapability.js";
import { MAILBOX_APP_OPS, RezClient } from "../src/client/RezClient.js";

// Remediation cover for SDK-1..SDK-5 (rez-core/docs/SECURITY_FINDINGS_CONSOLIDATED.md).
// Every test here fails against the pre-fix tree.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(__dirname, "..", "src");

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile() && full.endsWith(".js")) out.push(full);
  }
  return out;
}

// --- SDK-1: the frame codec is the trust boundary every remote frame crosses ---

test("SDK-1: decodeFrame refuses a frame body carrying a prototype-poisoning key", () => {
  const codec = createFrameCodec();
  for (const key of ["__proto__", "constructor", "prototype"]) {
    const raw = `{"id":"1","t":"evt.x","v":2,"body":{${JSON.stringify(key)}:{"isAdmin":true}}}`;
    assert.throws(() => codec.decodeFrame(raw), (err) => {
      assert.equal(err.code, "UNSAFE_JSON_KEY", key);
      assert.equal(err.retryable, false, "resending identical bytes cannot help");
      return true;
    }, key);
  }
});

test("SDK-1: a hostile frame is distinguishable from a merely malformed one", () => {
  // Flattening both into BAD_FRAME would send an operator looking for an
  // encoding bug when the actual event is an attack.
  const codec = createFrameCodec();
  assert.throws(() => codec.decodeFrame("{not json"), (err) => err.code === "BAD_FRAME");
  assert.throws(() => codec.decodeFrame("null"), (err) => err.code === "BAD_FRAME");
  assert.throws(
    () => codec.decodeFrame(String.raw`{"body":{"__proto__":{}}}`),
    (err) => err.code === "UNSAFE_JSON_KEY",
  );
});

test("SDK-1: ordinary frames still decode unchanged", () => {
  const codec = createFrameCodec();
  const frame = codec.decodeFrame(String.raw`{"id":"abc","t":"evt.mailbox.deposited","v":2,"body":{"seq":7}}`);
  assert.deepEqual(frame, { id: "abc", type: "evt.mailbox.deposited", version: 2, body: { seq: 7 } });
  // Round-trip through the encoder, so the guard cannot have broken our own wire.
  assert.deepEqual(
    codec.decodeFrame(codec.encodeFrame({ id: "x", type: "t", body: { a: [1, { b: 2 }] } })),
    { id: "x", type: "t", version: 2, body: { a: [1, { b: 2 }] } },
  );
});

// --- SDK-2: session identity is inbox-first; account id is local ---

test("SDK-2: a remotely-claimed accountId can never OUTRANK the local one", () => {
  // The old code read sessionInfo.accountId FIRST, so a substituted value simply
  // won. Now a disagreement ends the session instead.
  assert.throws(
    () => resolveSessionIdentity(
      { accountId: "rez:acct:attacker", capabilities: { deviceId: "d1" } },
      { accountId: "rez:acct:me", deviceId: "d1" },
    ),
    (err) => {
      assert.equal(err.code, "SESSION_ACCOUNT_MISMATCH");
      assert.match(err.message, /authenticated as 'rez:acct:me'/);
      return true;
    },
  );
});

test("SDK-2: the adoption case — a claim with no local value to check it against", () => {
  // The finding's core scenario: an SDK holding no account id would previously
  // have taken the node's word for who it was.
  assert.throws(
    () => resolveSessionIdentity({ accountId: "rez:acct:attacker" }, { deviceId: "d1" }),
    (err) => {
      assert.equal(err.code, "SESSION_ACCOUNT_MISMATCH");
      assert.match(err.message, /never node-authenticated/);
      return true;
    },
  );
});

test("SDK-2: accountId comes from local state, and an agreeing echo is not an error", () => {
  const identity = resolveSessionIdentity(
    { capabilities: { deviceId: "dev-1", localInboxId: "inbox-abc" } },
    { accountId: "rez:acct:me", deviceId: "dev-1" },
  );
  assert.deepEqual(identity, { accountId: "rez:acct:me", deviceId: "dev-1", localInboxId: "inbox-abc" });

  // rez-chat's own runtime client echoes the account it connected as. That is
  // local truth in the same shape — permitted, but still not the SOURCE.
  const echoed = resolveSessionIdentity(
    { accountId: "rez:acct:me", capabilities: { localInboxId: "inbox-abc" } },
    { accountId: "rez:acct:me", deviceId: "dev-1" },
  );
  assert.equal(echoed.accountId, "rez:acct:me");

  // No local account id and no claim: no account identity. It does NOT mean
  // "ask the node" — there is nothing on the wire to ask for.
  const anonymous = resolveSessionIdentity({ capabilities: { localInboxId: "inbox-abc" } }, {});
  assert.equal(anonymous.accountId, "");
  assert.equal(anonymous.localInboxId, "inbox-abc", "the node-authenticated half is still returned");
});

test("SDK-2: an echoed deviceId that disagrees with ours ends the session", () => {
  assert.throws(
    () => resolveSessionIdentity(
      { capabilities: { deviceId: "someone-else" } },
      { accountId: "rez:acct:me", deviceId: "mine" },
    ),
    (err) => err.code === "SESSION_DEVICE_MISMATCH",
  );
  // Agreement is fine, and so is a node that echoes nothing.
  assert.equal(resolveSessionIdentity({ capabilities: { deviceId: "mine" } }, { deviceId: "mine" }).deviceId, "mine");
  assert.equal(resolveSessionIdentity({ capabilities: {} }, { deviceId: "mine" }).deviceId, "mine");
});

// --- SDK-3: the app-facing mailbox surface cannot deposit ---

test("SDK-3: the mailbox app view exposes drain ops and no deposit", () => {
  const sent = [];
  const pool = {
    sendRequest: async (req) => {
      sent.push(req.type);
      return { body: { mailboxId: "mbox", eventId: "e1", removed: true, items: [], deviceId: "d", lastSeq: 1 } };
    },
    on: () => () => {},
    onState: () => () => {},
    onReconnected: () => () => {},
    getSessionInfo: () => null,
  };
  const client = new RezClient({ pool, eventBus: { on: () => {}, emit: () => {} }, authMachine: {} });

  assert.deepEqual(Object.keys(client.mailbox).sort(), [...MAILBOX_APP_OPS].sort());
  assert.equal(client.mailbox.deposit, undefined, "deposit must not be reachable from the app surface");
  assert.equal(Object.isFrozen(client.mailbox), true, "and it must not be re-attachable");
});

test("SDK-3: the app view is a deliberate subset — a new mailbox op must be classified", () => {
  // Guards the silent-omission failure: adding `MailboxCapability.peek` and
  // forgetting MAILBOX_APP_OPS would leave apps unable to use it with no error
  // anywhere. Adding an op here forces the deposit-or-drain decision.
  const declared = new Set([...MAILBOX_APP_OPS, "deposit"]);
  const actual = Object.getOwnPropertyNames(MailboxCapability.prototype).filter((n) => n !== "constructor");
  const unclassified = actual.filter((n) => !declared.has(n));
  assert.deepEqual(
    unclassified, [],
    "New MailboxCapability method(s) with no place on the app surface: " + unclassified.join(", ")
    + ". Add to MAILBOX_APP_OPS if apps may call it, or to this test's `declared` set if it is "
    + "producer-side like deposit.",
  );
  assert.equal(actual.includes("deposit"), true, "deposit still exists — it is hidden, not deleted");
});

// --- SDK-4: sendPayload encrypts nothing and now says so ---

test("SDK-4: payload params must acknowledge that the bytes are already sealed", () => {
  const base = {
    peerAccountId: "rez:acct:peer",
    payloadBytes: new Uint8Array([1, 2, 3]),
    deliverInboxId: "inbox-1",
  };
  assert.throws(() => new RezPayloadSendParams(base), /encrypts nothing/);
  assert.throws(() => new RezPayloadSendParams({ ...base, preSealed: "yes" }), /encrypts nothing/,
    "a truthy value is data passing through, not an assertion");
  assert.throws(() => new RezPayloadSendParams({ ...base, preSealed: 1 }), /encrypts nothing/);

  const ok = new RezPayloadSendParams({ ...base, preSealed: true });
  assert.equal(ok.preSealed, true);
  assert.equal(ok.deliverInboxId, "inbox-1");
});

// --- SDK-5: identifiers come from crypto-grade randomness ---

test("SDK-5: randomToken/randomUuid produce well-formed, non-repeating ids", () => {
  assert.match(randomToken(), /^[0-9a-f]{8}$/);
  assert.match(randomToken(16), /^[0-9a-f]{32}$/);
  assert.throws(() => randomToken(0), /positive integer/);
  assert.throws(() => randomToken(1.5), /positive integer/);

  const seen = new Set();
  for (let i = 0; i < 2000; i += 1) seen.add(randomToken());
  assert.ok(seen.size > 1990, "32 bits over 2000 draws should collide rarely; got " + seen.size);

  assert.match(randomUuid(), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test("SDK-5: no identifier in src/ is generated from Math.random()", () => {
  // TWO exempt files, for different reasons:
  //   - the reconnect-jitter site, which is not an identifier and where
  //     non-crypto randomness is correct;
  //   - randomId.js itself, which names Math.random() in the message explaining
  //     why it refuses to use it.
  // Both pinned by exact path so a second use cannot hide behind the exemption,
  // and comments are stripped so prose about the rule does not trip it.
  const JITTER_SITE = "src/connection/ConnectionStateMachine.js";
  const EXEMPT = new Set([JITTER_SITE, "src/util/randomId.js"]);
  const stripComments = (text) => text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
  const violations = [];
  for (const file of walk(SRC)) {
    const rel = path.relative(path.resolve(SRC, ".."), file);
    if (EXEMPT.has(rel)) continue;
    const lines = stripComments(fs.readFileSync(file, "utf8")).split("\n");
    for (let i = 0; i < lines.length; i += 1) {
      if (/Math\s*\.\s*random\s*\(/.test(lines[i])) {
        violations.push(rel + ":" + (i + 1) + "  " + lines[i].trim());
      }
    }
  }
  assert.deepEqual(violations, [],
    "Math.random() outside the reconnect-jitter site. SDK identifiers use "
    + "util/randomId.js (crypto-grade, throws rather than degrading).\n" + violations.join("\n"));

  // And the exemption is real, not a stale allowlist entry.
  const jitter = fs.readFileSync(path.resolve(SRC, "..", JITTER_SITE), "utf8");
  assert.match(jitter, /Math\.random\(\)/, "the jitter exemption points at a site that still exists");
});
