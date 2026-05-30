import test from "node:test";
import assert from "node:assert/strict";
import { UplinkPoolClient, WARN_CODES } from "../src/index.js";
import { FakeWsHarness } from "./support/FakeWsHarness.js";
import { REZ_CONTRACT_TYPES, CONTRACT_VERSION } from "@rezprotocol/core";
import { parseFrame, sendSuccessResponse, handleHandshake, createTestIdentityKeyPair } from "./support/ContractWsTestUtil.js";

const T = REZ_CONTRACT_TYPES;

function makeEventEnvelope(id, body) {
  return {
    id,
    t: T.EVT_MAILBOX_DEPOSITED,
    type: T.EVT_MAILBOX_DEPOSITED,
    v: CONTRACT_VERSION,
    body,
  };
}

function installServer(ws) {
  ws.addEventListener("message", (evt) => {
    const frame = parseFrame(evt);
    if (handleHandshake(ws, frame, "a")) return;
    sendSuccessResponse(ws, frame.id, "a", { ok: true });
  });
}

function b64OfSize(bytes) {
  return Buffer.alloc(bytes, 7).toString("base64");
}

async function flushMicrotasks() {
  await Promise.resolve();
  await Promise.resolve();
}

async function waitForCondition(fn, timeoutMs = 250) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (fn()) return true;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  return false;
}

test("large payload with serverMsgId is accepted without warning", async () => {
  const identity = await createTestIdentityKeyPair();
  const harness = new FakeWsHarness();
  let ws;
  harness.register("ws://a", (socket) => {
    ws = socket;
    installServer(socket);
  });

  const client = new UplinkPoolClient({
    uplinks: ["ws://a"],
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });
  await client.connect();

  const seen = [];
  const warns = [];
  client.on(T.EVT_MAILBOX_DEPOSITED, (frame) => seen.push(frame.body.serverMsgId));
  client.on("warn", (warn) => warns.push(warn.code));

  ws.send(JSON.stringify(makeEventEnvelope("evt-1", {
    serverMsgId: "sm-1",
    mailboxId: "mbox:sample",
    packetB64: b64OfSize(96 * 1024),
    createdAtMs: Date.now(),
  })));
  await waitForCondition(() => seen.length === 1);

  assert.deepEqual(seen, ["sm-1"]);
  assert.equal(warns.includes(WARN_CODES.UNIDENTIFIABLE_LARGE_FRAME), false);
  await client.close();
});

test("small payload without ids uses hash dedupe path", async () => {
  const identity = await createTestIdentityKeyPair();
  const harness = new FakeWsHarness();
  let ws;
  harness.register("ws://a", (socket) => {
    ws = socket;
    installServer(socket);
  });

  const client = new UplinkPoolClient({
    uplinks: ["ws://a"],
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });
  await client.connect();

  let count = 0;
  client.on(T.EVT_MAILBOX_DEPOSITED, () => {
    count += 1;
  });

  const envelope = makeEventEnvelope("evt-small", {
    mailboxId: "mbox:sample",
    packetB64: Buffer.from(new Uint8Array([1, 2, 3, 4])).toString("base64"),
    createdAtMs: Date.now(),
  });
  ws.send(JSON.stringify(envelope));
  ws.send(JSON.stringify(envelope));
  const emitted = await waitForCondition(() => count >= 1);
  assert.equal(emitted, true);

  assert.equal(count, 1);
  await client.close();
});

test("large payload without ids is dropped and warns", async () => {
  const identity = await createTestIdentityKeyPair();
  const harness = new FakeWsHarness();
  let ws;
  harness.register("ws://a", (socket) => {
    ws = socket;
    installServer(socket);
  });

  const client = new UplinkPoolClient({
    uplinks: ["ws://a"],
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });
  await client.connect();

  const seen = [];
  const warns = [];
  client.on(T.EVT_MAILBOX_DEPOSITED, () => seen.push("received"));
  client.on("warn", (warn) => warns.push(warn));

  ws.send(JSON.stringify(makeEventEnvelope("evt-large", {
    mailboxId: "mbox:sample",
    packetB64: b64OfSize(96 * 1024),
    createdAtMs: Date.now(),
  })));
  await flushMicrotasks();

  assert.equal(seen.length, 0);
  const largeWarn = warns.find((warn) => warn && warn.code === WARN_CODES.UNIDENTIFIABLE_LARGE_FRAME);
  assert.ok(largeWarn);
  assert.equal(largeWarn.droppedCount >= 1, true);
  await client.close();
});
