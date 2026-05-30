import test from "node:test";
import assert from "node:assert/strict";
import { UplinkPoolClient } from "../src/index.js";
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

function serverBasic(ws, label) {
  ws.addEventListener("message", (evt) => {
    const frame = parseFrame(evt);
    if (handleHandshake(ws, frame, label)) return;
    sendSuccessResponse(ws, frame.id, label, { ok: true });
  });
}

test("dedupes duplicate inbound frames by stable id", async () => {
  const harness = new FakeWsHarness();
  let wsA;
  let wsB;
  harness.register("ws://a", (ws) => {
    wsA = ws;
    serverBasic(ws, "a");
  });
  harness.register("ws://b", (ws) => {
    wsB = ws;
    serverBasic(ws, "b");
  });

  const identity = await createTestIdentityKeyPair();
  const client = new UplinkPoolClient({
    uplinks: ["ws://a", "ws://b"],
    warmSpareCount: 1,
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });
  await client.connect();

  const seen = [];
  const off = client.on(T.EVT_MAILBOX_DEPOSITED, (frame) => {
    seen.push(frame.body.serverMsgId);
  });

  const dupeEnvelope = makeEventEnvelope("evt1", {
    serverMsgId: "same-1",
    mailboxId: "mbox:test",
    eventId: "evt:test",
    objectId: "obj:test",
    createdAtMs: Date.now(),
  });
  wsA.send(JSON.stringify(dupeEnvelope));
  wsB.send(JSON.stringify(dupeEnvelope));
  await waitFor(() => seen.length === 1);

  assert.deepEqual(seen, ["same-1"]);
  off();
  await client.close();
});

async function waitFor(predicate, timeoutMs = 250) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
