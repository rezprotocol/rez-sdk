import test from "node:test";
import assert from "node:assert/strict";
import { UplinkPoolClient, WARN_CODES } from "../src/index.js";
import { FakeWsHarness } from "./support/FakeWsHarness.js";
import { REZ_CONTRACT_TYPES, CONTRACT_VERSION } from "@rezprotocol/core";
import { parseFrame, handleHandshake, createTestIdentityKeyPair } from "./support/ContractWsTestUtil.js";

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

test("flood gate drops excess inbound and emits warn", async () => {
  const harness = new FakeWsHarness();
  let ws;
  harness.register("ws://a", (serverWs) => {
    ws = serverWs;
    serverWs.addEventListener("message", (evt) => {
      const frame = parseFrame(evt);
      if (handleHandshake(serverWs, frame, "a")) return;
    });
  });

  const identity = await createTestIdentityKeyPair();
  const client = new UplinkPoolClient({
    uplinks: ["ws://a"],
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
    flood: {
      perConnRate: 1,
      perConnBurst: 1,
      globalRate: 1,
      globalBurst: 1,
      warnIntervalMs: 1,
    },
  });
  await client.connect();

  const events = [];
  const warns = [];
  client.on(T.EVT_MAILBOX_DEPOSITED, () => events.push(1));
  client.on("warn", (w) => warns.push(w));

  for (let i = 0; i < 10; i += 1) {
    ws.send(JSON.stringify(makeEventEnvelope(`e${i}`, {
      serverMsgId: `p${i}`,
      mailboxId: "mbox:flood",
      objectId: `obj:${i}`,
      createdAtMs: Date.now(),
    })));
  }
  await new Promise((r) => setTimeout(r, 5));

  assert.ok(events.length >= 1);
  assert.ok(events.length < 10);
  assert.ok(warns.length >= 1);
  assert.equal(warns[0].code, WARN_CODES.INBOUND_FLOOD);

  await client.close();
});
