import test from "node:test";
import assert from "node:assert/strict";
import { UplinkPoolClient } from "../src/index.js";
import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";
import { FakeWsHarness } from "./support/FakeWsHarness.js";
import { parseFrame, sendSuccessResponse, sendMessageUpsert, handleHandshake, createTestIdentityKeyPair } from "./support/ContractWsTestUtil.js";

async function waitFor(predicate, timeoutMs = 500) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  return false;
}

test("event subscriptions survive close + reconnect", async () => {
  const harness = new FakeWsHarness();
  let emitCount = 0;

  harness.register("ws://a", (ws) => {
    ws.addEventListener("message", (evt) => {
      const frame = parseFrame(evt);
      if (handleHandshake(ws, frame, "a")) return;
      sendSuccessResponse(ws, frame.id, "a");
      emitCount += 1;
      sendMessageUpsert(ws, `evt:${emitCount}`, {
        mailboxId: "mbox:a",
        id: `evt:${emitCount}`,
        objectId: `obj:${emitCount}`,
      });
    });
  });

  const identity = await createTestIdentityKeyPair();
  const client = new UplinkPoolClient({
    uplinks: ["ws://a"],
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });

  let seen = 0;
  client.on(REZ_CONTRACT_TYPES.EVT_MAILBOX_DEPOSITED, () => {
    seen += 1;
  });

  await client.connect();
  await client.request(REZ_CONTRACT_TYPES.MAILBOX_LIST, { mailboxId: "mbox:test" });
  const got1 = await waitFor(() => seen >= 1);
  assert.equal(got1, true, "expected first event after connect");
  assert.equal(seen, 1);

  await client.close();

  await client.connect();
  await client.request(REZ_CONTRACT_TYPES.MAILBOX_LIST, { mailboxId: "mbox:test" });
  const got2 = await waitFor(() => seen >= 2);
  assert.equal(got2, true, "expected second event after reconnect");
  assert.equal(seen, 2);

  await client.close();
});
