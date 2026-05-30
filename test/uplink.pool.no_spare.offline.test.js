import test from "node:test";
import assert from "node:assert/strict";
import { UplinkPoolClient } from "../src/index.js";
import { FakeWsHarness } from "./support/FakeWsHarness.js";
import { isHelloFrame, parseFrame, sendReady, handleHandshake, createTestIdentityKeyPair, isAuthenticateFrame } from "./support/ContractWsTestUtil.js";
import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";

function waitTick() {
  return new Promise((r) => setTimeout(r, 0));
}

async function waitFor(predicate, timeoutMs = 500) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return true;
    await waitTick();
  }
  return false;
}

test("goes offline when active disconnects and no spare exists", async () => {
  const harness = new FakeWsHarness();
  let wsA;
  harness.register("ws://a", (ws) => {
    wsA = ws;
    ws.addEventListener("message", (evt) => {
      const frame = parseFrame(evt);
      if (handleHandshake(ws, frame, "a")) return;
    });
  });

  const identity = await createTestIdentityKeyPair();
  const states = [];
  const client = new UplinkPoolClient({
    uplinks: ["ws://a", "ws://b"],
    warmSpareCount: 1,
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });
  client.onState((state) => states.push(state));
  await client.connect();
  assert.equal(client.getActiveUplink(), "ws://a");

  wsA.close(1006, "down");
  const wentNull = await waitFor(() => client.getActiveUplink() === null);
  assert.equal(wentNull, true, "expected active uplink to become null");
  const gotOffline = await waitFor(() => states.some((s) => s.phase === "offline"));
  assert.ok(gotOffline, "expected offline state event");
  await assert.rejects(
    () => client.request(REZ_CONTRACT_TYPES.MAILBOX_LIST, { mailboxId: "mbox:test" }),
    (err) => err?.code === "NOT_READY"
  );

  await client.close();
});
