import test from "node:test";
import assert from "node:assert/strict";
import { UplinkPoolClient } from "../src/index.js";
import { FakeWsHarness } from "./support/FakeWsHarness.js";
import { isHelloFrame, parseFrame, sendReady, sendThreadUpsert, handleHandshake, createTestIdentityKeyPair, isAuthenticateFrame } from "./support/ContractWsTestUtil.js";

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

function attachServer(ws, label) {
  ws.addEventListener("message", (evt) => {
    const frame = parseFrame(evt);
    if (handleHandshake(ws, frame, label)) return;
    sendThreadUpsert(ws, frame.id, label);
  });
}

test("promotes connected spare immediately on active disconnect", async () => {
  const harness = new FakeWsHarness();
  let wsA;
  harness.register("ws://a", (ws) => { wsA = ws; attachServer(ws, "a"); });
  harness.register("ws://b", (ws) => attachServer(ws, "b"));
  harness.register("ws://c", (ws) => attachServer(ws, "c"));

  const identity = await createTestIdentityKeyPair();
  const client = new UplinkPoolClient({
    uplinks: ["ws://a", "ws://b", "ws://c"],
    warmSpareCount: 2,
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });
  const states = [];
  client.onState((state) => states.push(state));

  await client.connect();
  assert.equal(client.getActiveUplink(), "ws://a");
  assert.ok(states.some((s) => s.phase === "connected"), "onState handlers must survive connect() and receive initial connected");

  wsA.close(1006, "drop");
  const promoted = await waitFor(() => client.getActiveUplink() === "ws://b");
  assert.equal(promoted, true, "expected active uplink to switch to ws://b");
  const gotFailover = await waitFor(() => states.some((s) => s.phase === "failover" && s.from === "ws://a" && s.to === "ws://b"));
  assert.ok(gotFailover, "expected failover state event");

  await client.close();
});
