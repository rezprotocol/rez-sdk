import test from "node:test";
import assert from "node:assert/strict";
import { UplinkPoolClient } from "../src/index.js";
import { FakeWsHarness } from "./support/FakeWsHarness.js";
import { isHelloFrame, parseFrame, sendReady, sendThreadUpsert, handleHandshake, createTestIdentityKeyPair, isAuthenticateFrame, sendChallenge } from "./support/ContractWsTestUtil.js";

function server(ws, label, onHello = null) {
  ws.addEventListener("message", (evt) => {
    const frame = parseFrame(evt);
    if (isHelloFrame(frame)) {
      if (onHello) onHello();
      sendChallenge(ws, frame.id, frame.body || {});
      return;
    }
    if (isAuthenticateFrame(frame)) {
      sendReady(ws, frame.id, label);
      return;
    }
    sendThreadUpsert(ws, frame.id, label);
  });
}

test("refills spare target after spare disconnect", async () => {
  const harness = new FakeWsHarness();
  let wsB;
  const helloCounts = { b: 0, d: 0 };
  harness.register("ws://a", (ws) => server(ws, "a"));
  harness.register("ws://b", (ws) => { wsB = ws; server(ws, "b", () => { helloCounts.b += 1; }); });
  harness.register("ws://c", (ws) => server(ws, "c"));
  harness.register("ws://d", (ws) => server(ws, "d", () => { helloCounts.d += 1; }));

  const identity = await createTestIdentityKeyPair();
  const client = new UplinkPoolClient({
    uplinks: ["ws://a", "ws://b", "ws://c", "ws://d"],
    warmSpareCount: 2,
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });
  await client.connect();
  assert.equal(client.getActiveUplink(), "ws://a");
  const startB = helloCounts.b;
  const startD = helloCounts.d;

  wsB.close(1006, "drop spare");
  await waitFor(
    () => helloCounts.b > startB || helloCounts.d > startD,
    100
  );

  assert.equal(client.getActiveUplink(), "ws://a");
  assert.ok(helloCounts.b > startB || helloCounts.d > startD);

  await client.close();
});

async function waitFor(predicate, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 1));
  }
}
