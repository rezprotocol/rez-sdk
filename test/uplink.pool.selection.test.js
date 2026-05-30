import test from "node:test";
import assert from "node:assert/strict";
import { UplinkPoolClient } from "../src/index.js";
import { FakeWsHarness } from "./support/FakeWsHarness.js";
import { isHelloFrame, parseFrame, sendError, sendReady, sendThreadUpsert, handleHandshake, createTestIdentityKeyPair, isAuthenticateFrame, sendChallenge } from "./support/ContractWsTestUtil.js";

function installServer(ws, { helloOk = true, failHello = false } = {}) {
  ws.addEventListener("message", (evt) => {
    const frame = parseFrame(evt);
    if (isHelloFrame(frame)) {
      if (failHello) {
        sendError(ws, frame.id, { code: "UNAUTHORIZED", message: "hello failed", retryable: false });
        return;
      }
      if (helloOk) {
        sendChallenge(ws, frame.id, frame.body || {});
      }
      return;
    }
    if (isAuthenticateFrame(frame)) {
      if (helloOk) {
        sendReady(ws, frame.id, "server");
      }
      return;
    }
    sendThreadUpsert(ws, frame.id, "server", { ok: true });
  });
}

test("selects first uplink that completes connect+hello", async () => {
  const identity = await createTestIdentityKeyPair();
  const harness = new FakeWsHarness();
  harness.register("ws://b", (ws) => installServer(ws, { helloOk: true }));

  const client = new UplinkPoolClient({
    uplinks: ["ws://a", "ws://b", "ws://c"],
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });

  await client.connect();
  assert.equal(client.getActiveUplink(), "ws://b");
  await client.close();
});

test("skips uplink with failed hello and selects next", async () => {
  const identity = await createTestIdentityKeyPair();
  const harness = new FakeWsHarness();
  harness.register("ws://a", (ws) => installServer(ws, { failHello: true }));
  harness.register("ws://b", (ws) => installServer(ws, { helloOk: true }));

  const client = new UplinkPoolClient({
    uplinks: ["ws://a", "ws://b"],
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });
  await client.connect();
  assert.equal(client.getActiveUplink(), "ws://b");
  await client.close();
});
