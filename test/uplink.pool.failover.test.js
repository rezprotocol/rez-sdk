import test from "node:test";
import assert from "node:assert/strict";
import { UplinkPoolClient } from "../src/index.js";
import { FakeWsHarness } from "./support/FakeWsHarness.js";
import { isHelloFrame, parseFrame, sendError, sendReady, sendThreadUpsert, handleHandshake, createTestIdentityKeyPair, isAuthenticateFrame, sendChallenge } from "./support/ContractWsTestUtil.js";
import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";

function serverWithBehavior(ws, { failOps = false, closeAfterHello = false, label = "x" } = {}) {
  ws.addEventListener("message", (evt) => {
    const frame = parseFrame(evt);
    if (isHelloFrame(frame)) {
      sendChallenge(ws, frame.id, frame.body || {});
      return;
    }
    if (isAuthenticateFrame(frame)) {
      sendReady(ws, frame.id, label);
      if (closeAfterHello) {
        queueMicrotask(() => ws.close(1012, "restart"));
      }
      return;
    }
    if (failOps) {
      sendError(ws, frame.id, { code: "RATE_LIMITED", message: "retry later", retryable: true });
      return;
    }
    sendThreadUpsert(ws, frame.id, label);
  });
}

test("fails over on retryable request failure", async () => {
  const identity = await createTestIdentityKeyPair();
  const harness = new FakeWsHarness();
  harness.register("ws://a", (ws) => serverWithBehavior(ws, { failOps: true, label: "a" }));
  harness.register("ws://b", (ws) => serverWithBehavior(ws, { failOps: false, label: "b" }));

  const client = new UplinkPoolClient({
    uplinks: ["ws://a", "ws://b"],
    warmSpareCount: 1,
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });
  await client.connect();
  const out = await client.request(REZ_CONTRACT_TYPES.MAILBOX_LIST, { mailboxId: "mbox:test" });
  assert.equal(out.mailboxId, "mbox:b");
  assert.equal(client.getActiveUplink(), "ws://b");
  await client.close();
});

test("does not fail over for non-retryable errors", async () => {
  const identity = await createTestIdentityKeyPair();
  const harness = new FakeWsHarness();
  harness.register("ws://a", (ws) => {
    ws.addEventListener("message", (evt) => {
      const frame = parseFrame(evt);
      if (handleHandshake(ws, frame, "a")) return;
      sendError(ws, frame.id, { code: "BAD_REQUEST", message: "bad", retryable: false });
    });
  });
  harness.register("ws://b", (ws) => serverWithBehavior(ws, { failOps: false, label: "b" }));

  const client = new UplinkPoolClient({
    uplinks: ["ws://a", "ws://b"],
    warmSpareCount: 1,
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });
  await client.connect();
  await assert.rejects(
    () => client.request(REZ_CONTRACT_TYPES.MAILBOX_LIST, { mailboxId: "mbox:test" }),
    (err) => err?.code === "BAD_REQUEST"
  );
  assert.equal(client.getActiveUplink(), "ws://a");
  await client.close();
});
