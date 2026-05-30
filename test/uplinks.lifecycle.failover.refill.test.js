import test from "node:test";
import assert from "node:assert/strict";
import { UplinkPoolClient } from "../src/index.js";
import { FakeWsHarness } from "./support/FakeWsHarness.js";
import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";
import { isHelloFrame, parseFrame, sendError, sendReady, sendThreadUpsert, handleHandshake, createTestIdentityKeyPair, isAuthenticateFrame, sendChallenge } from "./support/ContractWsTestUtil.js";

function waitTick() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function waitFor(predicate, timeoutMs = 250) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return true;
    await waitTick();
  }
  return false;
}

function installServer(ws, label, stats) {
  ws.addEventListener("message", (evt) => {
    const frame = parseFrame(evt);
    const atMs = Date.now();
    if (isHelloFrame(frame)) {
      stats.connectAttempts[label] = (stats.connectAttempts[label] || 0) + 1;
      sendChallenge(ws, frame.id, frame.body || {});
      return;
    }
    if (isAuthenticateFrame(frame)) {
      sendReady(ws, frame.id, label);
      return;
    }

    stats.receivedByUrl[label].push({
      uplink: label,
      id: frame.id,
      reqKey: frame.body?.cursor || null,
      t: frame.t,
      atMs,
    });

    if (label === "A" && frame.body?.cursor === "retryable-once" && !stats.retryInjected) {
      stats.retryInjected = true;
      sendError(ws, frame.id, { code: "RATE_LIMITED", message: "retry later", retryable: true });
      return;
    }

    sendThreadUpsert(ws, frame.id, label, { reqKey: frame.body?.cursor || null });
  });
}

test("lifecycle: connect, failover, continue requests, refill warm spares", async () => {
  const harness = new FakeWsHarness();
  const stats = {
    connectAttempts: { A: 0, B: 0, C: 0 },
    receivedByUrl: { A: [], B: [], C: [] },
    retryInjected: false,
  };
  let wsA;
  let wsB;
  let wsC;
  harness.register("ws://a", (ws) => {
    wsA = ws;
    installServer(ws, "A", stats);
  });
  harness.register("ws://b", (ws) => {
    wsB = ws;
    installServer(ws, "B", stats);
  });
  harness.register("ws://c", (ws) => {
    wsC = ws;
    installServer(ws, "C", stats);
  });

  const identity = await createTestIdentityKeyPair();
  const client = new UplinkPoolClient({
    uplinks: ["ws://a", "ws://b", "ws://c"],
    warmSpareCount: 2,
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });
  const stateEvents = [];
  client.onState((state) => stateEvents.push({ ...state, atMs: Date.now() }));
  await client.connect();

  assert.equal(client.getActiveUplink(), "ws://a");
  assert.equal(stats.connectAttempts.A >= 1, true);
  assert.equal(stats.connectAttempts.B >= 1, true);
  assert.equal(stats.connectAttempts.C >= 1, true);

  const first = await client.request(REZ_CONTRACT_TYPES.MAILBOX_LIST, { cursor: "single-a", mailboxId: "mbox:test" });
  assert.equal(first.mailboxId, "mbox:A");
  assert.equal(stats.receivedByUrl.A.length, 1);
  assert.equal(stats.receivedByUrl.B.length, 0);
  assert.equal(stats.receivedByUrl.C.length, 0);

  // This request intentionally fails once on A with retryable error and must fail over to B.
  const second = await client.request(REZ_CONTRACT_TYPES.MAILBOX_LIST, { cursor: "retryable-once", mailboxId: "mbox:test" });
  assert.equal(second.mailboxId, "mbox:B");
  const promoted = await waitFor(() => client.getActiveUplink() === "ws://b");
  assert.equal(promoted, true);

  const gotFailover = await waitFor(
    () =>
      stateEvents.some(
        (evt) =>
          evt.phase === "failover" && evt.from === "ws://a" && evt.to === "ws://b" && evt.reason === "request_retryable_error"
      ),
    500
  );
  assert.ok(gotFailover, "expected failover state event");
  const failoverEvent = stateEvents.find(
    (evt) => evt.phase === "failover" && evt.from === "ws://a" && evt.to === "ws://b" && evt.reason === "request_retryable_error"
  );

  // No-broadcast invariant:
  // each wire request id is never sent concurrently to multiple uplinks.
  // If an id repeats across uplinks (possible due per-connection id generators),
  // the later occurrence must be after failover.
  const allByRequestId = new Map();
  for (const frames of Object.values(stats.receivedByUrl)) {
    for (const frame of frames) {
      const list = allByRequestId.get(frame.id) || [];
      list.push(frame);
      allByRequestId.set(frame.id, list);
    }
  }
  for (const entries of allByRequestId.values()) {
    if (entries.length === 1) continue;
    const sorted = [...entries].sort((a, b) => a.atMs - b.atMs);
    for (let i = 1; i < sorted.length; i += 1) {
      assert.equal(sorted[i].atMs >= failoverEvent.atMs, true);
    }
  }

  // Retry ordering invariant on logical request key.
  const retryFrames = [
    ...stats.receivedByUrl.A.filter((f) => f.reqKey === "retryable-once"),
    ...stats.receivedByUrl.B.filter((f) => f.reqKey === "retryable-once"),
    ...stats.receivedByUrl.C.filter((f) => f.reqKey === "retryable-once"),
  ].sort((a, b) => a.atMs - b.atMs);
  assert.deepEqual(retryFrames.map((f) => f.uplink), ["A", "B"]);
  assert.equal(retryFrames[1].atMs >= failoverEvent.atMs, true);
  const singleFrames = [
    ...stats.receivedByUrl.A.filter((f) => f.reqKey === "single-a"),
    ...stats.receivedByUrl.B.filter((f) => f.reqKey === "single-a"),
    ...stats.receivedByUrl.C.filter((f) => f.reqKey === "single-a"),
  ];
  assert.deepEqual(singleFrames.map((f) => f.uplink), ["A"]);

  /*
   * Spare refill expectations:
   * - refill is opportunistic and follows uplink preference order.
   * - immediate refill under flapping links is not guaranteed.
   * - reconnect attempts must stay bounded for a single event chain (no storm loop).
   */
  wsC.close(1012, "drop-spare");
  const refilled1 = await waitFor(() => stats.connectAttempts.C >= 2, 10000);
  assert.equal(refilled1, true);

  wsC.close(1012, "drop-spare-again");
  const refilled2 = await waitFor(() => stats.connectAttempts.C >= 3, 10000);
  assert.equal(refilled2, true);
  assert.equal(stats.connectAttempts.C <= 3, true);

  await client.close();
});
