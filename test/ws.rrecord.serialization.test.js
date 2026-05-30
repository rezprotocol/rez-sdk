import test from "node:test";
import assert from "node:assert/strict";
import { UplinkPoolClient } from "../src/index.js";
import { RRecord } from "@rezprotocol/core";
import { FakeWsHarness } from "./support/FakeWsHarness.js";
import { isHelloFrame, parseFrame, sendReady, sendThreadUpsert, handleHandshake, createTestIdentityKeyPair, isAuthenticateFrame } from "./support/ContractWsTestUtil.js";

class SealedRecord extends RRecord {
  static type = "test.sealed.record";

  constructor({ name } = {}) {
    super();
    this.name = name;
    this._seal();
  }

  validate() {
    this.assert(typeof this.name === "string" && this.name.length > 0, "name required");
  }
}

class UnsealedRecord extends RRecord {
  static type = "test.unsealed.record";

  constructor({ name } = {}) {
    super();
    this.name = name;
  }
}

test("sdk serializes sealed RRecord payloads via toJSON", async () => {
  const identity = await createTestIdentityKeyPair();
  const harness = new FakeWsHarness();
  let observedBody = null;
  harness.register("ws://a", (ws) => {
    ws.addEventListener("message", (evt) => {
      const frame = parseFrame(evt);
      if (handleHandshake(ws, frame, "a")) return;
      if (frame.t === SealedRecord.type) {
        observedBody = frame.body;
      }
      sendThreadUpsert(ws, frame.id, "a");
    });
  });

  const client = new UplinkPoolClient({
    uplinks: ["ws://a"],
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });

  await client.connect();
  await client.request(new SealedRecord({ name: "ok" }));
  await client.close();

  assert.deepEqual(observedBody, { name: "ok" });
});

test("sdk rejects unsealed RRecord payloads before send", async () => {
  const identity = await createTestIdentityKeyPair();
  const harness = new FakeWsHarness();
  let sawSend = false;
  harness.register("ws://a", (ws) => {
    ws.addEventListener("message", (evt) => {
      const frame = parseFrame(evt);
      if (handleHandshake(ws, frame, "a")) return;
      sawSend = true;
      sendThreadUpsert(ws, frame.id, "a");
    });
  });

  const client = new UplinkPoolClient({
    uplinks: ["ws://a"],
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });

  await client.connect();
  await assert.rejects(
    () => client.request(new UnsealedRecord({ name: "nope" })),
    (err) => err?.name === "RezInvariantError"
  );
  await client.close();

  assert.equal(sawSend, false);
});
