import test from "node:test";
import assert from "node:assert/strict";
import {
  DeliveryTransportDescriptorV1,
  RDeliveryTransport,
} from "@rezprotocol/sdk/delivery";

test("RDeliveryTransport exposes the frozen post-seal carrier interface", async () => {
  const transport = new RDeliveryTransport();
  assert.throws(() => transport.descriptor(), /descriptor/);
  await assert.rejects(() => transport.start({}), /start/);
  await assert.rejects(() => transport.stop(), /stop/);
  await assert.rejects(() => transport.assess({}), /assess/);
  await assert.rejects(() => transport.submit({}), /submit/);
  assert.throws(() => transport.onInbound(async () => {}), /onInbound/);
  await assert.rejects(() => transport.settle({}), /settle/);
  await assert.rejects(() => transport.queryCustody({}), /queryCustody/);
});

test("an implementation can provide the interface without inheriting policy or crypto behavior", async () => {
  const descriptor = new DeliveryTransportDescriptorV1({
    transportKind: "fake",
    transportInstanceId: "trinst_0123456789abcdef0123456789abcdef",
    profileId: "fake.test.v1",
    profileVersion: 1,
    profileFingerprintHex: "ab".repeat(32),
    maxPayloadBytes: 1024,
    maxDeliveryAgeMs: 1000,
    custodyStages: ["carrier-accepted"],
    idempotencyMode: "transport-scoped-token",
  });
  class FakeDeliveryTransport extends RDeliveryTransport {
    descriptor() { return descriptor; }
    async start() { return undefined; }
    async stop() { return undefined; }
    async assess(record) { return record; }
    async submit(record) { return record; }
    onInbound(handler) { this.handler = handler; return () => { this.handler = null; }; }
    async settle(record) { return record; }
    async queryCustody(record) { return record; }
  }

  const transport = new FakeDeliveryTransport();
  assert.equal(transport.descriptor().transportKind, "fake");
  assert.equal(transport.descriptor().transportInstanceId, descriptor.transportInstanceId);
  assert.deepEqual(await transport.assess({ payloadSizeBytes: 4 }), { payloadSizeBytes: 4 });
  assert.deepEqual(await transport.submit({ sealedBytesB64: "AQIDBA==" }), { sealedBytesB64: "AQIDBA==" });
  const unsubscribe = transport.onInbound(async () => {});
  assert.equal(typeof unsubscribe, "function");
  unsubscribe();
});
