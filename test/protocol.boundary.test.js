import test from "node:test";
import assert from "node:assert/strict";
import {
  encodeEnvelope,
  decodeEnvelope,
  verifyEnvelope,
  signEnvelope,
} from "../src/client/index.js";

test("protocol envelope round-trip encode/decode", () => {
  const envelope = {
    id: "env-1",
    type: "demo.event",
    body: { ok: true },
    v: 1,
  };

  const bytes = encodeEnvelope(envelope);
  assert.ok(bytes instanceof Uint8Array);

  const decoded = decodeEnvelope(bytes);
  assert.deepEqual(decoded, envelope);

  const verified = verifyEnvelope(decoded, {
    verify(value) {
      return value.id === "env-1";
    },
  });
  assert.equal(verified.id, "env-1");
});

test("protocol signEnvelope adds signature", async () => {
  const envelope = { id: "env-2", type: "demo.event", body: { count: 1 }, v: 1 };
  const signed = await signEnvelope(envelope, {
    async sign(bytes) {
      return bytes;
    },
  });
  assert.equal(typeof signed.signature, "string");
  assert.ok(signed.signature.length > 0);
});
