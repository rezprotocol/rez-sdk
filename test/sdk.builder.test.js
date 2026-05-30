import test from "node:test";
import assert from "node:assert/strict";
import { RezRuntimeBuilder } from "../src/builders/RezRuntimeBuilder.js";
import { Header, Envelope } from "@rezprotocol/core";


test("RezRuntimeBuilder defaults", () => {
  const runtime = new RezRuntimeBuilder().build();

  const header = new Header({ id: "sdk-1", type: "message", createdAt: 1 });
  const envelope = new Envelope({ header, body: { z: 1, a: 2 } });

  const bytes = runtime.encodeEnvelope(envelope);
  const decoded = runtime.decodeEnvelope(bytes);

  assert.deepEqual(decoded.toJSON(), envelope.toJSON());

  const id = runtime.saveEnvelope(envelope);
  const loaded = runtime.loadEnvelope(id);
  assert.deepEqual(loaded?.toJSON(), envelope.toJSON());
});
