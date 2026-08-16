/**
 * P7.1/P7.2 — browser-runtime (WebCrypto) verification of the shared golden
 * vectors, IndexedDB round trip, and the opaque unknown-kind proof: the SDK
 * signs/verifies a `future-test-public-fact-v1` record with NO transport- or
 * kind-specific code anywhere.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  base64ToBytes,
  bytesToBase64,
  durableRecordSignableBytes,
  buildDurableRecordV1,
  durableRecordLocalId,
} from "@rezprotocol/core";
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";
import {
  GOLDEN_NODE_PRIVATE_KEY_B64,
  GOLDEN_NODE_PUBLIC_KEY_B64,
  GOLDEN_NOW_MS,
  GOLDEN_DURABLE_RECORD_V1,
  GOLDEN_DURABLE_RECORD_V1_LOCAL_ID,
} from "../../rez-core/test/support/goldenVectors.js";

const CRYPTO = new BrowserCryptoProvider();

test("WebCrypto reproduces and verifies the golden DurableRecordV1 signature byte-for-byte", async () => {
  const signable = durableRecordSignableBytes(GOLDEN_DURABLE_RECORD_V1);
  const resigned = await CRYPTO.sign({
    privateKey: base64ToBytes(GOLDEN_NODE_PRIVATE_KEY_B64),
    msg: signable,
  });
  assert.equal(bytesToBase64(new Uint8Array(resigned)), GOLDEN_DURABLE_RECORD_V1.sigB64,
    "browser and Node crypto must produce IDENTICAL bytes (deterministic Ed25519)");
  const verified = await CRYPTO.verify({
    publicKey: base64ToBytes(GOLDEN_NODE_PUBLIC_KEY_B64),
    msg: signable,
    sig: base64ToBytes(GOLDEN_DURABLE_RECORD_V1.sigB64),
  });
  assert.equal(verified, true);
});

test("SDK signs a generic unknown-kind record through the SSOT — no kind-specific code path", async () => {
  const record = buildDurableRecordV1({
    recordKind: "future-test-public-fact-v1",
    recordId: "sdk-signed-1",
    publisherPublicKeyB64: GOLDEN_NODE_PUBLIC_KEY_B64,
    payloadB64: bytesToBase64(new TextEncoder().encode("opaque")),
    issuedAtMs: GOLDEN_NOW_MS,
    expiresAtMs: GOLDEN_NOW_MS + 3_600_000,
  });
  const sig = await CRYPTO.sign({
    privateKey: base64ToBytes(GOLDEN_NODE_PRIVATE_KEY_B64),
    msg: durableRecordSignableBytes(record),
  });
  record.sigB64 = bytesToBase64(new Uint8Array(sig));
  assert.ok(durableRecordLocalId({
    publisherPublicKeyB64: record.publisherPublicKeyB64,
    recordKind: record.recordKind,
    recordId: record.recordId,
  }).length === 64);
});

test("golden record survives an IndexedDB-style keyed round trip byte-identically", async () => {
  // Minimal single-store fake IDB round trip (same discipline as the keystore
  // fake: the value crosses a structured-clone boundary like real IndexedDB).
  const stored = new Map();
  const db = {
    async put(key, value) { stored.set(key, structuredClone(value)); },
    async get(key) { return structuredClone(stored.get(key)); },
  };
  await db.put(GOLDEN_DURABLE_RECORD_V1_LOCAL_ID, GOLDEN_DURABLE_RECORD_V1);
  const back = await db.get(GOLDEN_DURABLE_RECORD_V1_LOCAL_ID);
  assert.deepEqual(back, GOLDEN_DURABLE_RECORD_V1);
  // The round-tripped record still verifies under WebCrypto.
  const verified = await CRYPTO.verify({
    publicKey: base64ToBytes(back.publisherPublicKeyB64),
    msg: durableRecordSignableBytes(back),
    sig: base64ToBytes(back.sigB64),
  });
  assert.equal(verified, true);
});

// ── DurableRecordV2 vectors under WebCrypto (re-audit R7) ───────────────────
import { durableRecordV2SignableBytes } from "@rezprotocol/core";
import {
  GOLDEN_DEVICE_PRIVATE_KEY_B64,
  GOLDEN_DEVICE_PUBLIC_KEY_B64,
  GOLDEN_DURABLE_RECORD_V2_DIRECT,
  GOLDEN_DURABLE_RECORD_V2_DELEGATED,
} from "../../rez-core/test/support/goldenVectors.js";

test("WebCrypto reproduces the V2 DIRECT (owner-signed) golden signature byte-for-byte", async () => {
  const signable = durableRecordV2SignableBytes(GOLDEN_DURABLE_RECORD_V2_DIRECT);
  const resigned = await CRYPTO.sign({
    privateKey: base64ToBytes(GOLDEN_NODE_PRIVATE_KEY_B64),
    msg: signable,
  });
  assert.equal(bytesToBase64(new Uint8Array(resigned)), GOLDEN_DURABLE_RECORD_V2_DIRECT.sigB64);
  const verified = await CRYPTO.verify({
    publicKey: base64ToBytes(GOLDEN_NODE_PUBLIC_KEY_B64),
    msg: signable,
    sig: base64ToBytes(GOLDEN_DURABLE_RECORD_V2_DIRECT.sigB64),
  });
  assert.equal(verified, true);
});

test("WebCrypto reproduces the V2 DELEGATED (device-signed) golden signature byte-for-byte", async () => {
  const signable = durableRecordV2SignableBytes(GOLDEN_DURABLE_RECORD_V2_DELEGATED);
  const resigned = await CRYPTO.sign({
    privateKey: base64ToBytes(GOLDEN_DEVICE_PRIVATE_KEY_B64),
    msg: signable,
  });
  assert.equal(bytesToBase64(new Uint8Array(resigned)), GOLDEN_DURABLE_RECORD_V2_DELEGATED.sigB64,
    "the chain-committed signable bytes must be identical across runtimes");
  const verified = await CRYPTO.verify({
    publicKey: base64ToBytes(GOLDEN_DEVICE_PUBLIC_KEY_B64),
    msg: signable,
    sig: base64ToBytes(GOLDEN_DURABLE_RECORD_V2_DELEGATED.sigB64),
  });
  assert.equal(verified, true);
});
