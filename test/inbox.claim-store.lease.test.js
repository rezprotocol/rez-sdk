import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { verifyTerminalInboxClose, canonicalJSONStringify, bytesToBase64, base64ToBytes } from "@rezprotocol/core";
import { InboxClaimStore } from "../src/inbox/InboxClaimStore.js";

// Portable inbox lease L1, SDK side (plans/PORTABLE_INBOX_LEASE_SPEC.md §2):
// v2 claims mint a random CLOSE keypair + generation inside the signed
// payload; the delegation carries the lease fields; createTerminalClose is
// the one sanctioned use of the close private key; legacy records stay legacy.

class MemoryKV {
  #m = new Map();
  async get(k) { return this.#m.has(k) ? this.#m.get(k) : null; }
  async set(k, v) { this.#m.set(k, v); }
}
class MemoryStorageProvider {
  #kv = new MemoryKV();
  getKeyValueStore() { return this.#kv; }
}

// WebCrypto-free ed25519 provider for tests (node:crypto, DER keys — the same
// format the SDK uses in production).
const CRYPTO = {
  randomBytes: (n) => crypto.randomBytes(n),
  async sign({ privateKey, msg }) {
    const key = crypto.createPrivateKey({ key: Buffer.from(privateKey), format: "der", type: "pkcs8" });
    return new Uint8Array(crypto.sign(null, Buffer.from(msg), key));
  },
  async verify({ publicKey, msg, sig }) {
    const key = crypto.createPublicKey({ key: Buffer.from(publicKey), format: "der", type: "spki" });
    return crypto.verify(null, Buffer.from(msg), key, Buffer.from(sig));
  },
  async generateSigningKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    return {
      publicKey: new Uint8Array(publicKey.export({ format: "der", type: "spki" })),
      privateKey: new Uint8Array(privateKey.export({ format: "der", type: "pkcs8" })),
    };
  },
};

async function makeStore(storageProvider = new MemoryStorageProvider()) {
  const store = new InboxClaimStore({ storageProvider, cryptoProvider: CRYPTO });
  await store.hydrate();
  return store;
}

test("L1: createClaim mints a distinct random close keypair + generation 1, signed into the v2 payload", async () => {
  const store = await makeStore();
  const claim = await store.createClaim();
  assert.ok(claim.closePublicKeyB64 && claim.closePrivateKeyB64);
  assert.notEqual(claim.closePublicKeyB64, claim.claimantPublicKeyB64, "close key ≠ claim key");
  assert.equal(claim.generation, 1);

  // The signature covers the v2 payload — verify it independently.
  const verified = await CRYPTO.verify({
    publicKey: base64ToBytes(claim.claimantPublicKeyB64),
    msg: new TextEncoder().encode(canonicalJSONStringify({
      inboxId: claim.inboxId,
      claimantPublicKeyB64: claim.claimantPublicKeyB64,
      closePublicKeyB64: claim.closePublicKeyB64,
      generation: claim.generation,
      claimedAtMs: claim.claimedAtMs,
    })),
    sig: base64ToBytes(claim.claimSignatureB64),
  });
  assert.equal(verified, true, "v2 claim payload signature verifies");
});

test("L1: v2 fields survive persist + rehydrate; reattestation carries them; the delegation carries generation + retentionClass", async () => {
  const storageProvider = new MemoryStorageProvider();
  const store = await makeStore(storageProvider);
  const claim = await store.persist(await store.createClaim());

  const reloaded = await makeStore(storageProvider);
  const record = reloaded.get(claim.inboxId);
  assert.equal(record.closePublicKeyB64, claim.closePublicKeyB64);
  assert.equal(record.generation, 1);

  const attestation = await reloaded.createReattestation(claim.inboxId);
  assert.equal(attestation.closePublicKeyB64, claim.closePublicKeyB64);
  assert.equal(attestation.generation, 1);

  const nodeKp = await CRYPTO.generateSigningKeyPair();
  const nodePublicKeyB64 = bytesToBase64(nodeKp.publicKey);
  const { relayKeyIdForNodePublicKeyB64, nodeKeyIdForNodePublicKeyB64 } = await import("@rezprotocol/core");
  const delegation = await reloaded.createNodeDelegation({
    inboxId: claim.inboxId,
    nodeKeyId: nodeKeyIdForNodePublicKeyB64(nodePublicKeyB64),
    nodePublicKeyB64,
    relayKeyId: relayKeyIdForNodePublicKeyB64(nodePublicKeyB64),
  });
  assert.equal(delegation.generation, 1);
  assert.equal(delegation.retentionClass, "transient");
});

test("L1: createTerminalClose round-trips verifyTerminalInboxClose against the close public key — and against NOTHING else", async () => {
  const store = await makeStore();
  const claim = await store.persist(await store.createClaim());
  const close = await store.createTerminalClose(claim.inboxId);
  assert.equal(close.inboxId, claim.inboxId);
  assert.equal(close.finalGeneration, 1);

  assert.equal(await verifyTerminalInboxClose({
    close, expectedClosePublicKeyB64: claim.closePublicKeyB64, crypto: CRYPTO,
  }), true);
  assert.equal(await verifyTerminalInboxClose({
    close, expectedClosePublicKeyB64: claim.claimantPublicKeyB64, crypto: CRYPTO,
  }), false, "the claim key can renew but can NEVER kill");
});

test("L1 migration: a seeded LEGACY record stays legacy — legacy reattestation shape, and createTerminalClose fails loud with INBOX_NOT_CLOSABLE", async () => {
  const storageProvider = new MemoryStorageProvider();
  const store = await makeStore(storageProvider);
  const legacy = await store.persist(await (async () => {
    const claim = await store.createClaim();
    // Strip the v2 fields to simulate a pre-L1 stored record (the normalize
    // path accepts a fully-legacy row).
    const { closePublicKeyB64, closePrivateKeyB64, generation, ...rest } = claim;
    void closePublicKeyB64; void closePrivateKeyB64; void generation;
    return rest;
  })());
  assert.equal(legacy.generation, undefined);

  const attestation = await store.createReattestation(legacy.inboxId);
  assert.equal(attestation.generation, undefined, "legacy reattestation carries no lease fields");

  await assert.rejects(
    () => store.createTerminalClose(legacy.inboxId),
    (err) => err.code === "INBOX_NOT_CLOSABLE",
    "no close key ⇒ not closable by record; the lease simply lapses",
  );
});
