import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {
  MemoryStorageProvider,
  RCapability,
  RCryptoProvider,
  base64ToBytes,
  bytesToBase64,
  canonicalJSONStringify,
} from "@rezprotocol/core";
import { InboxClaimStore } from "../src/inbox/InboxClaimStore.js";

// A minimal RCryptoProvider implementation using node's webcrypto + tweetnacl-like
// path. Production SDK uses the browser's webcrypto; for tests, node's `webcrypto`
// global provides the same surface.
class TestCrypto extends RCryptoProvider {
  constructor() {
    super();
    this._subtle = webcrypto.subtle;
  }
  randomBytes(n) {
    const out = new Uint8Array(n);
    webcrypto.getRandomValues(out);
    return out;
  }
  async generateSigningKeyPair() {
    const kp = await this._subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const pubRaw = new Uint8Array(await this._subtle.exportKey("raw", kp.publicKey));
    const pkcs8 = new Uint8Array(await this._subtle.exportKey("pkcs8", kp.privateKey));
    // Extract the 32-byte seed from pkcs8 (last 32 bytes for ed25519).
    const seed = pkcs8.slice(pkcs8.length - 32);
    return { publicKey: pubRaw, privateKey: seed };
  }
  async sign({ privateKey, msg }) {
    // Rebuild pkcs8 from the 32-byte seed by prepending the standard ed25519
    // pkcs8 prefix (this is what node's webcrypto expects for raw-seed import).
    const PKCS8_PREFIX = new Uint8Array([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
      0x04, 0x22, 0x04, 0x20,
    ]);
    const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + privateKey.length);
    pkcs8.set(PKCS8_PREFIX, 0);
    pkcs8.set(privateKey, PKCS8_PREFIX.length);
    const key = await this._subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
    const sig = new Uint8Array(await this._subtle.sign({ name: "Ed25519" }, key, msg));
    return sig;
  }
  async verify({ publicKey, msg, sig }) {
    const key = await this._subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return this._subtle.verify({ name: "Ed25519" }, key, sig, msg);
  }
}

function makeStore() {
  const storageProvider = new MemoryStorageProvider();
  const cryptoProvider = new TestCrypto();
  return {
    storageProvider,
    cryptoProvider,
    store: new InboxClaimStore({ storageProvider, cryptoProvider }),
  };
}

test("InboxClaimStore requires storageProvider and cryptoProvider", () => {
  assert.throws(() => new InboxClaimStore({}), /storageProvider/);
  assert.throws(() => new InboxClaimStore({ storageProvider: new MemoryStorageProvider() }), /cryptoProvider/);
});

test("methods reject calls before hydrate", async () => {
  const { store } = makeStore();
  await assert.rejects(() => store.createClaim(), /hydrate/);
  assert.throws(() => store.get("inbox:x"), /hydrate/);
  assert.throws(() => store.size(), /hydrate/);
  assert.throws(() => store.has("inbox:x"), /hydrate/);
  assert.throws(() => store.listRedacted(), /hydrate/);
});

test("createClaim produces a self-consistent signed record", async () => {
  const { store, cryptoProvider } = makeStore();
  await store.hydrate();
  const claim = await store.createClaim({ clock: () => 1700000000000 });

  // Shape
  assert.ok(claim.inboxId.startsWith("inbox:"));
  assert.equal(typeof claim.claimantPublicKeyB64, "string");
  assert.equal(typeof claim.claimantPrivateKeyB64, "string");
  assert.equal(claim.claimedAtMs, 1700000000000);
  assert.ok(claim.rootCap instanceof RCapability);

  // Signature verifies against the supplied claimant pubkey
  const verified = await cryptoProvider.verify({
    publicKey: base64ToBytes(claim.claimantPublicKeyB64),
    msg: new TextEncoder().encode(canonicalJSONStringify({
      inboxId: claim.inboxId,
      claimantPublicKeyB64: claim.claimantPublicKeyB64,
      claimedAtMs: claim.claimedAtMs,
    })),
    sig: base64ToBytes(claim.claimSignatureB64),
  });
  assert.equal(verified, true);

  // The root cap's resource targets the right inbox. inboxIds carry the
  // `inbox:` prefix so the resource string equals the inboxId verbatim.
  assert.equal(claim.rootCap.resource, claim.inboxId);
  assert.deepEqual([...claim.rootCap.actions].sort(), ["admin", "grant", "read", "write"]);

  // Not yet persisted — store still empty
  assert.equal(store.size(), 0);
  assert.equal(store.has(claim.inboxId), false);
});

test("each createClaim produces distinct keypairs and inbox IDs", async () => {
  const { store } = makeStore();
  await store.hydrate();
  const a = await store.createClaim();
  const b = await store.createClaim();
  assert.notEqual(a.inboxId, b.inboxId);
  assert.notEqual(a.claimantPublicKeyB64, b.claimantPublicKeyB64);
  assert.notEqual(a.claimantPrivateKeyB64, b.claimantPrivateKeyB64);
});

test("persist + get round-trips through storage", async () => {
  const { store } = makeStore();
  await store.hydrate();
  const claim = await store.createClaim({ clock: () => 1700000000000 });
  const persisted = await store.persist(claim);

  assert.equal(persisted.inboxId, claim.inboxId);
  assert.equal(store.size(), 1);
  assert.equal(store.has(claim.inboxId), true);
  const fetched = store.get(claim.inboxId);
  assert.equal(fetched.inboxId, claim.inboxId);
  assert.equal(fetched.claimantPublicKeyB64, claim.claimantPublicKeyB64);
  assert.equal(fetched.claimantPrivateKeyB64, claim.claimantPrivateKeyB64);
  assert.ok(fetched.rootCap instanceof RCapability);
});

test("persisted claims survive across new InboxClaimStore instances", async () => {
  const storageProvider = new MemoryStorageProvider();
  const cryptoProvider = new TestCrypto();

  const first = new InboxClaimStore({ storageProvider, cryptoProvider });
  await first.hydrate();
  const c1 = await first.createClaim();
  const c2 = await first.createClaim();
  await first.persist(c1);
  await first.persist(c2);

  const second = new InboxClaimStore({ storageProvider, cryptoProvider });
  await second.hydrate();
  assert.equal(second.size(), 2);
  assert.equal(second.has(c1.inboxId), true);
  assert.equal(second.has(c2.inboxId), true);
});

test("listRedacted does not leak private keys", async () => {
  const { store } = makeStore();
  await store.hydrate();
  const claim = await store.createClaim();
  await store.persist(claim);
  const list = store.listRedacted();
  assert.equal(list.length, 1);
  assert.equal(list[0].inboxId, claim.inboxId);
  assert.equal(list[0].claimantPublicKeyB64, claim.claimantPublicKeyB64);
  assert.equal(list[0].claimantPrivateKeyB64, undefined);
  assert.equal(list[0].claimSignatureB64, undefined);
  assert.equal(list[0].rootCap, undefined);
});

test("createReattestation produces a fresh signature using the stored privkey", async () => {
  const { store, cryptoProvider } = makeStore();
  await store.hydrate();
  const claim = await store.createClaim({ clock: () => 1 });
  await store.persist(claim);

  const reattest = await store.createReattestation(claim.inboxId, { clock: () => 9999 });
  assert.equal(reattest.inboxId, claim.inboxId);
  assert.equal(reattest.claimantPublicKeyB64, claim.claimantPublicKeyB64);
  assert.equal(reattest.claimedAtMs, 9999);
  // Different claimedAtMs ⇒ different signature
  assert.notEqual(reattest.claimSignatureB64, claim.claimSignatureB64);

  // Verifies against the same claimant pubkey
  const verified = await cryptoProvider.verify({
    publicKey: base64ToBytes(claim.claimantPublicKeyB64),
    msg: new TextEncoder().encode(canonicalJSONStringify({
      inboxId: claim.inboxId,
      claimantPublicKeyB64: claim.claimantPublicKeyB64,
      claimedAtMs: 9999,
    })),
    sig: base64ToBytes(reattest.claimSignatureB64),
  });
  assert.equal(verified, true);
});

test("createReattestation fails for an unknown inbox", async () => {
  const { store } = makeStore();
  await store.hydrate();
  await assert.rejects(() => store.createReattestation("inbox:never"), /no claim/);
});
