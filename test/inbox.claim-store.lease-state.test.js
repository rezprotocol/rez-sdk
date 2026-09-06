// M3 (rez-chat plans/MOBILE_LIFECYCLE_ADAPTER_PLAN.md §7c) — durable
// last-ACCEPTED lease state in InboxClaimStore. The pins under test:
//   1. Only accepted state persists (the caller invokes recordAcceptedLease
//      strictly after the wire op succeeds; this file proves the store side:
//      validation, durability, rollback).
//   3. A failed persist leaves the previous durable state intact — the store
//      never claims a durability it does not have.
// Absence semantics: no/invalid lease state derives as "renew now" at the
// caller — so normalization treats a malformed lease sub-record as ABSENT
// (the safe direction) while never invalidating the irreplaceable claim keys.

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { InboxClaimStore } from "../src/inbox/InboxClaimStore.js";

class MemoryKV {
  constructor() { this.m = new Map(); this.failNextSet = false; }
  async get(k) { return this.m.has(k) ? this.m.get(k) : null; }
  async getStrict(k) { return this.get(k); }
  async set(k, v) {
    if (this.failNextSet) {
      this.failNextSet = false;
      throw new Error("disk full");
    }
    // Deep-copy through JSON so in-memory aliasing cannot fake durability.
    this.m.set(k, JSON.parse(JSON.stringify(v)));
  }
}
class MemoryStorageProvider {
  constructor() { this.kv = new MemoryKV(); }
  getKeyValueStore() { return this.kv; }
}

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

async function makeStoreWithClaim(storageProvider = new MemoryStorageProvider()) {
  const store = new InboxClaimStore({ storageProvider, cryptoProvider: CRYPTO });
  await store.hydrate();
  const claim = await store.createClaim();
  await store.persist(claim);
  return { store, claim, storageProvider };
}

test("M3: recordAcceptedLease round-trips through leaseState and SURVIVES rehydration from storage", async () => {
  const { store, claim, storageProvider } = await makeStoreWithClaim();
  assert.equal(store.leaseState(claim.inboxId), null, "no lease until one is accepted");

  const recorded = await store.recordAcceptedLease({
    inboxId: claim.inboxId, issuedAtMs: 1000, expiresAtMs: 8000, retentionClass: "standard",
  });
  assert.deepEqual(recorded, { issuedAtMs: 1000, expiresAtMs: 8000, retentionClass: "standard" });
  assert.deepEqual(store.leaseState(claim.inboxId), recorded);

  // A fresh store over the same storage — the wake-after-kill read path.
  const rehydrated = new InboxClaimStore({ storageProvider, cryptoProvider: CRYPTO });
  await rehydrated.hydrate();
  assert.deepEqual(rehydrated.leaseState(claim.inboxId), recorded, "lease state is durable, not in-memory");
});

test("M3: recordAcceptedLease validates its inputs loudly", async () => {
  const { store, claim } = await makeStoreWithClaim();
  await assert.rejects(store.recordAcceptedLease({ inboxId: "inbox:doesnotexist000000000000", issuedAtMs: 1, expiresAtMs: 2 }), /no claim for/);
  await assert.rejects(store.recordAcceptedLease({ inboxId: claim.inboxId, issuedAtMs: 2000, expiresAtMs: 2000 }), /invalid lease window/);
  await assert.rejects(store.recordAcceptedLease({ inboxId: claim.inboxId, issuedAtMs: 2000, expiresAtMs: 1000 }), /invalid lease window/);
  await assert.rejects(store.recordAcceptedLease({ inboxId: claim.inboxId, issuedAtMs: 1, expiresAtMs: 2, retentionClass: "eternal" }), /unknown retentionClass/);
  assert.equal(store.leaseState(claim.inboxId), null, "nothing recorded by refused calls");
});

test("M3 pin 3: a failed persist ROLLS BACK — the previous lease state stays intact in memory and on disk", async () => {
  const { store, claim, storageProvider } = await makeStoreWithClaim();
  await store.recordAcceptedLease({ inboxId: claim.inboxId, issuedAtMs: 1000, expiresAtMs: 8000, retentionClass: "standard" });

  storageProvider.kv.failNextSet = true;
  await assert.rejects(
    store.recordAcceptedLease({ inboxId: claim.inboxId, issuedAtMs: 5000, expiresAtMs: 12000, retentionClass: "standard" }),
    /disk full/,
  );
  const previous = { issuedAtMs: 1000, expiresAtMs: 8000, retentionClass: "standard" };
  assert.deepEqual(store.leaseState(claim.inboxId), previous, "in-memory view rolled back");

  const rehydrated = new InboxClaimStore({ storageProvider, cryptoProvider: CRYPTO });
  await rehydrated.hydrate();
  assert.deepEqual(rehydrated.leaseState(claim.inboxId), previous, "durable view never advanced");
});

test("M3: persist() of claim material does not drop a recorded lease (store-owned state survives re-persist)", async () => {
  const { store, claim } = await makeStoreWithClaim();
  await store.recordAcceptedLease({ inboxId: claim.inboxId, issuedAtMs: 1000, expiresAtMs: 8000 });

  await store.persist(claim); // e.g. a re-acceptance path re-persisting the claim
  assert.deepEqual(store.leaseState(claim.inboxId),
    { issuedAtMs: 1000, expiresAtMs: 8000, retentionClass: "transient" });
});

test("M3: a malformed persisted lease is treated as ABSENT (fails toward renewal) while the claim itself survives", async () => {
  const { store, claim, storageProvider } = await makeStoreWithClaim();
  await store.recordAcceptedLease({ inboxId: claim.inboxId, issuedAtMs: 1000, expiresAtMs: 8000 });

  // Corrupt only the lease sub-record in storage.
  const raw = await storageProvider.kv.get("sdk:inbox:claims:v1");
  raw.claims[0].lease = { issuedAtMs: "soon", expiresAtMs: null, retentionClass: "standard" };
  storageProvider.kv.m.set("sdk:inbox:claims:v1", raw);

  const rehydrated = new InboxClaimStore({ storageProvider, cryptoProvider: CRYPTO });
  await rehydrated.hydrate();
  assert.equal(rehydrated.leaseState(claim.inboxId), null, "malformed lease derives as absent → renew");
  assert.ok(rehydrated.get(claim.inboxId), "the claim (irreplaceable keys) is intact");
});
