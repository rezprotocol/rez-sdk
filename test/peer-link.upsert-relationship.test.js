import test from "node:test";
import assert from "node:assert/strict";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService } from "../src/peer-link/PeerLinkService.js";
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

// Both host KV absence encodings exist in production: IndexedDB-backed
// stores return `undefined` for a missing key; the mobile host contract
// (SQLite-shaped, P1.1) returns `null`. The storage must behave identically
// over both (P1.3b: the null encoding made `create` see every empty slot as
// "already exists" and wedged the activation baseline apply).
function makeStorageProvider({ missingReadsAs = undefined } = {}) {
  const m = new Map();
  const kv = {
    async get(k) { return m.has(k) ? m.get(k) : missingReadsAs; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { return m.delete(k); },
    async keys(prefix) { const out = []; for (const k of m.keys()) if (!prefix || k.startsWith(prefix)) out.push(k); return out; },
  };
  const peerLinkStorage = createKeyValueBackedPeerLinkStorage({ keyValueStore: kv });
  return { getPeerLinkStorage() { return peerLinkStorage; }, getKeyValueStore() { return kv; }, peerLinkStorage };
}

function makeService(sp) {
  return new PeerLinkService({
    storageProvider: sp,
    ownerAccountId: "rez:acct:alice",
    cryptoProvider: new BrowserCryptoProvider(),
    // upsertPeerRelationship does pure storage work (no signing) — a stub authority
    // is enough to satisfy the constructor.
    getInviteAuthority: () => ({ sign: async () => new Uint8Array(64), verify: async () => true }),
    clock: () => 1000,
  });
}

const REL = {
  peerAccountId: "rez:acct:carol",
  peerLinkId: "pl_carol",
  peerInboxId: "inbox:carol",
  remoteAccountIdentityPublicKeyB64: "carolBpub",
  remoteIdentityDhPublicKeyB64: "carolDHpub",
};

test("upsertPeerRelationship creates a session-LESS peer-link record resolvable by getByPair", async () => {
  const sp = makeStorageProvider();
  const svc = makeService(sp);
  await svc.upsertPeerRelationship(REL);

  const rec = await sp.peerLinkStorage.peerLinks.getByPair("rez:acct:alice", "rez:acct:carol");
  assert.ok(rec, "getByPair resolves the replicated relationship");
  assert.equal(rec.peerLinkId, "pl_carol", "keeps the sibling's peerLinkId (so thread ids match)");
  assert.equal(rec.remoteAccountIdentityPublicKeyB64, "carolBpub");
  assert.equal(rec.remoteIdentityDhPublicKeyB64, "carolDHpub");
  assert.equal(rec.peerInboxId, "inbox:carol");
  assert.equal(rec.activeSessionId, null, "no legacy session — this device runs its own device sessions");
  assert.equal(rec.relationshipReplicated, true, "provenance marker");
  // AF3/F1 coupling: this exact shape (state session_established + no activeSessionId)
  // is the `sessionlessEstablished` trigger in acceptInvite, so a later explicit
  // invite accept RE-DRIVES a real handshake instead of short-circuiting as idempotent.
  assert.equal(rec.state, "session_established");
  assert.equal(Boolean(rec.activeSessionId), false, "sessionless ⇒ acceptInvite reattempt");
});

test("upsertPeerRelationship is idempotent + non-destructive: an existing link is left untouched", async () => {
  const sp = makeStorageProvider();
  const svc = makeService(sp);
  // Pretend this device already established a REAL session-bearing link.
  await sp.peerLinkStorage.peerLinks.create({
    peerLinkId: "pl_real",
    localAccountId: "rez:acct:alice",
    peerAccountId: "rez:acct:carol",
    remoteIdentityDhPublicKeyB64: "realDH",
    remoteAccountIdentityPublicKeyB64: "realB",
    state: "session_established",
    activeSessionId: "sess_real",
    peerInboxId: "inbox:real",
    version: 1,
  });

  const returned = await svc.upsertPeerRelationship(REL);
  assert.equal(returned.peerLinkId, "pl_real", "returns the existing link, not a new one");
  const rec = await sp.peerLinkStorage.peerLinks.getByPair("rez:acct:alice", "rez:acct:carol");
  assert.equal(rec.activeSessionId, "sess_real", "the real session record was NOT clobbered");
  assert.equal(rec.peerLinkId, "pl_real");
});

test("upsertPeerRelationship fails loud on missing identity/routing fields", async () => {
  const svc = makeService(makeStorageProvider());
  await assert.rejects(() => svc.upsertPeerRelationship({ peerAccountId: "rez:acct:carol", peerLinkId: "pl_x" }));
  await assert.rejects(() => svc.upsertPeerRelationship({ ...REL, remoteIdentityDhPublicKeyB64: "" }));
});

test("P1.3b: a null-for-missing host KV behaves identically — an empty store NEVER reports 'already exists', and updates still conflict correctly", async () => {
  const sp = makeStorageProvider({ missingReadsAs: null });
  const svc = makeService(sp);

  // The defect this pins: on a null-returning store, create's existence check
  // saw `null !== undefined` and refused the very first write.
  await svc.upsertPeerRelationship(REL);
  const rec = await sp.peerLinkStorage.peerLinks.getByPair("rez:acct:alice", "rez:acct:carol");
  assert.ok(rec, "the first create on an empty null-encoding store succeeds");
  assert.equal(rec.peerLinkId, "pl_carol");

  // Idempotence still holds (getByPair resolves through the same seam).
  const again = await svc.upsertPeerRelationship({ ...REL, peerInboxId: "inbox:evil" });
  assert.equal(again.peerInboxId, "inbox:carol", "existing link untouched");

  // Real duplicates are still refused: a DIFFERENT link id for the same pair.
  await assert.rejects(
    () => sp.peerLinkStorage.peerLinks.create({
      peerLinkId: "pl_other",
      localAccountId: "rez:acct:alice",
      peerAccountId: "rez:acct:carol",
      state: "session_established",
      version: 1,
    }),
    /already exists for pair/,
  );

  // update() on a missing record must still say NOT FOUND (under the null
  // encoding the unfixed check would have proceeded to update a phantom).
  await assert.rejects(
    () => sp.peerLinkStorage.peerLinks.update({
      peerLinkId: "pl_ghost",
      localAccountId: "rez:acct:alice",
      peerAccountId: "rez:acct:carol",
      version: 1,
    }, 1),
    /not found/,
  );
});
