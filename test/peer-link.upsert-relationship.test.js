import test from "node:test";
import assert from "node:assert/strict";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService } from "../src/peer-link/PeerLinkService.js";
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

function makeStorageProvider() {
  const m = new Map();
  const kv = {
    async get(k) { return m.has(k) ? m.get(k) : undefined; },
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
