import test from "node:test";
import assert from "node:assert/strict";
import {
  DeliveryCommitFatalError,
  DeliveryCommitRecordV1,
  DeliveryCommitStore,
  DecryptedDeliveryWorkV1,
  LifecycleEventIntentV1,
  PeerLinkEventIndexEntryV1,
  PeerLinkTransitionIntentV1,
  SessionCommitIntentV1,
} from "../src/delivery/index.js";

class MemoryKv {
  constructor() { this.rows = new Map(); }
  async set(key, value) { this.rows.set(key, JSON.parse(JSON.stringify(value))); }
  async getStrict(key) {
    const value = this.rows.get(key);
    return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
  }
  async delete(key) { return this.rows.delete(key); }
  async keys(prefix = "") { return [...this.rows.keys()].filter((key) => key.startsWith(prefix)).sort(); }
}

const OWNER = "rez:acct:commit-owner";
const PEER = "rez:acct:commit-peer";
const DIGEST = "12".repeat(32);

function buildFixture() {
  const sessionBefore = {
    sessionId: "pls_commit",
    peerLinkId: "pl_commit",
    localAccountId: OWNER,
    peerAccountId: PEER,
    status: "pending_remote_confirm",
    ratchetSnapshot: { step: 1 },
    version: 4,
  };
  const sessionAfter = { ...sessionBefore, status: "active", ratchetSnapshot: { step: 2 }, version: 5 };
  const peerBefore = {
    peerLinkId: "pl_commit",
    localAccountId: OWNER,
    peerAccountId: PEER,
    state: "accepted",
    version: 8,
  };
  const peerAfter = { ...peerBefore, state: "session_established", activeSessionId: "pls_commit", version: 9 };
  const sessionKey = "peer-link:sessions:" + OWNER + "::pls_commit";
  const sessionIndexKey = "peer-link:sessions:by-peer-link:" + OWNER + "::pl_commit";
  const peerKey = "peer-link:records:" + OWNER + "::pl_commit";
  const pairKey = "peer-link:pairs:" + OWNER + "::" + PEER;
  const eventKey = "peer-link:events:" + OWNER + "::pev_commit";
  const eventEntryKey = "peer-link:events-index:" + OWNER + "::pl_commit::pev_commit";
  const eventRecord = { eventId: "pev_commit", ownerAccountId: OWNER, peerLinkId: "pl_commit", type: "session_established", atMs: 50 };
  const indexEntry = new PeerLinkEventIndexEntryV1({ ownerAccountId: OWNER, peerLinkId: "pl_commit", eventId: "pev_commit", atMs: 50, seq: 2 });
  const work = new DecryptedDeliveryWorkV1({
    owner: OWNER,
    sealedDigest: DIGEST,
    laneId: "ratchet:pls_commit",
    sessionId: "pls_commit",
    peerLinkId: "pl_commit",
    authenticatedSenderAccountId: PEER,
    authenticatedSenderDeviceId: null,
    plaintextB64: "eyJraW5kIjoibWVzc2FnZSJ9",
    createdAtMs: 50,
  });
  const commit = new DeliveryCommitRecordV1({
    owner: OWNER,
    sealedDigest: DIGEST,
    runtimeEpoch: 3,
    laneId: "ratchet:pls_commit",
    commitGeneration: 5,
    sessionIntent: new SessionCommitIntentV1({
      recordKey: sessionKey,
      indexKey: sessionIndexKey,
      indexValue: "pls_commit",
      expectedSessionVersion: 4,
      nextSessionVersion: 5,
      nextSnapshotDigest: DeliveryCommitStore.canonicalDigest(sessionAfter),
      nextSessionRecord: sessionAfter,
    }),
    peerLinkIntent: new PeerLinkTransitionIntentV1({
      peerLinkId: "pl_commit",
      recordKey: peerKey,
      pairIndexKey: pairKey,
      pairIndexValue: "pl_commit",
      expectedPeerLinkVersion: 8,
      nextPeerLinkVersion: 9,
      nextPeerLinkDigest: DeliveryCommitStore.canonicalDigest(peerAfter),
      nextPeerLinkRecord: peerAfter,
    }),
    lifecycleEventIntent: new LifecycleEventIntentV1({
      eventId: "pev_commit",
      recordKey: eventKey,
      entryKey: eventEntryKey,
      eventRecord,
      indexEntry,
    }),
    work,
    replayState: "ready-to-apply",
    createdAtMs: 50,
  });
  return { sessionBefore, sessionAfter, peerBefore, peerAfter, sessionKey, sessionIndexKey, peerKey, pairKey, eventKey, eventEntryKey, eventRecord, indexEntry, work, commit };
}

async function seedCanonical(kv, f) {
  await kv.set(f.sessionKey, f.sessionBefore);
  await kv.set(f.sessionIndexKey, "pls_commit");
  await kv.set(f.peerKey, f.peerBefore);
  await kv.set(f.pairKey, "pl_commit");
}

test("commit point rolls every canonical key forward and leaves durable work", async () => {
  const kv = new MemoryKv();
  const f = buildFixture();
  await seedCanonical(kv, f);
  const store = new DeliveryCommitStore({ keyValueStore: kv, runtimeEpoch: 3, clock: () => 60 });
  const work = await store.commitAndRollForward(f.commit);
  assert.equal(work.sealedDigest, DIGEST);
  assert.deepEqual(await kv.getStrict(f.sessionKey), f.sessionAfter);
  assert.deepEqual(await kv.getStrict(f.peerKey), f.peerAfter);
  assert.deepEqual(await kv.getStrict(f.eventKey), f.eventRecord);
  assert.deepEqual(await kv.getStrict(f.eventEntryKey), f.indexEntry.toJSON());
  assert.equal(await kv.getStrict(DeliveryCommitStore.commitKey(OWNER, DIGEST)), undefined);
  const pending = await store.listPendingWork(OWNER);
  assert.equal(pending.length, 1);
  assert.equal(pending[0].sealedDigest, DIGEST);
});

test("recovery converges independently from every partial projection prefix", async () => {
  const f = buildFixture();
  const projections = [
    [f.sessionKey, f.sessionAfter],
    [f.sessionIndexKey, "pls_commit"],
    [f.peerKey, f.peerAfter],
    [f.pairKey, "pl_commit"],
    [f.eventKey, f.eventRecord],
    [f.eventEntryKey, f.indexEntry],
  ];
  for (let landed = 0; landed <= projections.length; landed += 1) {
    const kv = new MemoryKv();
    await seedCanonical(kv, f);
    await kv.set(DeliveryCommitStore.commitKey(OWNER, DIGEST), f.commit);
    for (let index = 0; index < landed; index += 1) {
      await kv.set(projections[index][0], projections[index][1]);
    }
    const recovered = new DeliveryCommitStore({ keyValueStore: kv, runtimeEpoch: 3 });
    assert.equal(await recovered.recoverOwner(OWNER), 1, "partial prefix " + landed);
    assert.deepEqual(await kv.getStrict(f.sessionKey), f.sessionAfter);
    assert.deepEqual(await kv.getStrict(f.peerKey), f.peerAfter);
    assert.equal((await recovered.listPendingWork(OWNER)).length, 1);
  }
});

test("duplicate ciphertext resolves to durable work without a second commit", async () => {
  const kv = new MemoryKv();
  const f = buildFixture();
  await seedCanonical(kv, f);
  const store = new DeliveryCommitStore({ keyValueStore: kv, runtimeEpoch: 3 });
  await store.commitAndRollForward(f.commit);
  const duplicate = await store.lookup(OWNER, DIGEST);
  assert.equal(duplicate.replay.state, "ready-to-apply");
  assert.equal(duplicate.work.plaintextB64, f.work.plaintextB64);
  await store.markApplied(OWNER, DIGEST);
  const applied = await store.lookup(OWNER, DIGEST);
  assert.equal(applied.replay.state, "applied");
  assert.equal(applied.work, null);
});

test("next-version digest mismatch quarantines only the known lane", async () => {
  const kv = new MemoryKv();
  const f = buildFixture();
  await seedCanonical(kv, f);
  await kv.set(f.sessionKey, { ...f.sessionAfter, ratchetSnapshot: { step: 999 } });
  await kv.set(DeliveryCommitStore.commitKey(OWNER, DIGEST), f.commit);
  const store = new DeliveryCommitStore({ keyValueStore: kv, runtimeEpoch: 3 });
  assert.equal(await store.recoverOwner(OWNER), 1);
  assert.throws(() => store.assertAvailable(OWNER, "ratchet:pls_commit"), /digest mismatch/);
  assert.doesNotThrow(() => store.assertAvailable(OWNER, "ratchet:other"));
});

test("misfiled readable WAL is store-fatal", async () => {
  const kv = new MemoryKv();
  const f = buildFixture();
  await seedCanonical(kv, f);
  const wrongKey = DeliveryCommitStore.commitKey(OWNER, "34".repeat(32));
  await kv.set(wrongKey, f.commit);
  const store = new DeliveryCommitStore({ keyValueStore: kv, runtimeEpoch: 3 });
  await assert.rejects(() => store.recoverOwner(OWNER), (err) => (
    err instanceof DeliveryCommitFatalError && err.scope === "store"
  ));
  assert.throws(() => store.assertAvailable(OWNER, "ratchet:other"), /key\/content mismatch/);
});

test("an unreadable WAL halts the known owner without guessing a lane", async () => {
  const kv = new MemoryKv();
  const f = buildFixture();
  await seedCanonical(kv, f);
  const commitKey = DeliveryCommitStore.commitKey(OWNER, DIGEST);
  await kv.set(commitKey, f.commit);
  const originalGetStrict = kv.getStrict.bind(kv);
  kv.getStrict = async (key) => {
    if (key === commitKey) throw new Error("injected unreadable WAL");
    return originalGetStrict(key);
  };
  const store = new DeliveryCommitStore({ keyValueStore: kv, runtimeEpoch: 3 });
  await assert.rejects(() => store.recoverOwner(OWNER), (err) => (
    err instanceof DeliveryCommitFatalError && err.scope === "owner" && err.laneId === null
  ));
  assert.throws(() => store.assertAvailable(OWNER, "ratchet:any"), /unreadable delivery commit record/);
  await assert.rejects(() => store.lookup(OWNER, DIGEST), /unreadable delivery commit record/);
  await assert.rejects(() => store.listPendingWork(OWNER), /unreadable delivery commit record/);
  await assert.rejects(() => store.markApplied(OWNER, DIGEST), /unreadable delivery commit record/);
  assert.doesNotThrow(() => store.assertAvailable("rez:acct:other", "ratchet:any"));
});

test("an enumerated WAL that disappears before strict read halts the owner", async () => {
  const kv = new MemoryKv();
  const f = buildFixture();
  await seedCanonical(kv, f);
  const commitKey = DeliveryCommitStore.commitKey(OWNER, DIGEST);
  await kv.set(commitKey, f.commit);
  const originalGetStrict = kv.getStrict.bind(kv);
  let enumerated = false;
  const originalKeys = kv.keys.bind(kv);
  kv.keys = async (prefix) => {
    const result = await originalKeys(prefix);
    enumerated = true;
    return result;
  };
  kv.getStrict = async (key) => {
    if (enumerated && key === commitKey) return undefined;
    return originalGetStrict(key);
  };
  const store = new DeliveryCommitStore({ keyValueStore: kv, runtimeEpoch: 3 });
  await assert.rejects(() => store.recoverOwner(OWNER), (err) => (
    err instanceof DeliveryCommitFatalError && err.scope === "owner"
  ));
  assert.throws(() => store.assertAvailable(OWNER, "ratchet:any"), /disappeared after enumeration/);
});

test("an unreadable canonical record quarantines its lane while independent lanes recover", async () => {
  const kv = new MemoryKv();
  const f = buildFixture();
  await seedCanonical(kv, f);
  await kv.set(DeliveryCommitStore.commitKey(OWNER, DIGEST), f.commit);
  const otherDigest = "56".repeat(32);
  const otherBefore = {
    sessionId: "pls_other",
    peerLinkId: "pl_other",
    localAccountId: OWNER,
    peerAccountId: PEER,
    status: "active",
    ratchetSnapshot: { step: 10 },
    version: 2,
  };
  const otherAfter = { ...otherBefore, ratchetSnapshot: { step: 11 }, version: 3 };
  const otherSessionKey = "peer-link:sessions:" + OWNER + "::pls_other";
  const otherIndexKey = "peer-link:sessions:by-peer-link:" + OWNER + "::pl_other";
  const otherWork = new DecryptedDeliveryWorkV1({
    owner: OWNER,
    sealedDigest: otherDigest,
    laneId: "ratchet:pls_other",
    sessionId: "pls_other",
    peerLinkId: "pl_other",
    authenticatedSenderAccountId: PEER,
    plaintextB64: "eyJraW5kIjoib3RoZXIifQ==",
    createdAtMs: 51,
  });
  const otherCommit = new DeliveryCommitRecordV1({
    owner: OWNER,
    sealedDigest: otherDigest,
    runtimeEpoch: 3,
    laneId: "ratchet:pls_other",
    commitGeneration: 1,
    sessionIntent: new SessionCommitIntentV1({
      recordKey: otherSessionKey,
      indexKey: otherIndexKey,
      indexValue: "pls_other",
      expectedSessionVersion: 2,
      nextSessionVersion: 3,
      nextSnapshotDigest: DeliveryCommitStore.canonicalDigest(otherAfter),
      nextSessionRecord: otherAfter,
    }),
    peerLinkIntent: null,
    lifecycleEventIntent: null,
    work: otherWork,
    replayState: "ready-to-apply",
    createdAtMs: 51,
  });
  await kv.set(otherSessionKey, otherBefore);
  await kv.set(otherIndexKey, "pls_other");
  await kv.set(DeliveryCommitStore.commitKey(OWNER, otherDigest), otherCommit);
  const originalGetStrict = kv.getStrict.bind(kv);
  kv.getStrict = async (key) => {
    if (key === f.sessionKey) throw new Error("injected unreadable session");
    return originalGetStrict(key);
  };
  const store = new DeliveryCommitStore({ keyValueStore: kv, runtimeEpoch: 3 });
  assert.equal(await store.recoverOwner(OWNER), 2);
  assert.throws(() => store.assertAvailable(OWNER, "ratchet:pls_commit"), /unreadable key/);
  assert.doesNotThrow(() => store.assertAvailable(OWNER, "ratchet:other"));
  assert.deepEqual(await kv.getStrict(otherSessionKey), otherAfter);
  assert.equal(await kv.getStrict(DeliveryCommitStore.commitKey(OWNER, otherDigest)), undefined);
  assert.notEqual(await originalGetStrict(DeliveryCommitStore.commitKey(OWNER, DIGEST)), undefined,
    "the quarantined lane keeps its WAL for operator recovery");
});

test("commit key uses fixed 43-character digests and stays below the filesystem hashing threshold", () => {
  const key = DeliveryCommitStore.commitKey(OWNER, DIGEST);
  const suffix = key.slice("sdk:delivery:commit:v1:".length).split(":");
  assert.equal(suffix.length, 2);
  assert.equal(suffix[0].length, 43);
  assert.equal(suffix[1].length, 43);
  assert.ok(new TextEncoder().encode(key).length < 150);
});

test("applied replay retention preserves pending work and WAL, and rejects stale new commits", async () => {
  const kv = new MemoryKv();
  const f = buildFixture();
  await seedCanonical(kv, f);
  const store = new DeliveryCommitStore({ keyValueStore: kv, runtimeEpoch: 3, clock: () => 60 });
  await store.commitAndRollForward(f.commit);
  assert.equal(await store.pruneAppliedReplay(OWNER, { maxRecords: 0 }), 0);
  assert.equal((await store.lookup(OWNER, DIGEST)).work.plaintextB64, f.work.plaintextB64);
  await store.markApplied(OWNER, DIGEST);
  const wal = DeliveryCommitStore.commitKey(OWNER, DIGEST);
  await kv.set(wal, f.commit.toJSON());
  assert.equal(await store.pruneAppliedReplay(OWNER, { maxRecords: 0 }), 0, "WAL still needs applied identity");
  await kv.delete(wal);
  assert.equal(await store.pruneAppliedReplay(OWNER, { maxRecords: 0 }), 1);
  assert.equal(await store.lookup(OWNER, DIGEST), null);
  await assert.rejects(store.commitAndRollForward(f.commit), /does not extend/);
  assert.equal(await kv.getStrict(DeliveryCommitStore.workKey(OWNER, DIGEST)), undefined);
});

test("released ownership rejects even a record bearing its own cached epoch", async () => {
  const kv = new MemoryKv(); const f = buildFixture(); await seedCanonical(kv,f);
  const store = new DeliveryCommitStore({ keyValueStore: kv });
  let active = true;
  store.activateRuntimeEpoch(3, () => { if (!active) throw new Error("released"); });
  active = false;
  await assert.rejects(store.commitAndRollForward(f.commit), /durable/);
  assert.equal(await kv.getStrict(DeliveryCommitStore.commitKey(OWNER,DIGEST)), undefined);
});

test("applied replay markers expire by age while recent markers survive", async () => {
  const kv = new MemoryKv(); const f = buildFixture(); await seedCanonical(kv, f);
  const store = new DeliveryCommitStore({ keyValueStore: kv, runtimeEpoch: 3, clock: () => 60 });
  await store.commitAndRollForward(f.commit);
  await store.markApplied(OWNER, DIGEST);
  assert.equal(await store.pruneAppliedReplay(OWNER, { nowMs: 65, retentionMs: 10 }), 0);
  assert.equal(await store.pruneAppliedReplay(OWNER, { nowMs: 71, retentionMs: 10 }), 1);
  assert.deepEqual(await store.listPendingWork(OWNER), []);
});
