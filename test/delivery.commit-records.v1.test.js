import test from "node:test";
import assert from "node:assert/strict";
import {
  DeliveryCommitRecordV1,
  DecryptedDeliveryWorkV1,
  LifecycleEventIntentV1,
  PeerLinkEventIndexEntryV1,
  PeerLinkTransitionIntentV1,
  ReplayIdentityRecordV1,
  SessionCommitIntentV1,
} from "../src/delivery/index.js";
import { DeliveryCommitStore } from "../src/delivery/DeliveryCommitStore.js";

function fixture() {
  const owner = "rez:acct:test-owner";
  const sealedDigest = "ab".repeat(32);
  const nextSessionRecord = {
    sessionId: "pls_test",
    peerLinkId: "pl_test",
    localAccountId: owner,
    peerAccountId: "rez:acct:peer",
    status: "active",
    ratchetSnapshot: { marker: "next" },
    version: 2,
  };
  const nextPeerLinkRecord = {
    peerLinkId: "pl_test",
    localAccountId: owner,
    peerAccountId: "rez:acct:peer",
    state: "session_established",
    version: 4,
  };
  const indexEntry = new PeerLinkEventIndexEntryV1({
    ownerAccountId: owner,
    peerLinkId: "pl_test",
    eventId: "pev_test",
    atMs: 100,
    seq: 3,
  });
  return new DeliveryCommitRecordV1({
    owner,
    sealedDigest,
    runtimeEpoch: 7,
    laneId: "ratchet:pls_test",
    commitGeneration: 2,
    sessionIntent: new SessionCommitIntentV1({
      recordKey: "peer-link:sessions:" + owner + "::pls_test",
      indexKey: "peer-link:sessions:by-peer-link:" + owner + "::pl_test",
      indexValue: "pls_test",
      expectedSessionVersion: 1,
      nextSessionVersion: 2,
      nextSnapshotDigest: DeliveryCommitStore.canonicalDigest(nextSessionRecord),
      nextSessionRecord,
    }),
    peerLinkIntent: new PeerLinkTransitionIntentV1({
      peerLinkId: "pl_test",
      recordKey: "peer-link:records:" + owner + "::pl_test",
      pairIndexKey: "peer-link:pairs:" + owner + "::rez:acct:peer",
      pairIndexValue: "pl_test",
      expectedPeerLinkVersion: 3,
      nextPeerLinkVersion: 4,
      nextPeerLinkDigest: DeliveryCommitStore.canonicalDigest(nextPeerLinkRecord),
      nextPeerLinkRecord,
    }),
    lifecycleEventIntent: new LifecycleEventIntentV1({
      eventId: "pev_test",
      recordKey: "peer-link:events:" + owner + "::pev_test",
      entryKey: "peer-link:events-index:" + owner + "::pl_test::pev_test",
      eventRecord: {
        eventId: "pev_test",
        ownerAccountId: owner,
        peerLinkId: "pl_test",
        type: "session_established",
        atMs: 100,
      },
      indexEntry,
    }),
    work: new DecryptedDeliveryWorkV1({
      owner,
      sealedDigest,
      laneId: "ratchet:pls_test",
      sessionId: "pls_test",
      peerLinkId: "pl_test",
      authenticatedSenderAccountId: "rez:acct:peer",
      authenticatedSenderDeviceId: null,
      plaintextB64: "aGVsbG8=",
      createdAtMs: 100,
    }),
    replayState: "ready-to-apply",
    createdAtMs: 100,
  });
}

test("DeliveryCommitRecordV1 owns and round-trips every nested intent", () => {
  const record = fixture();
  const decoded = DeliveryCommitRecordV1.fromBytes(record.toBytes());
  assert.deepEqual(decoded.toJSON(), record.toJSON());
  assert.ok(decoded.sessionIntent instanceof SessionCommitIntentV1);
  assert.ok(decoded.peerLinkIntent instanceof PeerLinkTransitionIntentV1);
  assert.ok(decoded.lifecycleEventIntent instanceof LifecycleEventIntentV1);
  assert.ok(decoded.lifecycleEventIntent.indexEntry instanceof PeerLinkEventIndexEntryV1);
  assert.ok(decoded.work instanceof DecryptedDeliveryWorkV1);
});

test("delivery commit records fail closed on version, digest, and nested-shape drift", () => {
  const raw = JSON.parse(JSON.stringify(fixture()));
  assert.throws(() => new DeliveryCommitRecordV1({ ...raw, recordVersion: 2 }), /recordVersion/);
  assert.throws(() => new DeliveryCommitRecordV1({ ...raw, sealedDigest: "bad" }), /sealedDigest/);
  assert.throws(() => new DeliveryCommitRecordV1({ ...raw, extra: true }), /unknown field/);
  assert.throws(() => new SessionCommitIntentV1({ ...raw.sessionIntent, nextSessionVersion: 9 }), /expectedSessionVersion/);
  assert.throws(() => new SessionCommitIntentV1({
    ...raw.sessionIntent,
    nextSessionRecord: { ...raw.sessionIntent.nextSessionRecord, status: "attacker-mutated" },
  }), /authenticate nextSessionRecord/);
  assert.throws(() => new PeerLinkTransitionIntentV1({
    ...raw.peerLinkIntent,
    nextPeerLinkRecord: { ...raw.peerLinkIntent.nextPeerLinkRecord, state: "attacker-mutated" },
  }), /authenticate nextPeerLinkRecord/);
  assert.throws(() => new DeliveryCommitRecordV1({
    ...raw,
    sessionIntent: { ...raw.sessionIntent, recordKey: "app:chat:attacker-controlled" },
  }), /recordKey is not canonical/);
  assert.throws(() => new DeliveryCommitRecordV1({
    ...raw,
    work: { ...raw.work, authenticatedSenderAccountId: "rez:acct:other" },
  }), /authenticated sender/);
});

test("ReplayIdentityRecordV1 accepts only the frozen replay states", () => {
  const row = new ReplayIdentityRecordV1({
    owner: "rez:acct:test-owner",
    sealedDigest: "cd".repeat(32),
    state: "ready-to-apply",
    workKey: "sdk:delivery:work:v1:key",
    createdAtMs: 1,
    updatedAtMs: 1,
  });
  assert.equal(row.state, "ready-to-apply");
  assert.throws(() => new ReplayIdentityRecordV1({ ...row.toJSON(), state: "settled" }), /unsupported/);
});
