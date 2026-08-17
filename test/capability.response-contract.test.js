import test from "node:test";
import assert from "node:assert/strict";

import { MailboxCapability } from "../src/capabilities/MailboxCapability.js";
import { DurableRecordsCapability } from "../src/capabilities/DurableRecordsCapability.js";
import { NodeCapability } from "../src/capabilities/NodeCapability.js";
import { RezClient } from "../src/client/RezClient.js";

// Response-contract gate, leaf 3 (Mailbox / DurableRecords / Node / sendPayload). Each required
// field list is pinned against the NODE handler that produces it, so these tests double as the
// record of what the node actually promises. The shared rule: contract drift throws, while a
// legitimately empty / null / false answer still passes.

function poolReturning(body) {
  return { async sendRequest() { return { body }; } };
}

const MAILBOX = "inbox:" + "a".repeat(24);
const EVENT = "evt-1";

test("mailbox.deposit accepts a delivered AND a queued response, rejects drift", async () => {
  // MailboxHandler.handleDeposit: { mailboxId, eventId } when delivered, and
  // { mailboxId, eventId: "", queued: true } when persisted to the outbound queue instead.
  const delivered = new MailboxCapability({ pool: poolReturning({ mailboxId: MAILBOX, eventId: EVENT }) });
  assert.deepEqual(await delivered.deposit({ mailboxId: MAILBOX }), { mailboxId: MAILBOX, eventId: EVENT });

  const queued = new MailboxCapability({ pool: poolReturning({ mailboxId: MAILBOX, eventId: "", queued: true }) });
  const res = await queued.deposit({ mailboxId: MAILBOX });
  assert.equal(res.queued, true, "the queued branch carries an EMPTY eventId, which is a real answer");
  assert.equal(res.eventId, "");

  const drifted = new MailboxCapability({ pool: poolReturning({}) });
  await assert.rejects(
    () => drifted.deposit({ mailboxId: MAILBOX }),
    /MailboxCapability\.deposit: response is missing the required 'mailboxId' non-empty string/,
  );
});

test("mailbox.list THROWS on a missing items array — drift must not read as an empty mailbox", async () => {
  const drifted = new MailboxCapability({ pool: poolReturning({ mailboxId: MAILBOX }) });
  await assert.rejects(() => drifted.list({ mailboxId: MAILBOX }), /missing the required 'items' array/);

  // A genuinely empty page is still a real answer.
  const empty = new MailboxCapability({ pool: poolReturning({ mailboxId: MAILBOX, items: [], nextCursor: null }) });
  assert.deepEqual(await empty.list({ mailboxId: MAILBOX }), { items: [], nextCursor: null });

  const page = new MailboxCapability({ pool: poolReturning({ mailboxId: MAILBOX, items: [{ eventId: EVENT }], nextCursor: "c2" }) });
  const res = await page.list({ mailboxId: MAILBOX });
  assert.equal(res.items.length, 1);
  assert.equal(res.nextCursor, "c2");
});

test("mailbox.fetch: a NOT-FOUND body passes (ciphertextB64 null), a malformed one throws", async () => {
  // The node answers an unknown eventId with a COMPLETE body whose payload fields are null — so
  // not-found and drift were previously indistinguishable to the caller.
  const notFound = new MailboxCapability({
    pool: poolReturning({ mailboxId: MAILBOX, eventId: EVENT, objectId: null, ciphertextB64: null, metadata: {}, createdAtMs: null }),
  });
  const res = await notFound.fetch({ mailboxId: MAILBOX, eventId: EVENT });
  assert.equal(res.ciphertextB64, null, "not-found is a real answer the caller reads as no ciphertext");

  const drifted = new MailboxCapability({ pool: poolReturning({ mailboxId: MAILBOX }) });
  await assert.rejects(() => drifted.fetch({ mailboxId: MAILBOX, eventId: EVENT }), /missing the required 'eventId' non-empty string/);
});

test("mailbox.ack and cursorAck require the fields that prove what happened", async () => {
  const acked = new MailboxCapability({ pool: poolReturning({ mailboxId: MAILBOX, eventId: EVENT, removed: true }) });
  assert.equal((await acked.ack({ mailboxId: MAILBOX, eventId: EVENT })).removed, true);

  // removed:false — the event was already gone — is an answer, not an absence.
  const alreadyGone = new MailboxCapability({ pool: poolReturning({ mailboxId: MAILBOX, eventId: EVENT, removed: false }) });
  assert.equal((await alreadyGone.ack({ mailboxId: MAILBOX, eventId: EVENT })).removed, false);

  const noRemoved = new MailboxCapability({ pool: poolReturning({ mailboxId: MAILBOX, eventId: EVENT }) });
  await assert.rejects(() => noRemoved.ack({ mailboxId: MAILBOX, eventId: EVENT }), /missing the required 'removed' boolean/);

  const cursor = new MailboxCapability({ pool: poolReturning({ mailboxId: MAILBOX, deviceId: "rez:dev:x", lastSeq: 0 }) });
  assert.equal((await cursor.cursorAck({ mailboxId: MAILBOX, throughSeq: 0 })).lastSeq, 0, "seq 0 is a real watermark");

  const noSeq = new MailboxCapability({ pool: poolReturning({ mailboxId: MAILBOX, deviceId: "rez:dev:x" }) });
  await assert.rejects(() => noSeq.cursorAck({ mailboxId: MAILBOX, throughSeq: 1 }), /missing the required 'lastSeq' integer/);
});

test("records.put THROWS on drift — a response at all means STORED, so {} read as a phantom success", async () => {
  const stored = new DurableRecordsCapability({ pool: poolReturning({ localId: "loc-1", replicas: 3 }) });
  assert.deepEqual(await stored.put({ record: { v: 2 } }), { localId: "loc-1", replicas: 3 });

  // Zero replicas (stored locally, no peers reachable) is a real answer.
  const noReplicas = new DurableRecordsCapability({ pool: poolReturning({ localId: "loc-1", replicas: 0 }) });
  assert.equal((await noReplicas.put({ record: { v: 2 } })).replicas, 0);

  const drifted = new DurableRecordsCapability({ pool: poolReturning({}) });
  await assert.rejects(() => drifted.put({ record: { v: 2 } }), /missing the required 'localId' non-empty string/);
});

test("records.get separates a real not-found (record: null) from a malformed response", async () => {
  const found = new DurableRecordsCapability({ pool: poolReturning({ record: { recordKind: "k" } }) });
  assert.deepEqual(await found.get({ recordKind: "k", recordId: "r", publisherPublicKeyB64: "p" }), { recordKind: "k" });

  const missing = new DurableRecordsCapability({ pool: poolReturning({ record: null }) });
  assert.equal(await missing.get({ recordKind: "k", recordId: "r", publisherPublicKeyB64: "p" }), null, "not-found stays null");

  // The KEY is absent — that is drift, not an answer.
  const drifted = new DurableRecordsCapability({ pool: poolReturning({}) });
  await assert.rejects(
    () => drifted.get({ recordKind: "k", recordId: "r", publisherPublicKeyB64: "p" }),
    /missing the required 'record' object or null/,
  );
});

test("node.status accepts a mesh-less node (mesh: null) but requires the envelope", async () => {
  const meshless = new NodeCapability({ pool: poolReturning({ node: { nodeKeyId: "k" }, mesh: null, peers: [] }) });
  const res = await meshless.status();
  assert.equal(res.mesh, null, "meshing off is an answer");
  assert.deepEqual(res.peers, []);

  const drifted = new NodeCapability({ pool: poolReturning({ node: { nodeKeyId: "k" }, mesh: null }) });
  await assert.rejects(() => drifted.status(), /NodeCapability\.status: response is missing the required 'peers' array/);
});

test("RezClient.sendPayload THROWS on drift instead of reporting a delivery it cannot confirm", async () => {
  function clientWith(body) {
    return new RezClient({
      pool: { authState: "authenticated", async sendRequest() { return { body }; } },
      eventBus: { on: () => () => {}, emit: () => {} },
      authMachine: {},
      identity: { accountId: "rez:acct:test", publicKeyB64: "p", privateKeyB64: "s" },
    });
  }
  // preSealed: sendPayload encrypts nothing — the caller states that the bytes
  // are already sealed (SDK-4). Required, so this frozen path cannot be used
  // by someone who assumed otherwise.
  const args = { peerAccountId: "rez:acct:peer", payloadBytes: [1, 2, 3], deliverInboxId: MAILBOX, preSealed: true };

  const ok = await clientWith({ mailboxId: MAILBOX, eventId: EVENT }).sendPayload(args);
  assert.equal(ok.eventId, EVENT);
  assert.equal(ok.mailboxId, MAILBOX);

  // The queued branch: an empty eventId is normalized to null by the documented `||` default.
  const queued = await clientWith({ mailboxId: MAILBOX, eventId: "", queued: true }).sendPayload(args);
  assert.equal(queued.eventId, null);

  await assert.rejects(() => clientWith({}).sendPayload(args), /RezClient\.sendPayload: response is missing the required 'mailboxId' non-empty string/);
});
