import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  REZ_CONTRACT_TYPES,
  buildInboxAddress,
  buildRendezvousAddress,
  buildDurableRecordV1,
} from "@rezprotocol/core";
import { MailboxCapability } from "../src/capabilities/MailboxCapability.js";
import { DurableRecordsCapability } from "../src/capabilities/DurableRecordsCapability.js";
import { MeshCapability } from "../src/capabilities/MeshCapability.js";
import { bytesToBase64 } from "../src/util/bytes.js";

const T = REZ_CONTRACT_TYPES;
const PUB = "MCowBQYDK2VwAyEA2crNvu+ZeiFMoMNP/imhLa/HIyYg6x96US6AyOqijPg=";

// Capturing pool: records every wire request and returns a canned response
// shaped per wire type. Only the socket is faked — the real Mailbox/
// DurableRecords capabilities build the actual wire body.
function capturingPool() {
  const calls = [];
  return {
    calls,
    async sendRequest(args) {
      calls.push(args);
      if (args.type === T.MAILBOX_DEPOSIT) {
        return { body: { mailboxId: args.body.mailboxId, eventId: "evt_1", queued: false } };
      }
      if (args.type === T.RECORD_PUT) {
        return { body: { localId: "lid_1", replicas: 3 } };
      }
      return { body: {} };
    },
  };
}

function buildMesh() {
  const pool = capturingPool();
  const mailbox = new MailboxCapability({ pool });
  const durableRecords = new DurableRecordsCapability({ pool });
  const mesh = new MeshCapability({ pool, mailbox, durableRecords });
  return { pool, mesh };
}

function signedRecord({ recordId = "plinv_1" } = {}) {
  const record = buildDurableRecordV1({
    recordKind: "peerlink-invite", recordId, publisherPublicKeyB64: PUB,
    payloadB64: "AAA", issuedAtMs: 1, expiresAtMs: 2,
  });
  record.sigB64 = "sig";
  return record;
}

describe("mesh.dispatch — routes by address kind through the real capabilities", () => {
  it("inbox address → one MAILBOX_DEPOSIT carrying the opaque bytes", async () => {
    const { pool, mesh } = buildMesh();
    const payloadBytes = new Uint8Array([1, 2, 3, 4]);
    const res = await mesh.dispatch(
      { payloadBytes, objectId: "obj_x" },
      buildInboxAddress({ inboxId: "inbox_abc" }),
    );

    assert.equal(pool.calls.length, 1);
    const call = pool.calls[0];
    assert.equal(call.type, T.MAILBOX_DEPOSIT);
    assert.equal(call.body.mailboxId, "inbox_abc");
    assert.equal(call.body.objectId, "obj_x");
    assert.equal(call.body.ciphertextB64, bytesToBase64(payloadBytes));
    assert.equal(res.eventId, "evt_1");
  });

  it("generates an objectId when the caller omits one", async () => {
    const { pool, mesh } = buildMesh();
    await mesh.dispatch({ payloadBytes: new Uint8Array([9]) }, buildInboxAddress({ inboxId: "inbox_abc" }));
    assert.match(pool.calls[0].body.objectId, /^obj_/);
  });

  it("rendezvous address → one RECORD_PUT carrying the signed record", async () => {
    const { pool, mesh } = buildMesh();
    const record = signedRecord();
    const res = await mesh.dispatch(
      { record },
      buildRendezvousAddress({ recordKind: "peerlink-invite", recordId: "plinv_1", publisherPublicKeyB64: PUB }),
    );

    assert.equal(pool.calls.length, 1);
    assert.equal(pool.calls[0].type, T.RECORD_PUT);
    assert.equal(pool.calls[0].body.record.recordId, "plinv_1");
    assert.equal(res.replicas, 3);
  });
});

describe("mesh.dispatch — aggressive validation before any transport", () => {
  it("throws on an invalid address and issues NO wire call", async () => {
    const { pool, mesh } = buildMesh();
    await assert.rejects(
      () => mesh.dispatch({ payloadBytes: new Uint8Array([1]) }, { kind: "bogus" }),
      /inbox.*rendezvous/,
    );
    await assert.rejects(
      () => mesh.dispatch({ payloadBytes: new Uint8Array([1]) }, null),
      /must be an object/,
    );
    assert.equal(pool.calls.length, 0);
  });

  it("inbox: throws when payloadBytes is missing or not bytes", async () => {
    const { pool, mesh } = buildMesh();
    await assert.rejects(() => mesh.dispatch({}, buildInboxAddress({ inboxId: "i" })), /payloadBytes/);
    await assert.rejects(() => mesh.dispatch({ payloadBytes: "nope" }, buildInboxAddress({ inboxId: "i" })), /payloadBytes/);
    assert.equal(pool.calls.length, 0);
  });

  it("rendezvous: rejects a record whose coordinate disagrees with the address", async () => {
    const { pool, mesh } = buildMesh();
    await assert.rejects(
      () => mesh.dispatch(
        { record: signedRecord({ recordId: "plinv_1" }) },
        buildRendezvousAddress({ recordKind: "peerlink-invite", recordId: "DIFFERENT", publisherPublicKeyB64: PUB }),
      ),
      /coordinate does not match/,
    );
    assert.equal(pool.calls.length, 0);
  });

  it("rendezvous: throws when the record is missing", async () => {
    const { mesh } = buildMesh();
    await assert.rejects(
      () => mesh.dispatch({}, buildRendezvousAddress({ recordKind: "k", recordId: "x", publisherPublicKeyB64: PUB })),
      /requires object.record/,
    );
  });
});
