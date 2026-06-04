import test from "node:test";
import assert from "node:assert/strict";
import { MESH_ADDRESS_KINDS } from "@rezprotocol/core";
import { RezClient } from "../src/client/RezClient.js";
import { TypedEventBus } from "../src/events/TypedEventBus.js";
import { AuthStateMachine } from "../src/auth/AuthStateMachine.js";
import { MetricsCollector } from "../src/observability/MetricsCollector.js";

// sealForPeer is the "build the object" step: it encrypts + resolves the peer's
// inbox into a protocol address + attaches the post-cap, and NEVER touches a
// transport. These tests pin that contract so chat services can rely on the
// returned { ciphertextBytes, inboxAddress, capChain, metadata } and hand it
// straight to mesh.dispatch.

const STUB_IDENTITY = {
  accountId: "rez:acct:test",
  deviceId: "dev:1",
  publicKeyB64: "cHVibGljLWtleQ==",
  privateKeyB64: "cHJpdmF0ZS1rZXk=",
};

function makeFakePool() {
  const sent = [];
  return {
    sent,
    sendRequest: async (request) => {
      sent.push(request);
      return { body: { mailboxId: request.body.mailboxId, eventId: "evt_x" } };
    },
    on() { return () => {}; },
    getActiveUplink() { return null; },
    getUplinkStates() { return []; },
    getSessionInfo() { return null; },
  };
}

function makeClient({ pool, peerLinkService }) {
  return new RezClient({
    pool,
    eventBus: new TypedEventBus(),
    authMachine: new AuthStateMachine({ identity: STUB_IDENTITY, eventBus: new TypedEventBus() }),
    metrics: new MetricsCollector(),
    identity: STUB_IDENTITY,
    peerLinkService,
  });
}

test("sealForPeer returns an inbox(inboxId) address and ciphertext WITHOUT touching the transport", async () => {
  const pool = makeFakePool();
  const peerLinkService = {
    encryptDirectMessage: async () => ({ encryptedPacket: { toBytes: () => new Uint8Array([0xDE, 0xAD]) } }),
  };
  const client = makeClient({ pool, peerLinkService });

  const sealed = await client.sealForPeer({
    peerAccountId: "rez:acct:peer",
    plaintextBodyBytes: new Uint8Array([1, 2, 3]),
    deliverInboxId: "inbox:peer-target",
  });

  // Object: ready-to-dispatch mesh object carrying opaque ciphertext, no plaintext.
  assert.ok(sealed.object.payloadBytes instanceof Uint8Array);
  assert.deepEqual([...sealed.object.payloadBytes], [0xDE, 0xAD]);
  // Address: a protocol inbox address, NOT a transport handle.
  assert.equal(sealed.address.kind, MESH_ADDRESS_KINDS.INBOX);
  assert.equal(sealed.address.inboxId, "inbox:peer-target");
  // No chat concepts leak onto the address.
  assert.equal("peerLinkId" in sealed.address, false);
  assert.equal("peerAccountId" in sealed.address, false);
  // sealForPeer is pure build — nothing went on the wire.
  assert.equal(pool.sent.length, 0);
});

test("sealForPeer resolves the inbox from the peer-link record when deliverInboxId is omitted", async () => {
  const pool = makeFakePool();
  let lookedUp = null;
  const peerLinkService = {
    ownerAccountId: "rez:acct:owner",
    peerLinkStorage: {
      peerLinks: {
        getByPair: async (owner, remote) => {
          lookedUp = { owner, remote };
          return { peerInboxId: "inbox:resolved", peerLinkId: "pl_1" };
        },
      },
    },
    encryptDirectMessage: async () => ({ encryptedPacket: { toBytes: () => new Uint8Array([9]) } }),
    getPostCapForPeerLink: async () => ({ cap: "signed-post-cap" }),
  };
  const client = makeClient({ pool, peerLinkService });

  const sealed = await client.sealForPeer({
    peerAccountId: "rez:acct:peer",
    plaintextBodyBytes: new Uint8Array([0xAA]),
  });

  assert.deepEqual(lookedUp, { owner: "rez:acct:owner", remote: "rez:acct:peer" });
  assert.equal(sealed.address.inboxId, "inbox:resolved");
  // Post-cap is folded into the object's capChain.
  assert.deepEqual(sealed.object.capChain, [{ cap: "signed-post-cap" }]);
});

test("sealForPeer carries receiptInboxId in metadata, null capChain when no cap exists", async () => {
  const pool = makeFakePool();
  const peerLinkService = {
    encryptDirectMessage: async () => ({ encryptedPacket: { toBytes: () => new Uint8Array([1]) } }),
  };
  const client = makeClient({ pool, peerLinkService });

  const sealed = await client.sealForPeer({
    peerAccountId: "rez:acct:peer",
    plaintextBodyBytes: new Uint8Array([1]),
    deliverInboxId: "inbox:peer",
    receiptInboxId: "inbox:mine",
  });

  assert.equal(sealed.object.metadata.receiptInboxId, "inbox:mine");
  assert.equal(sealed.object.capChain, null);
});

test("sealForPeer throws NO_DELIVERY_TARGET when no inbox can be resolved", async () => {
  const pool = makeFakePool();
  const peerLinkService = {
    ownerAccountId: "rez:acct:owner",
    peerLinkStorage: { peerLinks: { getByPair: async () => null } },
    encryptDirectMessage: async () => ({ encryptedPacket: { toBytes: () => new Uint8Array() } }),
  };
  const client = makeClient({ pool, peerLinkService });

  await assert.rejects(
    () => client.sealForPeer({
      peerAccountId: "rez:acct:peer",
      plaintextBodyBytes: new Uint8Array([1]),
    }),
    (err) => err && err.code === "NO_DELIVERY_TARGET",
  );
  assert.equal(pool.sent.length, 0);
});
