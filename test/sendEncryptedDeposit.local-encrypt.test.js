import test from "node:test";
import assert from "node:assert/strict";
import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";
import { RezClient } from "../src/client/RezClient.js";
import { TypedEventBus } from "../src/events/TypedEventBus.js";
import { AuthStateMachine } from "../src/auth/AuthStateMachine.js";
import { MetricsCollector } from "../src/observability/MetricsCollector.js";

const T = REZ_CONTRACT_TYPES;

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
      return {
        body: {
          mailboxId: request.body.mailboxId,
          eventId: "evt_" + Date.now(),
        },
      };
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

test("sendEncryptedDeposit rejects when no peerLinkService is configured", async () => {
  const pool = makeFakePool();
  const client = makeClient({ pool, peerLinkService: null });
  await assert.rejects(
    () => client.sendEncryptedDeposit({
      peerAccountId: "rez:acct:peer",
      plaintextBodyBytes: new Uint8Array([1, 2, 3]),
      deliverInboxId: "inbox:peer",
    }),
    /peerLinkService/,
  );
  assert.equal(pool.sent.length, 0);
});

test("sendEncryptedDeposit propagates NO_DELIVERY_TARGET when no peer-link record exists", async () => {
  const pool = makeFakePool();
  const peerLinkService = {
    ownerAccountId: "rez:acct:owner",
    peerLinkStorage: { peerLinks: { getByPair: async () => null } },
    encryptDirectMessage: async () => ({ encryptedPacket: { toBytes: () => new Uint8Array() } }),
  };
  const client = makeClient({ pool, peerLinkService });
  await assert.rejects(
    () => client.sendEncryptedDeposit({
      peerAccountId: "rez:acct:peer",
      plaintextBodyBytes: new Uint8Array([1, 2, 3]),
    }),
    (err) => err && err.code === "NO_DELIVERY_TARGET",
  );
  assert.equal(pool.sent.length, 0);
});

test("sendEncryptedDeposit refuses missing peerAccountId", async () => {
  const pool = makeFakePool();
  const client = makeClient({ pool, peerLinkService: { encryptDirectMessage: async () => ({}) } });
  await assert.rejects(
    () => client.sendEncryptedDeposit({ plaintextBodyBytes: new Uint8Array([1]) }),
    /peerAccountId/,
  );
});

test("sendEncryptedDeposit refuses non-Uint8Array plaintext", async () => {
  const pool = makeFakePool();
  const client = makeClient({ pool, peerLinkService: { encryptDirectMessage: async () => ({}) } });
  await assert.rejects(
    () => client.sendEncryptedDeposit({
      peerAccountId: "rez:acct:peer",
      plaintextBodyBytes: "not-bytes",
      deliverInboxId: "inbox:peer",
    }),
    /Uint8Array/,
  );
});

test("sendEncryptedDeposit local path: encrypts via peerLinkService and emits MAILBOX_DEPOSIT", async () => {
  const pool = makeFakePool();
  const plaintext = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
  const fakeCiphertextBytes = new Uint8Array([0xCC, 0xCC, 0xCC, 0xCC]);
  const encryptCalls = [];
  const peerLinkService = {
    encryptDirectMessage: async (args) => {
      encryptCalls.push(args);
      return { encryptedPacket: { toBytes: () => fakeCiphertextBytes } };
    },
  };

  const client = makeClient({ pool, peerLinkService });
  const result = await client.sendEncryptedDeposit({
    peerAccountId: "rez:acct:peer",
    plaintextBodyBytes: plaintext,
    deliverInboxId: "inbox:peer-target",
  });

  assert.equal(encryptCalls.length, 1);
  assert.equal(encryptCalls[0].peerAccountId, "rez:acct:peer");
  assert.deepEqual([...encryptCalls[0].plaintextBytes], [72, 101, 108, 108, 111]);

  assert.equal(pool.sent.length, 1);
  assert.equal(pool.sent[0].type, T.MAILBOX_DEPOSIT);
  assert.equal(pool.sent[0].expectedResponseType, T.MAILBOX_DEPOSIT_RES);
  assert.equal(pool.sent[0].body.mailboxId, "inbox:peer-target");
  assert.equal(pool.sent[0].body.ciphertextB64, "zMzMzA==");

  // Plaintext does not appear anywhere on the wire.
  const serialized = JSON.stringify(pool.sent[0]);
  assert.equal(serialized.includes("Hello"), false);
  assert.equal(serialized.includes(Buffer.from(plaintext).toString("base64")), false);

  assert.equal(result.mailboxId, "inbox:peer-target");
  assert.ok(result.eventId.startsWith("evt_"));
});

test("sendEncryptedDeposit local path: resolves deliverInboxId from peer-link record", async () => {
  const pool = makeFakePool();
  let lookedUp = null;
  const peerLinkService = {
    ownerAccountId: "rez:acct:owner",
    peerLinkStorage: {
      peerLinks: {
        getByPair: async (owner, remote) => {
          lookedUp = { owner, remote };
          return { peerInboxId: "inbox:resolved" };
        },
      },
    },
    encryptDirectMessage: async () => ({ encryptedPacket: { toBytes: () => new Uint8Array([1, 2]) } }),
  };
  const client = makeClient({ pool, peerLinkService });
  await client.sendEncryptedDeposit({
    peerAccountId: "rez:acct:peer",
    plaintextBodyBytes: new Uint8Array([0xAA]),
    // deliverInboxId omitted
  });
  assert.deepEqual(lookedUp, { owner: "rez:acct:owner", remote: "rez:acct:peer" });
  assert.equal(pool.sent[0].body.mailboxId, "inbox:resolved");
});

test("sendEncryptedDeposit propagates non-fallthrough errors (e.g. crypto failure) without falling back", async () => {
  const pool = makeFakePool();
  const peerLinkService = {
    ownerAccountId: "rez:acct:owner",
    peerLinkStorage: { peerLinks: { getByPair: async () => ({ peerInboxId: "inbox:peer" }) } },
    encryptDirectMessage: async () => { throw new Error("crypto bork"); },
  };
  const client = makeClient({ pool, peerLinkService });
  await assert.rejects(
    () => client.sendEncryptedDeposit({
      peerAccountId: "rez:acct:peer",
      plaintextBodyBytes: new Uint8Array([1]),
    }),
    /crypto bork/,
  );
  // No fallback to wire — crypto errors must propagate so the user knows
  // their message wasn't sent.
  assert.equal(pool.sent.length, 0);
});
