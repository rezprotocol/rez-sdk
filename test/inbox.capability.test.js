import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {
  MemoryStorageProvider,
  RCryptoProvider,
  REZ_CONTRACT_TYPES,
} from "@rezprotocol/core";
import { InboxClaimStore } from "../src/inbox/InboxClaimStore.js";
import { InboxesCapability } from "../src/capabilities/InboxesCapability.js";

const T = REZ_CONTRACT_TYPES;

class TestCrypto extends RCryptoProvider {
  constructor() { super(); this._subtle = webcrypto.subtle; }
  randomBytes(n) { const out = new Uint8Array(n); webcrypto.getRandomValues(out); return out; }
  async generateSigningKeyPair() {
    const kp = await this._subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const pubRaw = new Uint8Array(await this._subtle.exportKey("raw", kp.publicKey));
    const pkcs8 = new Uint8Array(await this._subtle.exportKey("pkcs8", kp.privateKey));
    return { publicKey: pubRaw, privateKey: pkcs8.slice(pkcs8.length - 32) };
  }
  async sign({ privateKey, msg }) {
    const PFX = new Uint8Array([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
    const pkcs8 = new Uint8Array(PFX.length + privateKey.length);
    pkcs8.set(PFX, 0); pkcs8.set(privateKey, PFX.length);
    const key = await this._subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
    return new Uint8Array(await this._subtle.sign({ name: "Ed25519" }, key, msg));
  }
  async verify({ publicKey, msg, sig }) {
    const key = await this._subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return this._subtle.verify({ name: "Ed25519" }, key, sig, msg);
  }
}

function makeFakePool(handler) {
  return {
    sendRequest: async (request) => handler(request),
  };
}

async function makeCapability() {
  const claimStore = new InboxClaimStore({
    storageProvider: new MemoryStorageProvider(),
    cryptoProvider: new TestCrypto(),
  });
  await claimStore.hydrate();
  return { claimStore };
}

test("InboxesCapability requires pool and claimStore", () => {
  assert.throws(() => new InboxesCapability({}), /pool/);
  assert.throws(() => new InboxesCapability({ pool: {} }), /claimStore/);
});

test("claimInbox sends inbox.claim, persists on success, returns the claim record", async () => {
  const { claimStore } = await makeCapability();
  const sentRequests = [];
  const pool = makeFakePool(async (request) => {
    sentRequests.push(request);
    return {
      body: {
        inboxId: request.body.inboxId,
        claimedAtMs: request.body.claimedAtMs,
      },
    };
  });
  const inboxes = new InboxesCapability({ pool, claimStore });

  const result = await inboxes.claimInbox();

  // Wire request shape
  assert.equal(sentRequests.length, 1);
  assert.equal(sentRequests[0].type, T.INBOX_CLAIM);
  assert.equal(sentRequests[0].expectedResponseType, T.INBOX_CLAIM_RES);
  assert.equal(typeof sentRequests[0].body.inboxId, "string");
  assert.equal(typeof sentRequests[0].body.claimantPublicKeyB64, "string");
  assert.equal(typeof sentRequests[0].body.signatureB64, "string");
  assert.equal(typeof sentRequests[0].body.claimedAtMs, "number");

  // Persisted in claim store
  assert.equal(claimStore.size(), 1);
  assert.equal(claimStore.has(result.inboxId), true);
  const stored = claimStore.get(result.inboxId);
  assert.equal(stored.inboxId, result.inboxId);
  assert.equal(typeof stored.claimantPrivateKeyB64, "string");
});

test("claimInbox throws if response inboxId mismatches request", async () => {
  const { claimStore } = await makeCapability();
  const pool = makeFakePool(async () => ({ body: { inboxId: "inbox:wrong" } }));
  const inboxes = new InboxesCapability({ pool, claimStore });
  await assert.rejects(() => inboxes.claimInbox(), /inboxId mismatch/);
  // Not persisted on failure
  assert.equal(claimStore.size(), 0);
});

test("claimInbox does not persist if the pool send rejects", async () => {
  const { claimStore } = await makeCapability();
  const pool = makeFakePool(async () => { throw new Error("network down"); });
  const inboxes = new InboxesCapability({ pool, claimStore });
  await assert.rejects(() => inboxes.claimInbox(), /network down/);
  assert.equal(claimStore.size(), 0);
});

test("reattestInbox uses stored claimant key and sends inbox.claim with fresh signature", async () => {
  const { claimStore } = await makeCapability();
  // First, claim an inbox so we have something to reattest.
  let nextResponse = (request) => ({ body: { inboxId: request.body.inboxId } });
  const sentRequests = [];
  const pool = makeFakePool(async (request) => { sentRequests.push(request); return nextResponse(request); });
  const inboxes = new InboxesCapability({ pool, claimStore });
  const first = await inboxes.claimInbox();
  const firstSig = sentRequests[0].body.signatureB64;
  const firstPubkey = sentRequests[0].body.claimantPublicKeyB64;

  // Now re-attest. Signature must be different (different timestamp) but
  // pubkey must match.
  const result = await inboxes.reattestInbox(first.inboxId);

  assert.equal(sentRequests.length, 2);
  assert.equal(sentRequests[1].body.inboxId, first.inboxId);
  assert.equal(sentRequests[1].body.claimantPublicKeyB64, firstPubkey);
  assert.notEqual(sentRequests[1].body.signatureB64, firstSig);
  assert.equal(result.inboxId, first.inboxId);
});

test("reattestInbox throws if the inbox isn't in the claim store", async () => {
  const { claimStore } = await makeCapability();
  const pool = makeFakePool(async () => ({ body: {} }));
  const inboxes = new InboxesCapability({ pool, claimStore });
  await assert.rejects(() => inboxes.reattestInbox("inbox:never"), /no stored claim/);
});

test("listClaimed proxies to InboxClaimStore.listRedacted", async () => {
  const { claimStore } = await makeCapability();
  const pool = makeFakePool(async (request) => ({ body: { inboxId: request.body.inboxId } }));
  const inboxes = new InboxesCapability({ pool, claimStore });
  await inboxes.claimInbox();
  await inboxes.claimInbox();

  const list = inboxes.listClaimed();
  assert.equal(list.length, 2);
  for (const entry of list) {
    assert.equal(typeof entry.inboxId, "string");
    assert.equal(typeof entry.claimantPublicKeyB64, "string");
    assert.equal(entry.claimantPrivateKeyB64, undefined);
  }
});
