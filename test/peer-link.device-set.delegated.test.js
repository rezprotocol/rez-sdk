import test from "node:test";
import assert from "node:assert/strict";
import {
  bytesToBase64,
  base64ToBytes,
  deriveAccountIdFromPublicKey,
  verifyDurableRecordV2,
  DeviceRegistrationV1,
  DeviceSetRecordV1,
  AccountDeviceCapabilityV1,
  ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
  DEVICE_SET_RECORD_KIND,
} from "@rezprotocol/core";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService } from "../src/peer-link/PeerLinkService.js";
import { DEVICE_SET_PUBLISH_CAPABILITY } from "../src/peer-link/deviceSetPublish.js";
// REAL crypto — the seal is a static-static X25519 agreement; the delegated
// envelope + inner set carry genuine Ed25519 signatures verified end to end.
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

// S2.5 S9 K2 — cert-mode device-set PUBLISH (the S8 L5 delegated params, now
// wired through the service). A delegated publisher (hasAdminRoot=false) signs
// the INNER DeviceSetRecordV1 AND the sealed DurableRecordV2 envelope with its
// device key C under the B→C capability chain — the account key B is never
// touched (the harness authority THROWS on sign to prove it). The owner/slot
// stays B, so a DIRECT peer resolves and ingests the record unchanged.

const enc = (s) => new TextEncoder().encode(s);
const FAR_FUTURE = 10_000_000_000_000;

function makeKvStore() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : undefined; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { return m.delete(k); },
    async keys(prefix) {
      const out = [];
      for (const k of m.keys()) if (!prefix || k.startsWith(prefix)) out.push(k);
      return out;
    },
  };
}

function makeStorageProvider() {
  const kv = makeKvStore();
  const peerLinkStorage = createKeyValueBackedPeerLinkStorage({ keyValueStore: kv });
  return {
    getPeerLinkStorage() { return peerLinkStorage; },
    getKeyValueStore() { return kv; },
    peerLinkStorage,
  };
}

async function buildLeafCert(c, { accountPubB64, accountPrivBytes, granteePubB64, capabilities }) {
  const fields = {
    v: 1,
    purpose: ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
    accountIdentityPublicKeyB64: accountPubB64,
    parentCertId: null,
    granteeDevicePublicKeyB64: granteePubB64,
    granteeDeviceId: DeviceRegistrationV1.deviceIdFor(granteePubB64),
    capabilities,
    maxDelegationDepth: 0,
    issuedAtMs: 1,
    expiresAtMs: FAR_FUTURE,
    signerPublicKeyB64: accountPubB64,
  };
  const certId = AccountDeviceCapabilityV1.deriveCertId(fields);
  const sigBytes = await c.sign({ privateKey: accountPrivBytes, msg: AccountDeviceCapabilityV1.signableBytes({ ...fields, certId }) });
  return new AccountDeviceCapabilityV1({ ...fields, certId, sig: { alg: "ed25519", sigB64: bytesToBase64(sigBytes) } });
}

// An account with a real Ed25519 root B, a device key C, and a self-provisioned
// binding. `delegated: true` = cert-mode service (chain + hasAdminRoot=false)
// whose account authority THROWS on sign — the delegated publish path must
// never reach for B. `bindingAccountPubB64` overrides the binding's account
// anchor (harness-only, to exercise the anchor↔binding disagreement check).
async function makeAccount(crypto, { mailboxId, delegated = false, bindingAccountPubB64 = null } = {}) {
  const b = await crypto.generateSigningKeyPair();
  const accountPubB64 = bytesToBase64(b.publicKey);
  const accountId = deriveAccountIdFromPublicKey(b.publicKey);
  const authority = {
    signer: {
      getSignerRef() { return { accountId, keyId: "invite-ed25519-v1", alg: "ed25519", signerPublicKeyB64: accountPubB64 }; },
      async sign(bytes) {
        if (delegated) {
          throw new Error("TEST FAILURE: a delegated publisher must never sign with the account key");
        }
        return crypto.sign({ privateKey: b.privateKey, msg: bytes });
      },
    },
    verifier: { async verify() { return true; } },
  };
  const deviceKp = await crypto.generateSigningKeyPair();
  const deviceKeyPair = { publicKeyB64: bytesToBase64(deviceKp.publicKey), privateKeyB64: bytesToBase64(deviceKp.privateKey) };
  const leafCert = delegated
    ? await buildLeafCert(crypto, {
        accountPubB64,
        accountPrivBytes: b.privateKey,
        granteePubB64: deviceKeyPair.publicKeyB64,
        capabilities: ["deviceSet.publish"],
      })
    : null;
  const sp = makeStorageProvider();
  const svc = new PeerLinkService({
    storageProvider: sp,
    clock: () => 1,
    ownerAccountId: accountId,
    getInviteAuthority: () => authority,
    inviteBinding: { mailboxId, capabilityId: mailboxId },
    cryptoProvider: crypto,
    deviceKeyPair,
    deviceId: DeviceRegistrationV1.deviceIdFor(deviceKeyPair.publicKeyB64),
    accountCapabilityCertChain: leafCert ? [leafCert] : null,
    hasAdminRoot: delegated ? false : null,
  });

  const challenge = await svc.getOrCreateAccountBindingChallenge({ ownerAccountId: accountId });
  const bindingSig = await crypto.sign({ privateKey: delegated ? deviceKp.privateKey : b.privateKey, msg: enc("x3dh-subkey-binding:" + challenge.x3dhIdentityPublicKeyB64) });
  await svc.upsertAccountBinding({
    ownerAccountId: accountId,
    accountBinding: {
      accountId,
      accountIdentityPublicKeyB64: bindingAccountPubB64 || accountPubB64,
      x3dhIdentityPublicKeyB64: challenge.x3dhIdentityPublicKeyB64,
      issuedAtMs: 1,
      expiresAtMs: FAR_FUTURE,
      accountBindingSigB64: bytesToBase64(bindingSig),
      ...(delegated ? { accountBindingSignerPublicKeyB64: deviceKeyPair.publicKeyB64 } : {}),
    },
  });

  const bound = await svc._requireBoundX3dhIdentity(accountId);
  return {
    svc, sp, accountId, accountPubB64, deviceKeyPair,
    deviceId: svc.deviceId,
    identityDhPubB64: bytesToBase64(bound.identityDhKeyPair.publicKey),
  };
}

async function crossLink(a, b, { aLinkId, bLinkId }) {
  await a.sp.peerLinkStorage.peerLinks.create({
    peerLinkId: aLinkId, localAccountId: a.accountId, peerAccountId: b.accountId,
    state: "session_established",
    remoteIdentityDhPublicKeyB64: b.identityDhPubB64,
    remoteAccountIdentityPublicKeyB64: b.accountPubB64,
    version: 1,
  });
  await b.sp.peerLinkStorage.peerLinks.create({
    peerLinkId: bLinkId, localAccountId: b.accountId, peerAccountId: a.accountId,
    state: "session_established",
    remoteIdentityDhPublicKeyB64: a.identityDhPubB64,
    remoteAccountIdentityPublicKeyB64: a.accountPubB64,
    version: 1,
  });
}

test("cert-mode publish: C signs inner set + V2 envelope under the chain, owner stays B, a DIRECT peer ingests it", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice", delegated: true });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_a_b", bLinkId: "pl_b_a" });

  const { record, publisherPublicKeyB64 } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });

  assert.equal(record.recordKind, DEVICE_SET_RECORD_KIND);
  assert.equal(record.v, 2);
  assert.equal(record.ownerPublicKeyB64, alice.accountPubB64, "the owner/slot anchor stays the account key B");
  assert.equal(record.signerPublicKeyB64, alice.deviceKeyPair.publicKeyB64, "the device key C signs the envelope");
  assert.equal(record.requiredCapability, DEVICE_SET_PUBLISH_CAPABILITY);
  assert.equal(Array.isArray(record.certChain) && record.certChain.length, 1);
  assert.equal(publisherPublicKeyB64, alice.accountPubB64, "the fetch coordinate stays the account key");

  const verdict = await verifyDurableRecordV2({ record, crypto, nowMs: 2 });
  assert.equal(verdict.ok, true, verdict.reason);
  assert.equal(verdict.mode, "delegated");

  // The DIRECT peer opens + ingests the delegated record: same-signer inner
  // binding (C signed the set, C signed the envelope) passes, sessions
  // establish, and the responder side completes — full device-session loop.
  const ingested = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record });
  assert.equal(ingested.deviceSetRecord.devices.length, 1);
  assert.equal(ingested.established.length, 1);
  assert.equal(ingested.established[0].peerDeviceId, alice.deviceId);

  await alice.svc.completeDeviceSetResponder({
    peerAccountId: bob.accountId,
    peerDeviceId: bob.deviceId,
    handshakeData: ingested.established[0].handshakeData,
  });
  const { encryptedPacket } = await bob.svc.encryptDirectMessageForDevice({
    peerAccountId: alice.accountId, peerLinkId: "pl_b_a", peerDeviceId: alice.deviceId, plaintextBytes: enc("to the delegated device"),
  });
  const opened = await alice.svc.decryptFromDevice({
    peerAccountId: bob.accountId, peerLinkId: "pl_a_b", peerDeviceId: bob.deviceId, packetBytes: encryptedPacket.toBytes(),
  });
  assert.equal(new TextDecoder().decode(opened.plaintextBytes), "to the delegated device");
});

test("cert-mode: the inner DeviceSetRecordV1 is C-signed (same-signer binding) with the account anchor intact", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice", delegated: true });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_a_b", bLinkId: "pl_b_a" });

  const { record } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });
  // Open on the peer side and check the inner set's signer + anchor directly.
  const opened = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record });
  const set = opened.deviceSetRecord;
  assert.equal(set.accountIdentityPublicKeyB64, alice.accountPubB64, "the set body's account anchor stays B");
  const setOk = await crypto.verify({
    publicKey: base64ToBytes(alice.deviceKeyPair.publicKeyB64),
    msg: DeviceSetRecordV1.signableBytes(set.toJSON()),
    sig: base64ToBytes(set.sig.sigB64),
  });
  assert.equal(setOk, true, "the inner set is signed by C, not B");
});

test("cert-mode: a chain anchored to a different account than the owner fails loud before signing", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice", delegated: true });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  // Resolve the delegated signer for an owner the chain does NOT anchor to —
  // the anchor↔owner derivation check must reject before any signing.
  await assert.rejects(
    () => alice.svc._resolveDelegatedAccountIdentitySigner(bob.accountId),
    /chain anchor does not derive the owner accountId/,
  );
});

test("cert-mode: a binding that disagrees with the chain anchor fails loud", async () => {
  const crypto = new BrowserCryptoProvider();
  const strangerKp = await crypto.generateSigningKeyPair();
  const alice = await makeAccount(crypto, {
    mailboxId: "rez:inbox:alice",
    delegated: true,
    bindingAccountPubB64: bytesToBase64(strangerKp.publicKey),
  });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_a_b", bLinkId: "pl_b_a" });
  await assert.rejects(
    () => alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId }),
    /chain anchor disagrees with the account binding/,
  );
});

test("direct regression: the shipped publish shape is unchanged — B signs inner + envelope, no chain", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_a_b", bLinkId: "pl_b_a" });

  const { record } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });
  assert.equal(record.v, 2);
  assert.equal(record.ownerPublicKeyB64, alice.accountPubB64);
  assert.equal(record.signerPublicKeyB64, alice.accountPubB64, "direct mode: the account key signs the envelope");
  assert.equal(Array.isArray(record.certChain) && record.certChain.length, 0, "direct mode carries no chain");
  const verdict = await verifyDurableRecordV2({ record, crypto, nowMs: 2 });
  assert.equal(verdict.ok, true, verdict.reason);
  assert.equal(verdict.mode, "direct");

  const ingested = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record });
  const set = ingested.deviceSetRecord;
  const setOk = await crypto.verify({
    publicKey: base64ToBytes(alice.accountPubB64),
    msg: DeviceSetRecordV1.signableBytes(set.toJSON()),
    sig: base64ToBytes(set.sig.sigB64),
  });
  assert.equal(setOk, true, "direct mode: the inner set is B-signed");
});
