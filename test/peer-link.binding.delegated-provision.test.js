import test from "node:test";
import assert from "node:assert/strict";
import {
  bytesToBase64,
  base64ToBytes,
  canonicalJSONStringify,
  deriveAccountIdFromPublicKey,
  DeviceRegistrationV1,
  AccountDeviceCapabilityV1,
  ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
} from "@rezprotocol/core";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService, x3dhBindingPayload } from "../src/peer-link/PeerLinkService.js";
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

// S2.5 S9 K2 — selfProvisionDelegatedAccountBinding: the SDK-side producer of
// the delegated x3dh-subkey binding (C signs the canonical payload and names
// itself as the binding signer). Proven against the REAL S8 verifier: a full
// invite round-trip accepts a method-provisioned binding, and the binding
// fails CLOSED when the cert chain is withheld. A direct-mode service refuses
// the method outright.

const NOW = 1_770_000_000_000;
const FAR = NOW + 7 * 24 * 60 * 60 * 1000;

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

function signedPayloadBytes(payload) {
  return new TextEncoder().encode(canonicalJSONStringify(payload));
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
    issuedAtMs: NOW - 1000,
    expiresAtMs: FAR,
    signerPublicKeyB64: accountPubB64,
  };
  const certId = AccountDeviceCapabilityV1.deriveCertId(fields);
  const sigBytes = await c.sign({ privateKey: accountPrivBytes, msg: AccountDeviceCapabilityV1.signableBytes({ ...fields, certId }) });
  return new AccountDeviceCapabilityV1({ ...fields, certId, sig: { alg: "ed25519", sigB64: bytesToBase64(sigBytes) } });
}

// `provision`: "none" leaves the account binding to the caller; "manual"
// hand-signs the direct (B-signed) binding the way rez-chat's shipped
// self-provision does.
async function makeAccount(c, { mailboxId, delegated = false, provision = "manual" } = {}) {
  const b = await c.generateSigningKeyPair();
  const accountPubB64 = bytesToBase64(b.publicKey);
  const accountId = deriveAccountIdFromPublicKey(b.publicKey);
  const deviceKp = await c.generateSigningKeyPair();
  const deviceKeyPair = { publicKeyB64: bytesToBase64(deviceKp.publicKey), privateKeyB64: bytesToBase64(deviceKp.privateKey) };
  const authority = {
    signer: {
      getSignerRef() { return { accountId, keyId: "invite-ed25519-v1", alg: "ed25519", signerPublicKeyB64: accountPubB64 }; },
      async sign(bytes) {
        if (delegated) {
          throw new Error("TEST FAILURE: a delegated device must never sign with the account key");
        }
        return c.sign({ privateKey: b.privateKey, msg: bytes });
      },
    },
    verifier: {
      async verify({ signerRef, bytes, sigBytes }) {
        const pub = base64ToBytes(String(signerRef.signerPublicKeyB64));
        if (deriveAccountIdFromPublicKey(pub) !== String(signerRef.accountId)) return false;
        return c.verify({ publicKey: pub, msg: bytes, sig: sigBytes });
      },
    },
  };
  const leafCert = delegated
    ? await buildLeafCert(c, { accountPubB64, accountPrivBytes: b.privateKey, granteePubB64: deviceKeyPair.publicKeyB64, capabilities: ["peerLink.create"] })
    : null;
  const svc = new PeerLinkService({
    storageProvider: makeStorageProvider(),
    clock: () => NOW,
    ownerAccountId: accountId,
    getInviteAuthority: () => authority,
    inviteBinding: { mailboxId, capabilityId: mailboxId },
    cryptoProvider: c,
    deviceKeyPair,
    deviceId: DeviceRegistrationV1.deviceIdFor(deviceKeyPair.publicKeyB64),
    accountCapabilityCertChain: leafCert ? [leafCert] : null,
    hasAdminRoot: delegated ? false : true,
  });

  if (provision === "manual") {
    const challenge = await svc.getOrCreateAccountBindingChallenge({ ownerAccountId: accountId });
    const payload = x3dhBindingPayload({
      accountId,
      x3dhIdentityPublicKeyB64: challenge.x3dhIdentityPublicKeyB64,
      issuedAtMs: NOW - 1000,
      expiresAtMs: FAR,
    });
    const bindingSig = await c.sign({ privateKey: b.privateKey, msg: signedPayloadBytes(payload) });
    await svc.upsertAccountBinding({
      ownerAccountId: accountId,
      accountBinding: {
        accountId,
        accountIdentityPublicKeyB64: accountPubB64,
        x3dhIdentityPublicKeyB64: challenge.x3dhIdentityPublicKeyB64,
        issuedAtMs: NOW - 1000,
        expiresAtMs: FAR,
        accountBindingSigB64: bytesToBase64(bindingSig),
      },
    });
  }

  return { svc, accountId, accountPubB64, deviceKeyPair, mailboxId, leafCert };
}

test("a method-provisioned delegated binding carries C as its signer and drives a full invite round-trip", async () => {
  const c = new BrowserCryptoProvider();
  const inviter = await makeAccount(c, { mailboxId: "rez:inbox:inviter", delegated: true, provision: "none" });
  const acceptor = await makeAccount(c, { mailboxId: "rez:inbox:acceptor" });

  const binding = await inviter.svc.selfProvisionDelegatedAccountBinding();
  assert.equal(binding.accountId, inviter.accountId);
  assert.equal(binding.accountIdentityPublicKeyB64, inviter.accountPubB64, "the binding anchors at B");
  assert.equal(binding.accountBindingSignerPublicKeyB64, inviter.deviceKeyPair.publicKeyB64, "C is named as the signer");
  assert.ok(binding.expiresAtMs > binding.issuedAtMs);

  // The REAL verifier gate: a delegated invite built on this binding is
  // accepted end to end (chain in the envelope, binding verified against C).
  const created = await inviter.svc.createInvite({ kind: "direct", maxUses: 1, expiresAtMs: NOW + 60_000 });
  const stored = await inviter.svc.getStoredInviteEnvelope(inviter.accountId, created.inviteId);
  assert.equal(stored.envelope.binding.x3dh.accountBindingSignerPublicKeyB64, inviter.deviceKeyPair.publicKeyB64);
  let packetBytes = null;
  const accept = await acceptor.svc.acceptInvite({
    envelope: stored.envelope,
    signatureB64: stored.signatureB64,
    acceptorAccountId: acceptor.accountId,
    acceptorDisplayName: "Acceptor",
    senderInboxId: acceptor.mailboxId,
    sendHandshake: async ({ handshakePacket }) => {
      packetBytes = handshakePacket.toBytes();
      return {};
    },
  });
  assert.equal(accept.snapshot.peerAccountId, inviter.accountId);
  const drained = await inviter.svc.handleIncomingHandshakePacket({
    ownerAccountId: inviter.accountId,
    packetBytes,
  });
  assert.equal(Boolean(drained.rejected), false);
});

test("the method-provisioned binding fails CLOSED when verified without the cert chain", async () => {
  const c = new BrowserCryptoProvider();
  const inviter = await makeAccount(c, { mailboxId: "rez:inbox:inviter", delegated: true, provision: "none" });
  const acceptor = await makeAccount(c, { mailboxId: "rez:inbox:acceptor" });
  await inviter.svc.selfProvisionDelegatedAccountBinding();
  const created = await inviter.svc.createInvite({ kind: "direct", maxUses: 1, expiresAtMs: NOW + 60_000 });
  const stored = await inviter.svc.getStoredInviteEnvelope(inviter.accountId, created.inviteId);
  await assert.rejects(
    () => acceptor.svc._verifyInviteX3dhBinding({
      ownerAccountId: inviter.accountId,
      inviteBinding: stored.envelope.binding,
      certChain: null,
    }),
    (err) => err && err.code === "INVITE_SIGNATURE_INVALID"
      && /delegated signer without a cert chain/.test(err.message),
  );
});

test("a direct-mode (primary) service refuses to self-provision a delegated binding", async () => {
  const c = new BrowserCryptoProvider();
  const primary = await makeAccount(c, { mailboxId: "rez:inbox:primary", provision: "none" });
  await assert.rejects(
    () => primary.svc.selfProvisionDelegatedAccountBinding(),
    /requires a delegated PeerLinkService \(hasAdminRoot=false\); a primary device provisions its binding with the account key/,
  );
});
