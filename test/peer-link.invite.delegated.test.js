import test from "node:test";
import assert from "node:assert/strict";
import {
  bytesToBase64,
  base64ToBytes,
  canonicalJSONStringify,
  deriveAccountIdFromPublicKey,
  verifyDurableRecordV2,
  DeviceRegistrationV1,
  AccountDeviceCapabilityV1,
  ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
} from "@rezprotocol/core";
import { canonicalPayloadBytesV1 } from "../src/peer-link/inviteCodeV1.js";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService, x3dhBindingPayload } from "../src/peer-link/PeerLinkService.js";
// REAL crypto — the invite path runs genuine Ed25519 + X3DH end to end.
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

// S2.5 S8 L6 — invite create/accept dual-mode (inventory P1/P2/V1/V2). A
// DELEGATED inviter signs the invite envelope AND its durable record with its
// device key C, carrying an AccountDeviceCapabilityV1 chain C←B that must
// grant "peerLink.create". The accepter re-roots trust at the account key B
// (binding-anchor derivation + chain anchoring + chain-inside-signed-envelope).
// The DIRECT path is the live shipped one and must stay byte-identical.

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

// A signed single-hop capability cert: the account root B grants `capabilities`
// to the device key `granteePubB64`.
async function buildLeafCert(c, { accountPubB64, accountPrivBytes, granteePubB64, capabilities, issuedAtMs = NOW - 1000, expiresAtMs = FAR }) {
  const fields = {
    v: 1,
    purpose: ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
    accountIdentityPublicKeyB64: accountPubB64,
    parentCertId: null,
    granteeDevicePublicKeyB64: granteePubB64,
    granteeDeviceId: DeviceRegistrationV1.deviceIdFor(granteePubB64),
    capabilities,
    maxDelegationDepth: 0,
    issuedAtMs,
    expiresAtMs,
    signerPublicKeyB64: accountPubB64,
  };
  const certId = AccountDeviceCapabilityV1.deriveCertId(fields);
  const sigBytes = await c.sign({ privateKey: accountPrivBytes, msg: AccountDeviceCapabilityV1.signableBytes({ ...fields, certId }) });
  return new AccountDeviceCapabilityV1({ ...fields, certId, sig: { alg: "ed25519", sigB64: bytesToBase64(sigBytes) } });
}

// An account with a REAL Ed25519 root (B), a device key (C), a production-shaped
// invite authority, and a properly-signed x3dh-subkey-binding.
// `delegated: true` builds the account as a DELEGATED inviter: the service gets
// the B→C cert chain, the binding is C-signed (with the signer surfaced), and
// the account authority's SIGN function THROWS — proving the delegated invite
// path never touches the account private key.
async function makeAccount(c, { mailboxId, delegated = false, capabilities = ["peerLink.create"] } = {}) {
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
          throw new Error("TEST FAILURE: a delegated inviter must never sign with the account key");
        }
        return c.sign({ privateKey: b.privateKey, msg: bytes });
      },
    },
    verifier: {
      // Production-faithful direct verify: bind the signerRef key to the
      // claimed account by derivation, then check the signature.
      async verify({ signerRef, bytes, sigBytes }) {
        const pub = base64ToBytes(String(signerRef.signerPublicKeyB64));
        if (deriveAccountIdFromPublicKey(pub) !== String(signerRef.accountId)) return false;
        return c.verify({ publicKey: pub, msg: bytes, sig: sigBytes });
      },
    },
  };
  const leafCert = delegated
    ? await buildLeafCert(c, { accountPubB64, accountPrivBytes: b.privateKey, granteePubB64: deviceKeyPair.publicKeyB64, capabilities })
    : null;
  const sp = makeStorageProvider();
  const svc = new PeerLinkService({
    storageProvider: sp,
    clock: () => NOW,
    ownerAccountId: accountId,
    getInviteAuthority: () => authority,
    inviteBinding: { mailboxId, capabilityId: mailboxId },
    cryptoProvider: c,
    deviceKeyPair,
    deviceId: DeviceRegistrationV1.deviceIdFor(deviceKeyPair.publicKeyB64),
    accountCapabilityCertChain: leafCert ? [leafCert] : null,
  });

  // Provision the x3dh-subkey-binding: B-signed for a direct account; C-signed
  // (with the signer surfaced) for a delegated one — a delegated device holds
  // no B private key to self-provision with.
  const challenge = await svc.getOrCreateAccountBindingChallenge({ ownerAccountId: accountId });
  const payload = x3dhBindingPayload({
    accountId,
    x3dhIdentityPublicKeyB64: challenge.x3dhIdentityPublicKeyB64,
    issuedAtMs: NOW - 1000,
    expiresAtMs: FAR,
  });
  const bindingPriv = delegated ? deviceKp.privateKey : b.privateKey;
  const bindingSig = await c.sign({ privateKey: bindingPriv, msg: signedPayloadBytes(payload) });
  await svc.upsertAccountBinding({
    ownerAccountId: accountId,
    accountBinding: {
      accountId,
      accountIdentityPublicKeyB64: accountPubB64,
      x3dhIdentityPublicKeyB64: challenge.x3dhIdentityPublicKeyB64,
      issuedAtMs: NOW - 1000,
      expiresAtMs: FAR,
      accountBindingSigB64: bytesToBase64(bindingSig),
      ...(delegated ? { accountBindingSignerPublicKeyB64: deviceKeyPair.publicKeyB64 } : {}),
    },
  });

  return { svc, sp, accountId, accountPubB64, accountPrivBytes: b.privateKey, deviceKeyPair, devicePriv: deviceKp.privateKey, leafCert, mailboxId };
}

async function createAndAccept(c, inviter, acceptor, { tamperEnvelope = null } = {}) {
  const created = await inviter.svc.createInvite({
    creatorDisplayName: "Inviter",
    kind: "direct",
    maxUses: 1,
    expiresAtMs: NOW + 60_000,
  });
  const stored = await inviter.svc.getStoredInviteEnvelope(inviter.accountId, created.inviteId);
  let envelope = stored.envelope;
  let signatureB64 = stored.signatureB64;
  if (typeof tamperEnvelope === "function") {
    const tampered = await tamperEnvelope({ envelope: JSON.parse(JSON.stringify(envelope)), signatureB64 });
    envelope = tampered.envelope;
    signatureB64 = tampered.signatureB64;
  }
  let packetBytes = null;
  const accept = await acceptor.svc.acceptInvite({
    envelope,
    signatureB64,
    acceptorAccountId: acceptor.accountId,
    acceptorDisplayName: "Acceptor",
    senderInboxId: acceptor.mailboxId,
    sendHandshake: async ({ handshakePacket }) => {
      packetBytes = handshakePacket.toBytes();
      return {};
    },
  });
  return { created, envelope, signatureB64, accept, packetBytes };
}

test("delegated inviter round-trip: C signs envelope + V2 record with a B→C chain; accepter verifies and the handshake establishes", async () => {
  const c = new BrowserCryptoProvider();
  const inviter = await makeAccount(c, { mailboxId: "rez:inbox:inviter", delegated: true });
  const acceptor = await makeAccount(c, { mailboxId: "rez:inbox:acceptor" });

  const { created, envelope, accept, packetBytes } = await createAndAccept(c, inviter, acceptor);

  // Envelope: delegated signerRef + the chain INSIDE the signed payload.
  assert.equal(envelope.creatorAccountId, inviter.accountId);
  assert.equal(envelope.signerRef.accountId, inviter.accountId);
  assert.equal(envelope.signerRef.keyId, "invite-ed25519-delegated-v1");
  assert.equal(envelope.signerRef.signerPublicKeyB64, inviter.deviceKeyPair.publicKeyB64);
  assert.equal(Array.isArray(envelope.certChain) && envelope.certChain.length, 1);
  assert.equal(envelope.binding.x3dh.accountBindingSignerPublicKeyB64, inviter.deviceKeyPair.publicKeyB64,
    "the C-signed binding surfaces its signer");

  // Durable record: V2, OWNER = the account root B (slot/commitment unmoved),
  // SIGNER = the device C, cap stamped; verifies as mode=delegated.
  const record = created.durableRecord;
  assert.equal(record.v, 2);
  assert.equal(record.ownerPublicKeyB64, inviter.accountPubB64);
  assert.equal(record.signerPublicKeyB64, inviter.deviceKeyPair.publicKeyB64);
  assert.equal(record.requiredCapability, "peerLink.create");
  assert.equal(created.publisherPublicKeyB64, inviter.accountPubB64, "the fetch coordinate stays the account key");
  const verdict = await verifyDurableRecordV2({ record, crypto: c, nowMs: NOW + 1 });
  assert.equal(verdict.ok, true, verdict.reason);
  assert.equal(verdict.mode, "delegated");

  // Accepter committed and produced a real X3DH handshake.
  assert.equal(accept.snapshot.peerAccountId, inviter.accountId);
  assert.ok(packetBytes instanceof Uint8Array && packetBytes.length > 0);

  // Inviter drains the handshake → session_established (full loop).
  const drained = await inviter.svc.handleIncomingHandshakePacket({
    ownerAccountId: inviter.accountId,
    packetBytes,
  });
  assert.equal(Boolean(drained.rejected), false);
  const links = await inviter.svc.peerLinkStorage.peerLinks.listByOwner(inviter.accountId);
  assert.equal(links.length, 1);
  assert.equal(links[0].peerAccountId, acceptor.accountId);
  assert.equal(links[0].state, "session_established");
});

test("delegated: a chain granting the wrong capability is rejected on accept", async () => {
  const c = new BrowserCryptoProvider();
  const inviter = await makeAccount(c, { mailboxId: "rez:inbox:inviter", delegated: true, capabilities: ["deviceSet.publish"] });
  const acceptor = await makeAccount(c, { mailboxId: "rez:inbox:acceptor" });
  await assert.rejects(
    () => createAndAccept(c, inviter, acceptor),
    (err) => err && err.code === "INVITE_SIGNATURE_INVALID",
  );
});

test("delegated: a chain rooted at a DIFFERENT account than the binding anchor is rejected", async () => {
  const c = new BrowserCryptoProvider();
  const inviter = await makeAccount(c, { mailboxId: "rez:inbox:inviter", delegated: true });
  const acceptor = await makeAccount(c, { mailboxId: "rez:inbox:acceptor" });
  const stranger = await c.generateSigningKeyPair();
  const strangerCert = await buildLeafCert(c, {
    accountPubB64: bytesToBase64(stranger.publicKey),
    accountPrivBytes: stranger.privateKey,
    granteePubB64: inviter.deviceKeyPair.publicKeyB64,
    capabilities: ["peerLink.create"],
  });
  // Swap the chain for one anchored at the stranger's account and RE-SIGN the
  // envelope with C so the signature itself passes — the chain-anchor check
  // (expected account = the binding's B) must be what rejects it.
  await assert.rejects(
    () => createAndAccept(c, inviter, acceptor, {
      tamperEnvelope: async ({ envelope }) => {
        envelope.certChain = [strangerCert.toJSON()];
        const resigned = await c.sign({ privateKey: inviter.devicePriv, msg: canonicalPayloadBytesV1(envelope) });
        return { envelope, signatureB64: bytesToBase64(resigned) };
      },
    }),
    (err) => err && err.code === "INVITE_SIGNATURE_INVALID",
  );
});

test("delegated: an EXPIRED leaf cert is rejected on accept", async () => {
  const c = new BrowserCryptoProvider();
  const inviter = await makeAccount(c, { mailboxId: "rez:inbox:inviter", delegated: true });
  const acceptor = await makeAccount(c, { mailboxId: "rez:inbox:acceptor" });
  const expiredCert = await buildLeafCert(c, {
    accountPubB64: inviter.accountPubB64,
    accountPrivBytes: inviter.accountPrivBytes,
    granteePubB64: inviter.deviceKeyPair.publicKeyB64,
    capabilities: ["peerLink.create"],
    issuedAtMs: NOW - 10_000,
    expiresAtMs: NOW - 1,
  });
  await assert.rejects(
    () => createAndAccept(c, inviter, acceptor, {
      tamperEnvelope: async ({ envelope }) => {
        envelope.certChain = [expiredCert.toJSON()];
        const resigned = await c.sign({ privateKey: inviter.devicePriv, msg: canonicalPayloadBytesV1(envelope) });
        return { envelope, signatureB64: bytesToBase64(resigned) };
      },
    }),
    (err) => err && err.code === "INVITE_SIGNATURE_INVALID",
  );
});

test("delegated: tampering the certChain after signing breaks the envelope signature", async () => {
  const c = new BrowserCryptoProvider();
  const inviter = await makeAccount(c, { mailboxId: "rez:inbox:inviter", delegated: true });
  const acceptor = await makeAccount(c, { mailboxId: "rez:inbox:acceptor" });
  await assert.rejects(
    () => createAndAccept(c, inviter, acceptor, {
      tamperEnvelope: async ({ envelope, signatureB64 }) => {
        // Widen the granted capabilities WITHOUT re-signing the envelope.
        envelope.certChain[0].capabilities = ["peerLink.create", "device.revoke"];
        return { envelope, signatureB64 };
      },
    }),
    (err) => err && err.code === "INVITE_SIGNATURE_INVALID",
  );
});

test("a binding naming a delegated signer WITHOUT a cert chain is rejected (fail closed)", async () => {
  const c = new BrowserCryptoProvider();
  const inviter = await makeAccount(c, { mailboxId: "rez:inbox:inviter", delegated: true });
  const acceptor = await makeAccount(c, { mailboxId: "rez:inbox:acceptor" });
  const created = await inviter.svc.createInvite({ kind: "direct", maxUses: 1, expiresAtMs: NOW + 60_000 });
  const stored = await inviter.svc.getStoredInviteEnvelope(inviter.accountId, created.inviteId);
  // The delegated binding straight off the envelope, verified with NO chain —
  // the shape a handshake-borne binding would have if its chain were stripped.
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

test("direct regression: the shipped invite shape is unchanged — no certChain key, V1 record, B signs, full round-trip", async () => {
  const c = new BrowserCryptoProvider();
  const inviter = await makeAccount(c, { mailboxId: "rez:inbox:inviter" });
  const acceptor = await makeAccount(c, { mailboxId: "rez:inbox:acceptor" });

  const { created, envelope, accept, packetBytes } = await createAndAccept(c, inviter, acceptor);

  assert.equal("certChain" in envelope, false, "a direct envelope gains NO new keys");
  assert.deepEqual(envelope.signerRef, {
    accountId: inviter.accountId,
    keyId: "invite-ed25519-v1",
    alg: "ed25519",
    signerPublicKeyB64: inviter.accountPubB64,
  });
  assert.equal("accountBindingSignerPublicKeyB64" in envelope.binding.x3dh, false,
    "a direct binding gains NO signer field");
  const record = created.durableRecord;
  assert.equal(record.v, 1, "the direct durable record stays DurableRecordV1");
  assert.equal(record.publisherPublicKeyB64, inviter.accountPubB64);
  assert.equal("ownerPublicKeyB64" in record, false);
  assert.equal(created.publisherPublicKeyB64, inviter.accountPubB64);

  assert.equal(accept.snapshot.peerAccountId, inviter.accountId);
  const drained = await inviter.svc.handleIncomingHandshakePacket({
    ownerAccountId: inviter.accountId,
    packetBytes,
  });
  assert.equal(Boolean(drained.rejected), false);
  const links = await inviter.svc.peerLinkStorage.peerLinks.listByOwner(inviter.accountId);
  assert.equal(links[0].state, "session_established");
});
