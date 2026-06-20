import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase64, deriveAccountIdFromPublicKey, DeviceRegistrationV1, DEVICE_SET_RECORD_KIND } from "@rezprotocol/core";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService } from "../src/peer-link/PeerLinkService.js";
// REAL crypto — the seal is a static-static X25519 agreement and the session
// round-trip needs genuine AES-GCM/ratchet auth (FakeCryptoProvider collapses
// first-message keys and cannot prove peer-scoping).
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
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

async function makeDeviceKey(crypto) {
  const kp = await crypto.generateSigningKeyPair();
  return { publicKeyB64: bytesToBase64(kp.publicKey), privateKeyB64: bytesToBase64(kp.privateKey) };
}

// Build an account whose B (chat-server identity) key is a real Ed25519 pair, the
// accountId derives from it, the invite authority signs with it (production wires
// the authority to B — see buildChatServerInviteAuthority), and a device key C is
// attached. Returns a PeerLinkService primed with a self-provisioned account
// binding (so _requireBoundX3dhIdentity resolves) plus its public material.
async function makeAccount(crypto, { mailboxId }) {
  const b = await crypto.generateSigningKeyPair();
  const accountPubB64 = bytesToBase64(b.publicKey);
  const accountId = deriveAccountIdFromPublicKey(b.publicKey);
  const authority = {
    signer: {
      getSignerRef() { return { accountId, keyId: "invite-ed25519-v1", alg: "ed25519", signerPublicKeyB64: accountPubB64 }; },
      async sign(bytes) { return crypto.sign({ privateKey: b.privateKey, msg: bytes }); },
    },
    verifier: { async verify() { return true; } },
  };
  const deviceKeyPair = await makeDeviceKey(crypto);
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
  });

  // Self-provision the account binding: B vouches for the X3DH signing subkey.
  // _requireBoundX3dhIdentity reads (not crypto-verifies) this; the invite path
  // owns binding-sig verification, so a genuine-but-unchecked sig is honest here.
  const challenge = await svc.getOrCreateAccountBindingChallenge({ ownerAccountId: accountId });
  const bindingSig = await crypto.sign({ privateKey: b.privateKey, msg: enc("x3dh-subkey-binding:" + challenge.x3dhIdentityPublicKeyB64) });
  await svc.upsertAccountBinding({
    ownerAccountId: accountId,
    accountBinding: {
      accountId,
      accountIdentityPublicKeyB64: accountPubB64,
      x3dhIdentityPublicKeyB64: challenge.x3dhIdentityPublicKeyB64,
      issuedAtMs: 1,
      expiresAtMs: FAR_FUTURE,
      accountBindingSigB64: bytesToBase64(bindingSig),
    },
  });

  const bound = await svc._requireBoundX3dhIdentity(accountId);
  return {
    svc, sp, accountId, accountPubB64, deviceKeyPair,
    deviceId: svc.deviceId,
    identityDhPubB64: bytesToBase64(bound.identityDhKeyPair.publicKey),
  };
}

// Cross-link two accounts: each side persists the OTHER's account-level
// identity-DH pubkey (seal half) + account B pubkey (durable publisher) — exactly
// what Slice 3 leaves 2/4 record at handshake.
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

test("device set: publish → ingest → responder-complete → per-device session round-trips both ways", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });

  // Alice publishes her device set sealed to Bob (retains her responder pre-key
  // keyed by Bob). Bob ingests it and establishes an initiator session to Alice's
  // device; Alice completes as responder from Bob's handshake.
  const { record } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });
  assert.equal(record.recordKind, DEVICE_SET_RECORD_KIND);
  assert.equal(record.publisherPublicKeyB64, alice.accountPubB64);

  const ingested = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record });
  assert.equal(ingested.deviceSetRecord.devices.length, 1);
  assert.equal(ingested.established.length, 1);
  assert.equal(ingested.established[0].peerDeviceId, alice.deviceId);

  await alice.svc.completeDeviceSetResponder({
    peerAccountId: bob.accountId,
    peerDeviceId: bob.deviceId,
    handshakeData: ingested.established[0].handshakeData,
  });

  // Bob → Alice over the established device session.
  const { encryptedPacket: toAlice } = await bob.svc.encryptDirectMessageForDevice({
    peerAccountId: alice.accountId, peerLinkId: "pl_bob_alice", peerDeviceId: alice.deviceId, plaintextBytes: enc("hi alice"),
  });
  const gotAlice = await alice.svc.decryptFromDevice({
    peerAccountId: bob.accountId, peerLinkId: "pl_alice_bob", peerDeviceId: bob.deviceId, packetBytes: toAlice.toBytes(),
  });
  assert.equal(dec(gotAlice.plaintextBytes), "hi alice");

  // Alice → Bob over the same session pair (responder→initiator direction).
  const { encryptedPacket: toBob } = await alice.svc.encryptDirectMessageForDevice({
    peerAccountId: bob.accountId, peerLinkId: "pl_alice_bob", peerDeviceId: bob.deviceId, plaintextBytes: enc("hi bob"),
  });
  const gotBob = await bob.svc.decryptFromDevice({
    peerAccountId: alice.accountId, peerLinkId: "pl_bob_alice", peerDeviceId: alice.deviceId, packetBytes: toBob.toBytes(),
  });
  assert.equal(dec(gotBob.plaintextBytes), "hi bob");
});

test("device set is sealed to the peer-derived slot under the publisher's account key", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });

  const { record, slotRecordId } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });
  assert.match(slotRecordId, /^[0-9a-f]{32}$/);
  assert.equal(record.recordId, slotRecordId);
  // The DeviceSetRecordV1 + bundle are NOT in cleartext on the durable record.
  assert.equal(record.payloadB64.includes(alice.deviceId), false);
});

test("a third account cannot ingest a set sealed to someone else (peer-derived slot mismatch)", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  const carol = await makeAccount(crypto, { mailboxId: "rez:inbox:carol" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });
  await crossLink(alice, carol, { aLinkId: "pl_alice_carol", bLinkId: "pl_carol_alice" });

  // Alice seals to Bob; Carol (a different established peer) tries to open it.
  const { record } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });
  await assert.rejects(
    () => carol.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record }),
    /does not match the peer-derived slot/,
  );
});

test("publish fails loud when the peer link lacks the persisted peer identity material", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  // A bare link with NO remote identity-DH / account pubkey (pre-Slice-3 link).
  await alice.sp.peerLinkStorage.peerLinks.create({
    peerLinkId: "pl_alice_bob", localAccountId: alice.accountId, peerAccountId: bob.accountId,
    state: "session_established", version: 1,
  });
  await assert.rejects(
    () => alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId }),
    (err) => err && err.code === "PEER_LINK_DEVICE_SET_UNSUPPORTED",
  );
});

test("responder-complete fails loud when no pre-key was retained for the peer", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });
  await assert.rejects(
    () => alice.svc.completeDeviceSetResponder({ peerAccountId: bob.accountId, peerDeviceId: bob.deviceId, handshakeData: {} }),
    (err) => err && err.code === "PEER_LINK_DEVICE_PREKEY_MISSING",
  );
});
