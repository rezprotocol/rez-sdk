import test from "node:test";
import assert from "node:assert/strict";
import {
  bytesToBase64,
  deriveAccountIdFromPublicKey,
  DeviceRegistrationV1,
  DEVICE_SET_RECORD_KIND,
  DeviceSetRecordV1,
  DevicePrekeyBundleV1,
  AccountDeviceCapabilityV1,
  ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
} from "@rezprotocol/core";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService } from "../src/peer-link/PeerLinkService.js";
import { buildSealedDeviceSetRecord, DEVICE_SET_PUBLISH_CAPABILITY } from "../src/peer-link/deviceSetPublish.js";
import { derivePeerScopedKey, openFromPeer } from "../src/peer-link/peerScopedSeal.js";
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
    // Harness-only private material for hand-building delegated records
    // (S8 L5 tests): the account B signer + the identity-DH seal half.
    accountPrivBytes: b.privateKey,
    identityDhPrivB64: bytesToBase64(bound.identityDhKeyPair.privateKey),
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
  assert.equal(record.v, 2);
  assert.equal(record.ownerPublicKeyB64, alice.accountPubB64);
  assert.equal(record.signerPublicKeyB64, alice.accountPubB64, "direct mode: the account key signs");

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

test("first-contact: the device handshake rides IN-BAND in the message envelope; receiver establishes the responder from it, then decrypts (Audit P1)", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });

  // Alice publishes; Bob ingests → Bob holds an initiator session to Alice's
  // device PLUS the handshakeData Alice needs to complete the responder.
  const { record } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });
  const ingested = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record });
  const handshakeData = ingested.established[0].handshakeData;

  // Bob sends his FIRST device message to Alice with the handshake embedded
  // IN-BAND in the envelope (exactly what sealForPeerDevice does) — NOT in
  // metadata, which the durable home log drops and the receiver never reads.
  const { encryptedPacket } = await bob.svc.encryptDirectMessageForDevice({
    peerAccountId: alice.accountId, peerLinkId: "pl_bob_alice", peerDeviceId: alice.deviceId, plaintextBytes: enc("first contact"),
  });
  const env = JSON.parse(new TextDecoder().decode(encryptedPacket.toBytes()));
  env.deviceHandshake = { senderAccountId: bob.accountId, senderDeviceId: bob.deviceId, handshakeData };
  const inbandBytes = new TextEncoder().encode(JSON.stringify(env));

  // Alice has NOT pre-established the responder. She reads the in-band handshake,
  // completes the responder against Bob, THEN decrypts the SAME envelope.
  assert.equal(await alice.svc.hasDeviceSession({ peerAccountId: bob.accountId, peerDeviceId: bob.deviceId }), false, "no device session before first contact");
  const dh = env.deviceHandshake;
  await alice.svc.completeDeviceSetResponder({ peerAccountId: dh.senderAccountId, peerDeviceId: dh.senderDeviceId, handshakeData: dh.handshakeData });
  assert.equal(await alice.svc.hasDeviceSession({ peerAccountId: bob.accountId, peerDeviceId: bob.deviceId }), true, "responder session established from the in-band handshake");

  // The inner ciphertext decrypts over the now-established session — the extra
  // deviceHandshake field in the envelope is ignored by the decrypt.
  const got = await alice.svc.decryptFromDevice({
    peerAccountId: bob.accountId, peerLinkId: "pl_alice_bob", peerDeviceId: bob.deviceId, packetBytes: inbandBytes,
  });
  assert.equal(dec(got.plaintextBytes), "first contact");
});

test("resolve coordinates are commutative: the resolver independently recomputes the publisher's slot + publisher key", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });

  // Alice publishes her set sealed to Bob. Bob, WITHOUT being told where, derives
  // the same fetch coordinates from his own dh-priv + Alice's dh-pub.
  const published = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });
  const coords = await bob.svc.resolvePeerDeviceSetCoordinates({ peerAccountId: alice.accountId });
  assert.equal(coords.recordKind, published.recordKind);
  assert.equal(coords.recordId, published.recordId, "resolver recomputes the publisher's peer-derived slot");
  assert.equal(coords.publisherPublicKeyB64, alice.accountPubB64, "publisher is Alice's account (B) key");
  assert.equal(coords.publisherPublicKeyB64, published.publisherPublicKeyB64);
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

test("Audit R2 #2: re-ingesting an UNCHANGED device set is idempotent — no session churn, no new establishment", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });

  const { record } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });

  // First ingest establishes the initiator session.
  const first = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record });
  assert.equal(first.established.length, 1, "first ingest establishes one device session");
  const sid1 = await bob.sp.peerLinkStorage.sessions.getByPeerLinkAndDevice(bob.accountId, "pl_bob_alice", alice.deviceId);
  assert.ok(sid1, "session stored after first ingest");

  // Complete the responder so a real round-trip is possible, then send once to
  // advance the ratchet.
  await alice.svc.completeDeviceSetResponder({ peerAccountId: bob.accountId, peerDeviceId: bob.deviceId, handshakeData: first.established[0].handshakeData });
  const { encryptedPacket: m1 } = await bob.svc.encryptDirectMessageForDevice({
    peerAccountId: alice.accountId, peerLinkId: "pl_bob_alice", peerDeviceId: alice.deviceId, plaintextBytes: enc("one"),
  });
  assert.equal(dec((await alice.svc.decryptFromDevice({ peerAccountId: bob.accountId, peerLinkId: "pl_alice_bob", peerDeviceId: bob.deviceId, packetBytes: m1.toBytes() })).plaintextBytes), "one");

  // Re-ingest the SAME record (the old code would re-establish a fresh session
  // here, desyncing the responder). Now it is a no-op for the existing device.
  const sessionBefore = await bob.sp.peerLinkStorage.sessions.getByPeerLinkAndDevice(bob.accountId, "pl_bob_alice", alice.deviceId);
  const second = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record });
  assert.equal(second.established.length, 0, "no NEW establishment on an unchanged re-ingest");
  assert.equal(second.reused.length, 1, "the existing device session is reused");
  const sessionAfter = await bob.sp.peerLinkStorage.sessions.getByPeerLinkAndDevice(bob.accountId, "pl_bob_alice", alice.deviceId);
  assert.deepEqual(sessionAfter, sessionBefore, "the stored session is byte-unchanged across re-ingest (no churn)");

  // The SAME session still round-trips after re-ingest — not reset.
  const { encryptedPacket: m2 } = await bob.svc.encryptDirectMessageForDevice({
    peerAccountId: alice.accountId, peerLinkId: "pl_bob_alice", peerDeviceId: alice.deviceId, plaintextBytes: enc("two"),
  });
  assert.equal(dec((await alice.svc.decryptFromDevice({ peerAccountId: bob.accountId, peerLinkId: "pl_alice_bob", peerDeviceId: bob.deviceId, packetBytes: m2.toBytes() })).plaintextBytes), "two");
});

test("Audit R2 #2: ingest rejects a device set whose revision rolls back below a known revision", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });

  const { record } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });
  // The built set is revision 1; ingesting it while we already accepted a higher
  // revision (minRevision: 5) is a rollback and must be refused fail-loud.
  await assert.rejects(
    () => bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record, minRevision: 5 }),
    (err) => err && err.code === "DEVICE_SET_STALE_REVISION" && err.revision === 1 && err.knownRevision === 5,
  );
  // An equal-or-higher floor is accepted (revision 1, minRevision 1).
  const ok = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record, minRevision: 1 });
  assert.equal(ok.revision, 1);
  assert.equal(ok.established.length, 1);
});

test("S11: buildDeviceSetRecordForPeer threads an explicit revision (default 1 stays byte-compatible)", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });

  // Default: revision 1 (the pre-S11 direct path).
  const def = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });
  const okDefault = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record: def.record });
  assert.equal(okDefault.revision, 1, "no revision arg ⇒ revision 1, unchanged");

  // An explicit higher revision (an authority epoch bumped by a device mutation)
  // rides through and is accepted as it advances the floor.
  const bumped = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId, revision: 7 });
  const okBumped = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record: bumped.record });
  assert.equal(okBumped.revision, 7, "the explicit revision threads into the published set");
});

test("S11: buildDeviceSetRecordForPeer rejects a non-positive/non-integer revision (fail loud)", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });
  await assert.rejects(() => alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId, revision: 0 }), /positive integer revision/);
  await assert.rejects(() => alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId, revision: 1.5 }), /positive integer revision/);
});

test("Audit R3 #5: a successful ingest persists the revision floor durably", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });
  const { record } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });

  await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record });
  const floorKey = "peer-link:device-set-floor:" + bob.accountId + ":" + alice.accountId;
  const storedFloor = await bob.sp.getKeyValueStore().get(floorKey);
  assert.equal(storedFloor.revision, 1, "the highest accepted revision is persisted so the floor survives a restart");
  assert.equal(typeof storedFloor.binding, "string");
  assert.ok(storedFloor.binding.length > 0, "the accepted authority content is bound for same-revision equivocation detection");
});

test("Audit R4 #3: different authority content at the same revision is rejected as equivocation", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });
  const { record } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId, nowMs: 1_000 });

  // Accept the revision-1 set once (records its stable authority binding).
  await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record, nowMs: 1_000 });

  // Produce a second FULLY VALID account/device-signed set at revision 1 that
  // rebinds the existing device to another inbox. Freshness is later too, but
  // the authority-content change is what must make this equivocation.
  alice.svc.inviteBinding = { mailboxId: "rez:inbox:alice-conflict", capabilityId: "rez:inbox:alice-conflict" };
  const conflictingRecord = (await alice.svc.buildDeviceSetRecordForPeer({
    peerAccountId: bob.accountId,
    nowMs: 2_000,
  })).record;
  await assert.rejects(
    () => bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record: conflictingRecord, nowMs: 2_000 }),
    (err) => err && err.code === "DEVICE_SET_REVISION_EQUIVOCATION" && err.revision === 1,
  );
});

test("device-set floor migration: a legacy signature floor accepts a refresh and anchors stable authority content", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });
  const { record } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });

  const floorKey = "peer-link:device-set-floor:" + bob.accountId + ":" + alice.accountId;
  // This is the exact floor shape shipped before stable authority bindings. Its
  // signature may differ from an honest timestamp refresh at the SAME revision;
  // upgrading must repair that state without forcing an IndexedDB/account wipe.
  await bob.sp.getKeyValueStore().set(floorKey, { revision: 1, sigB64: "legacy-signature" });

  // The genuine set is accepted and the legacy signature is replaced by the
  // stable authority-content binding (monotonic: revision remains unchanged).
  const ok = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record });
  assert.equal(ok.revision, 1);
  const backfilled = await bob.sp.getKeyValueStore().get(floorKey);
  assert.equal(backfilled.revision, 1, "floor stays at the same revision (monotonic)");
  assert.equal(typeof backfilled.binding, "string");
  assert.ok(backfilled.binding.length > 0, "the verified authority content is anchored on the legacy floor");
  assert.equal(Object.hasOwn(backfilled, "sigB64"), false, "the incompatible signature binding is removed");

  // Once migrated, conflicting same-revision authority content is rejected.
  await bob.sp.getKeyValueStore().set(floorKey, { revision: 1, binding: "conflicting-authority-content" });
  await assert.rejects(
    () => bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record }),
    (err) => err && err.code === "DEVICE_SET_REVISION_EQUIVOCATION" && err.revision === 1,
  );
});

test("device-set refresh: new timestamps and signature at the same revision preserve the authority binding", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });

  const firstRecord = (await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId, nowMs: 1_000 })).record;
  const first = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record: firstRecord, nowMs: 1_000 });
  assert.equal(first.established.length, 1);

  const floorKey = "peer-link:device-set-floor:" + bob.accountId + ":" + alice.accountId;
  const firstFloor = await bob.sp.getKeyValueStore().get(floorKey);
  const refreshedRecord = (await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId, nowMs: 2_000 })).record;
  const refreshed = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record: refreshedRecord, nowMs: 2_000 });
  const refreshedFloor = await bob.sp.getKeyValueStore().get(floorKey);

  assert.notEqual(firstRecord.sigB64, refreshedRecord.sigB64, "the refreshed durable record is genuinely re-signed");
  assert.equal(refreshed.revision, 1);
  assert.equal(refreshed.established.length, 0, "the existing device session is not reset");
  assert.equal(refreshed.reused.length, 1);
  assert.equal(refreshedFloor.binding, firstFloor.binding, "freshness changes do not change authority content");
});

test("Audit R4 #3: concurrent ingests of one set serialize — exactly one establishment, floor consistent", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });
  const { record } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });

  // Without the per-(owner,peer) lock both ingests would see no existing session
  // and double-establish (clobbering the first). The lock serializes them.
  const results = await Promise.all([
    bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record }),
    bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record }),
  ]);
  const establishedTotal = results.reduce((n, r) => n + r.established.length, 0);
  assert.equal(establishedTotal, 1, "the device session is established exactly once across concurrent ingests");
  const floorKey = "peer-link:device-set-floor:" + bob.accountId + ":" + alice.accountId;
  const storedFloor = await bob.sp.getKeyValueStore().get(floorKey);
  assert.equal(storedFloor.revision, 1, "the floor settles at the accepted revision with no regression");
});

test("Audit R3 #5: the DURABLE floor rejects a rolled-back set even when the caller passes minRevision 0 (sender restart)", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });
  const { record } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });

  // Simulate a PRIOR acceptance of a higher revision (5). The chat-side resolve
  // cache that supplies minRevision resets to 0 on restart — but the durable
  // floor persists, so a replayed revision-1 set must still be refused.
  const floorKey = "peer-link:device-set-floor:" + bob.accountId + ":" + alice.accountId;
  await bob.sp.getKeyValueStore().set(floorKey, { revision: 5 });

  await assert.rejects(
    // Note: minRevision omitted (defaults 0) — the post-restart caller.
    () => bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record }),
    (err) => err && err.code === "DEVICE_SET_STALE_REVISION" && err.revision === 1 && err.knownRevision === 5,
  );
});

// ── S8 L5: delegated publish → service ingest (V3/V4 through PeerLinkService) ──

// Hand-build a DELEGATED device-set record for `from` sealed to `to`: open the
// direct record's payload (static-static seal — the harness holds `from`'s dh
// priv), re-sign the inner set with a fresh delegated device key C2 at
// `revision`, and wrap it in a C2-signed V2 envelope carrying a B→C2 chain.
// The device LIST (and its C1-signed prekey bundle) is unchanged — real X3DH
// material, so session establishment still works.
async function buildDelegatedRecordFrom(crypto, from, to, { revision } = {}) {
  const direct = await from.svc.buildDeviceSetRecordForPeer({ peerAccountId: to.accountId });
  const { aeadKey } = await derivePeerScopedKey({
    cryptoProvider: crypto,
    myIdentityDhPrivateKeyB64: from.identityDhPrivB64,
    peerIdentityDhPublicKeyB64: to.identityDhPubB64,
  });
  const envelope = JSON.parse(dec(Buffer.from(direct.record.payloadB64, "base64")));
  const plaintext = await openFromPeer({
    cryptoProvider: crypto,
    aeadKey,
    nonceB64: envelope.nonceB64,
    ciphertextB64: envelope.ciphertextB64,
    aad: "rez:device-set:v1",
  });
  const inner = JSON.parse(dec(plaintext));

  // A delegated device key C2, granted deviceSet.publish by the account B key.
  const kp = await crypto.generateSigningKeyPair();
  const c2PubB64 = bytesToBase64(kp.publicKey);
  const certFields = {
    v: 1,
    purpose: ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
    accountIdentityPublicKeyB64: from.accountPubB64,
    parentCertId: null,
    granteeDevicePublicKeyB64: c2PubB64,
    granteeDeviceId: DeviceRegistrationV1.deviceIdFor(c2PubB64),
    capabilities: [DEVICE_SET_PUBLISH_CAPABILITY],
    maxDelegationDepth: 0,
    issuedAtMs: 0,
    expiresAtMs: FAR_FUTURE,
    signerPublicKeyB64: from.accountPubB64,
  };
  const certId = AccountDeviceCapabilityV1.deriveCertId(certFields);
  const certSig = await crypto.sign({ privateKey: from.accountPrivBytes, msg: AccountDeviceCapabilityV1.signableBytes({ ...certFields, certId }) });
  const leaf = new AccountDeviceCapabilityV1({ ...certFields, certId, sig: { alg: "ed25519", sigB64: bytesToBase64(certSig) } });

  // Re-sign the inner set with C2 at the requested revision (same-signer binding).
  const setBody = { ...inner.deviceSet, revision };
  delete setBody.sig;
  const setSig = await crypto.sign({ privateKey: kp.privateKey, msg: DeviceSetRecordV1.signableBytes(setBody) });
  const deviceSetRecord = new DeviceSetRecordV1({ ...setBody, sig: { alg: "ed25519", sigB64: bytesToBase64(setSig) } });
  const prekeyBundleRecords = inner.prekeyBundles.map((j) => DevicePrekeyBundleV1.fromJSON(j));

  const { record } = await buildSealedDeviceSetRecord({
    cryptoProvider: crypto,
    accountPublicKeyB64: from.accountPubB64,
    signerSign: async (bytes) => crypto.sign({ privateKey: kp.privateKey, msg: bytes }),
    signerPublicKeyB64: c2PubB64,
    certChain: [leaf],
    myIdentityDhPrivateKeyB64: from.identityDhPrivB64,
    peerIdentityDhPublicKeyB64: to.identityDhPubB64,
    deviceSetRecord,
    prekeyBundleRecords,
    nowMs: 1,
    ttlMs: FAR_FUTURE,
  });
  return { record };
}

test("S8 L5: a DELEGATED device-set record (C2-signed, B→C2 chain) ingests through the service and advances the floor", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });

  // Bob first ingests Alice's DIRECT revision-1 set (the shipped path).
  const { record: directRecord } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });
  const first = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record: directRecord });
  assert.equal(first.established.length, 1);

  // Alice's delegated device republishes at revision 2 (same device list).
  const { record } = await buildDelegatedRecordFrom(crypto, alice, bob, { revision: 2 });
  assert.equal(record.v, 2);
  assert.notEqual(record.signerPublicKeyB64, alice.accountPubB64, "envelope signed by the delegated key, not B");
  const second = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record });
  assert.equal(second.revision, 2);
  assert.equal(second.established.length, 0, "unchanged device list: no re-establishment");
  assert.equal(second.reused.length, 1, "the existing device session is reused");

  const floorKey = "peer-link:device-set-floor:" + bob.accountId + ":" + alice.accountId;
  const storedFloor = await bob.sp.getKeyValueStore().get(floorKey);
  assert.equal(storedFloor.revision, 2, "the delegated set advances the durable floor");
});

test("S8 L5: a delegated refresh with unchanged authority content is accepted at the same revision", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccount(crypto, { mailboxId: "rez:inbox:alice" });
  const bob = await makeAccount(crypto, { mailboxId: "rez:inbox:bob" });
  await crossLink(alice, bob, { aLinkId: "pl_alice_bob", bLinkId: "pl_bob_alice" });

  const { record: directRecord } = await alice.svc.buildDeviceSetRecordForPeer({ peerAccountId: bob.accountId });
  await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record: directRecord });

  // Same revision and device list, but freshly signed by an authorized delegated
  // key. Signer/timestamp rotation is not an authority change; the stable device
  // membership remains identical and the existing session must be reused.
  const { record } = await buildDelegatedRecordFrom(crypto, alice, bob, { revision: 1 });
  const refreshed = await bob.svc.ingestPeerDeviceSet({ peerAccountId: alice.accountId, record });
  assert.equal(refreshed.revision, 1);
  assert.equal(refreshed.established.length, 0);
  assert.equal(refreshed.reused.length, 1);
});
