import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase64, DeviceRegistrationV1 } from "@rezprotocol/core";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService } from "../src/peer-link/PeerLinkService.js";
// REAL crypto — the cross-device non-decryption + no-cross-advance proofs need
// genuine AES-GCM auth (FakeCryptoProvider collapses first-message keys).
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

const OWNER = "rez:acct:owner";
const PEER = "rez:acct:peer";
const MY_LINK = "pl_owner_peer";   // owner's link to the peer account
const A_LINK = "pl_a_owner";       // peer device A's link to owner
const B_LINK = "pl_b_owner";       // peer device B's link to owner

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);

// Minimal invite signer/verifier — the per-device session methods never touch
// them (they're for the invite path), but the constructor requires the pair.
const signer = { sign: async () => new Uint8Array([1]), getSignerRef: () => ({ kind: "test" }) };
const verifier = { verify: async () => true };

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
  // The device key (C) is an Ed25519 SPKI/PKCS8 pair — the keystore's format and
  // exactly what the cryptoProvider sign/verify expect.
  const kp = await crypto.generateSigningKeyPair();
  return { publicKeyB64: bytesToBase64(kp.publicKey), privateKeyB64: bytesToBase64(kp.privateKey) };
}

// A service's deviceId is the SELF-CERT id of its device key (sha256 of the SPKI
// pubkey) — exactly as production derives it. The responder authenticates the
// initiator's device key and rejects any other claimed id (Audit R2 #1), so the
// tests must use the real self-cert ids, not arbitrary labels.
async function makeService(crypto, { ownerAccountId, withDevice = true } = {}) {
  const sp = makeStorageProvider();
  const dkp = withDevice ? await makeDeviceKey(crypto) : null;
  const deviceId = dkp ? DeviceRegistrationV1.deviceIdFor(dkp.publicKeyB64) : null;
  const svc = new PeerLinkService({
    storageProvider: sp,
    clock: () => 1,
    ownerAccountId,
    signer,
    verifier,
    cryptoProvider: crypto,
    deviceKeyPair: dkp,
    deviceId,
  });
  return { svc, sp, deviceId };
}

// Establish a per-device session: ownerSvc (initiator) ↔ one peer device
// (responder), through the PeerLinkService surface. The responder's view of the
// initiator device is its real self-cert id (ownerSvc.deviceId).
async function establish(ownerSvc, peer, peerDeviceId) {
  const { bundleJson, preKeyState } = await peer.svc.buildDevicePreKeyBundle({ ownerAccountId: PEER });
  const { handshakeData } = await ownerSvc.establishInitiatorDeviceSession({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId, peerDeviceBundleJson: bundleJson,
  });
  await peer.svc.establishResponderDeviceSession({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: peer.link, peerDeviceId: ownerSvc.deviceId, preKeyState, handshakeData,
  });
}

async function makeWorld() {
  const crypto = new BrowserCryptoProvider();
  const owner = await makeService(crypto, { ownerAccountId: OWNER });
  const devA = { ...(await makeService(crypto, { ownerAccountId: PEER })), link: A_LINK };
  const devB = { ...(await makeService(crypto, { ownerAccountId: PEER })), link: B_LINK };
  return { crypto, owner, devA, devB };
}

test("PeerLinkService: two peer devices establish independent sessions; each decrypts its own", async () => {
  const { owner, devA, devB } = await makeWorld();
  await establish(owner.svc, devA, devA.deviceId);
  await establish(owner.svc, devB, devB.deviceId);

  const { encryptedPacket: pktA } = await owner.svc.encryptDirectMessageForDevice({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: devA.deviceId, plaintextBytes: enc("for A"),
  });
  const gotA = await devA.svc.decryptFromDevice({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: A_LINK, peerDeviceId: owner.deviceId, packetBytes: pktA.toBytes(),
  });
  assert.equal(dec(gotA.plaintextBytes), "for A");

  const { encryptedPacket: pktB } = await owner.svc.encryptDirectMessageForDevice({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: devB.deviceId, plaintextBytes: enc("for B"),
  });
  const gotB = await devB.svc.decryptFromDevice({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: B_LINK, peerDeviceId: owner.deviceId, packetBytes: pktB.toBytes(),
  });
  assert.equal(dec(gotB.plaintextBytes), "for B");
});

test("PeerLinkService: a packet for device A does NOT decrypt on device B (distinct ratchets)", async () => {
  const { owner, devA, devB } = await makeWorld();
  await establish(owner.svc, devA, devA.deviceId);
  await establish(owner.svc, devB, devB.deviceId);

  const { encryptedPacket: pktA } = await owner.svc.encryptDirectMessageForDevice({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: devA.deviceId, plaintextBytes: enc("secret for A"),
  });
  await assert.rejects(
    () => devB.svc.decryptFromDevice({
      ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: B_LINK, peerDeviceId: owner.deviceId, packetBytes: pktA.toBytes(),
    }),
    (err) => err && err.code === "DECRYPT_FAILED",
  );
});

test("PeerLinkService HEADLINE (no cross-advance): encrypting for device A leaves device B's snapshot byte-unchanged", async () => {
  const { owner, devA, devB } = await makeWorld();
  await establish(owner.svc, devA, devA.deviceId);
  await establish(owner.svc, devB, devB.deviceId);

  const before = (await owner.sp.peerLinkStorage.sessions.getByPeerLinkAndDevice(OWNER, MY_LINK, devB.deviceId)).ratchetSnapshot;
  for (let i = 0; i < 3; i++) {
    await owner.svc.encryptDirectMessageForDevice({
      ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: devA.deviceId, plaintextBytes: enc("msg " + i),
    });
  }
  const after = (await owner.sp.peerLinkStorage.sessions.getByPeerLinkAndDevice(OWNER, MY_LINK, devB.deviceId)).ratchetSnapshot;
  assert.deepEqual(after, before, "device B's ratchet must not advance when only device A is used");
});

test("PeerLinkService.decryptDirectMessageAnyPeer is device-aware (receive path)", async () => {
  const { owner, devA } = await makeWorld();
  await establish(owner.svc, devA, devA.deviceId);
  // Owner needs a peer-link row so anyPeer iterates this peer.
  await owner.sp.peerLinkStorage.peerLinks.create({ peerLinkId: MY_LINK, localAccountId: OWNER, peerAccountId: PEER, state: "session_established" });

  // Peer device A sends to owner over its device session.
  const { encryptedPacket } = await devA.svc.encryptDirectMessageForDevice({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: A_LINK, peerDeviceId: owner.deviceId, plaintextBytes: enc("hello owner"),
  });
  const got = await owner.svc.decryptDirectMessageAnyPeer({ ownerAccountId: OWNER, packetBytes: encryptedPacket.toBytes() });
  assert.equal(dec(got.plaintextBytes), "hello owner");
  assert.equal(got.peerDeviceId, devA.deviceId, "anyPeer identifies the sending peer device");
});

test("Audit R2 #1: the responder rejects a handshake whose claimed deviceId is not the authenticated device key", async () => {
  const { owner, devA } = await makeWorld();
  // Owner (initiator) runs X3DH against device A's bundle with owner's REAL device
  // key, but A is told the sender is some OTHER device id — a forgery.
  const { bundleJson, preKeyState } = await devA.svc.buildDevicePreKeyBundle({ ownerAccountId: PEER });
  const { handshakeData } = await owner.svc.establishInitiatorDeviceSession({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: devA.deviceId, peerDeviceBundleJson: bundleJson,
  });
  await assert.rejects(
    () => devA.svc.establishResponderDeviceSession({
      ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: A_LINK,
      peerDeviceId: "rez:dev:0000000000000000000000000000000000000000000000000000000000000000",
      preKeyState, handshakeData,
    }),
    (err) => err && err.code === "DEVICE_ID_MISMATCH",
  );
  // And no session was persisted for the forged id.
  const sess = await devA.sp.peerLinkStorage.sessions.getByPeerLinkAndDevice(
    PEER, A_LINK, "rez:dev:0000000000000000000000000000000000000000000000000000000000000000",
  );
  assert.ok(sess == null, "a forged-deviceId handshake persists no session");
});

test("PeerLinkService: per-device X3DH identity (DH key) is generated once and reused", async () => {
  const { owner } = await makeWorld();
  const first = await owner.svc._loadDeviceIdentity();
  const second = await owner.svc._loadDeviceIdentity();
  assert.deepEqual(second.identityDhKeyPair.publicKey, first.identityDhKeyPair.publicKey, "stable DH identity across calls");
  // The signing identity IS the device key (C), not a generated subkey.
  assert.equal(bytesToBase64(first.identityKeyPair.publicKey), owner.svc.devicePublicKeyB64);
});

test("PeerLinkService without a device key: per-device sessions are unavailable and fail loud", async () => {
  const crypto = new BrowserCryptoProvider();
  const sp = makeStorageProvider();
  const svc = new PeerLinkService({
    storageProvider: sp, clock: () => 1, ownerAccountId: OWNER, signer, verifier, cryptoProvider: crypto,
  });
  assert.equal(svc.hasDeviceSessions(), false);
  await assert.rejects(
    () => svc.encryptDirectMessageForDevice({ ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: "rez:dev:a", plaintextBytes: enc("x") }),
    /no device key/,
  );
});
