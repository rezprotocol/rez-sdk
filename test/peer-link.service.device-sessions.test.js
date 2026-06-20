import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase64 } from "@rezprotocol/core";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService } from "../src/peer-link/PeerLinkService.js";
// REAL crypto — the cross-device non-decryption + no-cross-advance proofs need
// genuine AES-GCM auth (FakeCryptoProvider collapses first-message keys).
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

const OWNER = "rez:acct:owner";
const PEER = "rez:acct:peer";
const OWNER_DEV = "rez:dev:owner";
const DEV_A = "rez:dev:a";
const DEV_B = "rez:dev:b";
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

async function makeService(crypto, { ownerAccountId, deviceId, deviceKeyPair = null }) {
  const sp = makeStorageProvider();
  const dkp = deviceKeyPair || (deviceId ? await makeDeviceKey(crypto) : null);
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
  return { svc, sp };
}

// Establish a per-device session: ownerSvc (initiator) ↔ one peer device
// (responder), through the PeerLinkService surface.
async function establish(ownerSvc, peer, peerDeviceId) {
  const { bundleJson, preKeyState } = await peer.svc.buildDevicePreKeyBundle({ ownerAccountId: PEER });
  const { handshakeData } = await ownerSvc.establishInitiatorDeviceSession({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId, peerDeviceBundleJson: bundleJson,
  });
  await peer.svc.establishResponderDeviceSession({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: peer.link, peerDeviceId: OWNER_DEV, preKeyState, handshakeData,
  });
}

async function makeWorld() {
  const crypto = new BrowserCryptoProvider();
  const owner = await makeService(crypto, { ownerAccountId: OWNER, deviceId: OWNER_DEV });
  const devA = { ...(await makeService(crypto, { ownerAccountId: PEER, deviceId: DEV_A })), link: A_LINK };
  const devB = { ...(await makeService(crypto, { ownerAccountId: PEER, deviceId: DEV_B })), link: B_LINK };
  return { crypto, owner, devA, devB };
}

test("PeerLinkService: two peer devices establish independent sessions; each decrypts its own", async () => {
  const { owner, devA, devB } = await makeWorld();
  await establish(owner.svc, devA, DEV_A);
  await establish(owner.svc, devB, DEV_B);

  const { encryptedPacket: pktA } = await owner.svc.encryptDirectMessageForDevice({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_A, plaintextBytes: enc("for A"),
  });
  const gotA = await devA.svc.decryptFromDevice({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: A_LINK, peerDeviceId: OWNER_DEV, packetBytes: pktA.toBytes(),
  });
  assert.equal(dec(gotA.plaintextBytes), "for A");

  const { encryptedPacket: pktB } = await owner.svc.encryptDirectMessageForDevice({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_B, plaintextBytes: enc("for B"),
  });
  const gotB = await devB.svc.decryptFromDevice({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: B_LINK, peerDeviceId: OWNER_DEV, packetBytes: pktB.toBytes(),
  });
  assert.equal(dec(gotB.plaintextBytes), "for B");
});

test("PeerLinkService: a packet for device A does NOT decrypt on device B (distinct ratchets)", async () => {
  const { owner, devA, devB } = await makeWorld();
  await establish(owner.svc, devA, DEV_A);
  await establish(owner.svc, devB, DEV_B);

  const { encryptedPacket: pktA } = await owner.svc.encryptDirectMessageForDevice({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_A, plaintextBytes: enc("secret for A"),
  });
  await assert.rejects(
    () => devB.svc.decryptFromDevice({
      ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: B_LINK, peerDeviceId: OWNER_DEV, packetBytes: pktA.toBytes(),
    }),
    (err) => err && err.code === "DECRYPT_FAILED",
  );
});

test("PeerLinkService HEADLINE (no cross-advance): encrypting for device A leaves device B's snapshot byte-unchanged", async () => {
  const { owner, devA, devB } = await makeWorld();
  await establish(owner.svc, devA, DEV_A);
  await establish(owner.svc, devB, DEV_B);

  const before = (await owner.sp.peerLinkStorage.sessions.getByPeerLinkAndDevice(OWNER, MY_LINK, DEV_B)).ratchetSnapshot;
  for (let i = 0; i < 3; i++) {
    await owner.svc.encryptDirectMessageForDevice({
      ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_A, plaintextBytes: enc("msg " + i),
    });
  }
  const after = (await owner.sp.peerLinkStorage.sessions.getByPeerLinkAndDevice(OWNER, MY_LINK, DEV_B)).ratchetSnapshot;
  assert.deepEqual(after, before, "device B's ratchet must not advance when only device A is used");
});

test("PeerLinkService.decryptDirectMessageAnyPeer is device-aware (receive path)", async () => {
  const { owner, devA } = await makeWorld();
  await establish(owner.svc, devA, DEV_A);
  // Owner needs a peer-link row so anyPeer iterates this peer.
  await owner.sp.peerLinkStorage.peerLinks.create({ peerLinkId: MY_LINK, localAccountId: OWNER, peerAccountId: PEER, state: "session_established" });

  // Peer device A sends to owner over its device session.
  const { encryptedPacket } = await devA.svc.encryptDirectMessageForDevice({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: A_LINK, peerDeviceId: OWNER_DEV, plaintextBytes: enc("hello owner"),
  });
  const got = await owner.svc.decryptDirectMessageAnyPeer({ ownerAccountId: OWNER, packetBytes: encryptedPacket.toBytes() });
  assert.equal(dec(got.plaintextBytes), "hello owner");
  assert.equal(got.peerDeviceId, DEV_A, "anyPeer identifies the sending peer device");
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
    () => svc.encryptDirectMessageForDevice({ ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_A, plaintextBytes: enc("x") }),
    /no device key/,
  );
});
