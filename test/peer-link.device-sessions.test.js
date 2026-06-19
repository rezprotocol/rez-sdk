import test from "node:test";
import assert from "node:assert/strict";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { DevicePeerSessions } from "../src/peer-link/DevicePeerSessions.js";
// REAL crypto (Ed25519 / X25519 / AES-256-GCM via WebCrypto). The cross-device
// non-decryption proof needs genuine AES-GCM authentication — the deterministic
// FakeCryptoProvider collapses first-message keys across sessions, so it can
// prove a round-trip but NOT that a different session fails to decrypt.
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

function makeKvStore() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : undefined; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { return m.delete(k); },
    async keys(prefix) {
      const out = [];
      for (const k of m.keys()) {
        if (!prefix || k.startsWith(prefix)) out.push(k);
      }
      return out;
    },
  };
}

const OWNER = "rez:acct:owner";
const PEER = "rez:acct:peer";
const MY_DEVICE_ID = "rez:dev:me";
const DEV_A = "rez:dev:a";
const DEV_B = "rez:dev:b";
const MY_LINK = "pl_owner_to_peer";
const A_LINK = "pl_a_to_owner";
const B_LINK = "pl_b_to_owner";

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);

// One shared real-crypto provider across all sides (WebCrypto is stateless —
// every key is independently random). Each device gets its own X3DH identity
// (signing + DH) so the sessions are genuinely independent ratchets.
async function makeWorld() {
  const crypto = new BrowserCryptoProvider();
  const makeIdentity = async () => ({
    signing: await crypto.generateSigningKeyPair(),
    dh: await crypto.dhGenerateKeyPair(),
  });
  const mineStorage = createKeyValueBackedPeerLinkStorage({ keyValueStore: makeKvStore() });
  const mine = new DevicePeerSessions({ cryptoProvider: crypto, peerLinkStorage: mineStorage });
  // My device's own per-device X3DH identity (D-a).
  const myIdentity = await makeIdentity();

  // Each peer DEVICE is its own client (own storage), same peer account.
  async function makePeerDevice(deviceLink) {
    const storage = createKeyValueBackedPeerLinkStorage({ keyValueStore: makeKvStore() });
    const sessions = new DevicePeerSessions({ cryptoProvider: crypto, peerLinkStorage: storage });
    const identity = await makeIdentity();
    return {
      storage,
      sessions,
      deviceLink,
      signing: identity.signing,
      dh: identity.dh,
    };
  }

  // Establish a per-device session between my (initiator) side and one peer
  // device (responder). Both sides persist their per-device session.
  async function establish(peerDevice, peerDeviceId) {
    const { bundleJson, preKeyState } = await peerDevice.sessions.buildDevicePreKeyBundle({
      ownerAccountId: PEER,
      identityKeyPair: peerDevice.signing,
      identityDhKeyPair: peerDevice.dh,
    });
    const { handshakeData } = await mine.establishInitiatorDeviceSession({
      ownerAccountId: OWNER,
      peerAccountId: PEER,
      peerLinkId: MY_LINK,
      peerDeviceId,
      peerDeviceBundleJson: bundleJson,
      identityKeyPair: myIdentity.signing,
      identityDhKeyPair: myIdentity.dh,
    });
    await peerDevice.sessions.establishResponderDeviceSession({
      ownerAccountId: PEER,
      peerAccountId: OWNER,
      peerLinkId: peerDevice.deviceLink,
      peerDeviceId: MY_DEVICE_ID,
      identityDhKeyPair: peerDevice.dh,
      preKeyState,
      handshakeData,
    });
  }

  return { crypto, mine, mineStorage, makePeerDevice, establish };
}

test("each peer device establishes an independent session and decrypts its OWN ciphertext", async () => {
  const { mine, makePeerDevice, establish } = await makeWorld();
  const devA = await makePeerDevice(A_LINK);
  const devB = await makePeerDevice(B_LINK);
  await establish(devA, DEV_A);
  await establish(devB, DEV_B);

  const { encryptedPacket: pktA } = await mine.encryptForDevice({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_A, plaintextBytes: enc("for A"),
  });
  const gotA = await devA.sessions.trialDecryptAcrossDevices({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: A_LINK, packetBytes: pktA.toBytes(),
  });
  assert.ok(gotA, "device A decrypts its own packet");
  assert.equal(dec(gotA.plaintextBytes), "for A");
  assert.equal(gotA.peerDeviceId, MY_DEVICE_ID, "trial routing identifies the sender device");

  const { encryptedPacket: pktB } = await mine.encryptForDevice({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_B, plaintextBytes: enc("for B"),
  });
  const gotB = await devB.sessions.trialDecryptAcrossDevices({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: B_LINK, packetBytes: pktB.toBytes(),
  });
  assert.ok(gotB, "device B decrypts its own packet");
  assert.equal(dec(gotB.plaintextBytes), "for B");
});

test("a packet for device A does NOT decrypt on device B (distinct ratchets)", async () => {
  const { mine, makePeerDevice, establish } = await makeWorld();
  const devA = await makePeerDevice(A_LINK);
  const devB = await makePeerDevice(B_LINK);
  await establish(devA, DEV_A);
  await establish(devB, DEV_B);

  const { encryptedPacket: pktA } = await mine.encryptForDevice({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_A, plaintextBytes: enc("secret for A only"),
  });
  const onB = await devB.sessions.trialDecryptAcrossDevices({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: B_LINK, packetBytes: pktA.toBytes(),
  });
  assert.equal(onB, null, "device B cannot decrypt device A's ciphertext");
});

test("HEADLINE (no cross-advance): encrypting for device A leaves device B's snapshot byte-unchanged", async () => {
  const { mine, mineStorage, makePeerDevice, establish } = await makeWorld();
  const devA = await makePeerDevice(A_LINK);
  const devB = await makePeerDevice(B_LINK);
  await establish(devA, DEV_A);
  await establish(devB, DEV_B);

  const before = (await mineStorage.sessions.getByPeerLinkAndDevice(OWNER, MY_LINK, DEV_B)).ratchetSnapshot;
  // Advance device A's ratchet a few times.
  for (let i = 0; i < 3; i++) {
    await mine.encryptForDevice({
      ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_A, plaintextBytes: enc("msg " + i),
    });
  }
  const after = (await mineStorage.sessions.getByPeerLinkAndDevice(OWNER, MY_LINK, DEV_B)).ratchetSnapshot;
  assert.deepEqual(after, before, "device B's ratchet must not advance when only device A is used");
});

test("a failed trial-decrypt leaves the receiver's session byte-unchanged (no corruption)", async () => {
  const { mine, makePeerDevice, establish } = await makeWorld();
  const devA = await makePeerDevice(A_LINK);
  const devB = await makePeerDevice(B_LINK);
  await establish(devA, DEV_A);
  await establish(devB, DEV_B);

  const beforeList = await devB.storage.sessions.listByPeerLink(PEER, B_LINK);
  const before = beforeList[0].ratchetSnapshot;

  const { encryptedPacket: pktA } = await mine.encryptForDevice({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_A, plaintextBytes: enc("not for B"),
  });
  const onB = await devB.sessions.trialDecryptAcrossDevices({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: B_LINK, packetBytes: pktA.toBytes(),
  });
  assert.equal(onB, null);

  const afterList = await devB.storage.sessions.listByPeerLink(PEER, B_LINK);
  assert.deepEqual(afterList[0].ratchetSnapshot, before, "a failed trial must not mutate the session");
});

test("decryptFromDevice round-trips and rejects a foreign packet with DECRYPT_FAILED", async () => {
  const { mine, makePeerDevice, establish } = await makeWorld();
  const devA = await makePeerDevice(A_LINK);
  const devB = await makePeerDevice(B_LINK);
  await establish(devA, DEV_A);
  await establish(devB, DEV_B);

  const { encryptedPacket: pktA } = await mine.encryptForDevice({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_A, plaintextBytes: enc("hi A"),
  });
  const got = await devA.sessions.decryptFromDevice({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: A_LINK, peerDeviceId: MY_DEVICE_ID, packetBytes: pktA.toBytes(),
  });
  assert.equal(dec(got.plaintextBytes), "hi A");

  const { encryptedPacket: pktA2 } = await mine.encryptForDevice({
    ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_A, plaintextBytes: enc("also A"),
  });
  await assert.rejects(
    () => devB.sessions.decryptFromDevice({
      ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: B_LINK, peerDeviceId: MY_DEVICE_ID, packetBytes: pktA2.toBytes(),
    }),
    (err) => err && err.code === "DECRYPT_FAILED",
  );
});

test("P1.4: concurrent encryptForDevice on one device session never clobbers the ratchet", async () => {
  const { mine, makePeerDevice, establish } = await makeWorld();
  const devA = await makePeerDevice(A_LINK);
  await establish(devA, DEV_A);

  // Two sends fired CONCURRENTLY for the SAME device session. Without the
  // per-session lock both would advance off the same snapshot (same ratchet
  // step → key/nonce reuse, and last-write-wins drops one advance).
  const [r1, r2] = await Promise.all([
    mine.encryptForDevice({ ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_A, plaintextBytes: enc("first") }),
    mine.encryptForDevice({ ownerAccountId: OWNER, peerAccountId: PEER, peerLinkId: MY_LINK, peerDeviceId: DEV_A, plaintextBytes: enc("second") }),
  ]);

  // BOTH ciphertexts must independently decrypt on the peer (distinct steps).
  const got1 = await devA.sessions.trialDecryptAcrossDevices({ ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: A_LINK, packetBytes: r1.encryptedPacket.toBytes() });
  const got2 = await devA.sessions.trialDecryptAcrossDevices({ ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: A_LINK, packetBytes: r2.encryptedPacket.toBytes() });
  assert.ok(got1 && got2, "both concurrent sends decrypt");
  assert.deepEqual([dec(got1.plaintextBytes), dec(got2.plaintextBytes)].sort(), ["first", "second"]);
});

test("P2: re-establishing a device reuses its session record (no stale-session accumulation)", async () => {
  const { mine, mineStorage, makePeerDevice, establish } = await makeWorld();
  const devA = await makePeerDevice(A_LINK);
  await establish(devA, DEV_A);
  const firstId = (await mineStorage.sessions.getByPeerLinkAndDevice(OWNER, MY_LINK, DEV_A)).sessionId;

  // Peer rotates its bundle / link recovers → re-establish the same device.
  await establish(devA, DEV_A);

  const list = await mineStorage.sessions.listByPeerLink(OWNER, MY_LINK);
  assert.equal(list.length, 1, "exactly one session record per device after re-establish");
  assert.equal(list[0].sessionId, firstId, "sessionId is reused, old ratchet not left dangling");
});

test("P2: a malformed packet surfaces (throws) instead of being silently dropped as no-match", async () => {
  const { makePeerDevice, mine, establish } = await makeWorld();
  const devA = await makePeerDevice(A_LINK);
  await establish(devA, DEV_A);
  // Structurally-corrupt encrypted packet (truthy non-string payload) — the
  // codec's record parse throws; the device layer must NOT swallow it as a
  // benign "wrong device" non-match.
  const malformed = enc(JSON.stringify({ e2ee: 1, v: 1, payload: 123 }));
  await assert.rejects(() => devA.sessions.trialDecryptAcrossDevices({
    ownerAccountId: PEER, peerAccountId: OWNER, peerLinkId: A_LINK, packetBytes: malformed,
  }));
});
