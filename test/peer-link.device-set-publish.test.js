import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { bytesToBase64, DeviceRegistrationV1, DeviceSetRecordV1, DevicePrekeyBundleV1 } from "@rezprotocol/core";
// REAL crypto — static-static X25519 + AES-GCM + Ed25519 via WebCrypto.
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";
import { buildSealedDeviceSetRecord, openSealedDeviceSetRecord } from "../src/peer-link/deviceSetPublish.js";

const NOW = 1_770_000_000_000;
const TTL = 7 * 24 * 60 * 60 * 1000;

function b64(n) {
  return Buffer.from(crypto.randomBytes(n)).toString("base64");
}

// An account = an Ed25519 signing identity (B) + a stable X25519 identity-DH key.
async function makeAccount(c) {
  const sign = await c.generateSigningKeyPair();
  const dh = await c.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
  return {
    pubB64: bytesToBase64(sign.publicKey),
    privBytes: sign.privateKey,
    dhPubB64: bytesToBase64(dh.publicKey),
    dhPrivB64: bytesToBase64(dh.privateKey),
  };
}

async function makeDeviceKey(c) {
  const kp = await c.generateSigningKeyPair();
  return { pubB64: bytesToBase64(kp.publicKey), privBytes: kp.privateKey };
}

function signerFor(c, privBytes) {
  return async (bytes) => c.sign({ privateKey: privBytes, msg: bytes });
}

async function edSig(c, privBytes, bytes) {
  return { alg: "ed25519", sigB64: bytesToBase64(await c.sign({ privateKey: privBytes, msg: bytes })) };
}

// Build a one-device, account-signed device set + the device's C-signed prekey bundle.
async function buildPublisherRecords(c, account, device, { inboxId = "rez:inbox:dev0", revision = 1 } = {}) {
  const deviceId = DeviceRegistrationV1.deviceIdFor(device.pubB64);
  const setBody = {
    v: 1,
    purpose: "rez:device-set:v1",
    accountIdentityPublicKeyB64: account.pubB64,
    revision,
    devices: [{ deviceId, devicePublicKeyB64: device.pubB64, inboxId }],
    issuedAtMs: NOW,
    expiresAtMs: NOW + TTL,
  };
  const deviceSetRecord = new DeviceSetRecordV1({ ...setBody, sig: await edSig(c, account.privBytes, DeviceSetRecordV1.signableBytes(setBody)) });

  const bundleBody = {
    v: 1,
    purpose: "rez:device-prekey-bundle:v1",
    accountIdentityPublicKeyB64: account.pubB64,
    devicePublicKeyB64: device.pubB64,
    deviceId,
    inboxId,
    prekeyVersion: 1,
    bundleJson: {
      receiverId: "rez:acct:peer",
      identitySigningPublicKeyB64: device.pubB64,
      identityDhPublicKeyB64: b64(44),
      identityDhSignatureB64: b64(64),
      signedPreKeyPublicB64: b64(44),
      signedPreKeySignatureB64: b64(64),
      accountIdentityPublicKeyB64: null,
      accountBindingSigB64: null,
      accountBindingIssuedAtMs: null,
      accountBindingExpiresAtMs: null,
      oneTimePreKeyPublicB64: b64(44),
    },
    issuedAtMs: NOW,
    expiresAtMs: NOW + TTL,
  };
  const prekeyBundle = new DevicePrekeyBundleV1({ ...bundleBody, sig: await edSig(c, device.privBytes, DevicePrekeyBundleV1.signableBytes(bundleBody)) });
  return { deviceSetRecord, prekeyBundleRecords: [prekeyBundle] };
}

async function publish(c, publisher, peer, records, overrides = {}) {
  return buildSealedDeviceSetRecord({
    cryptoProvider: c,
    accountSign: signerFor(c, publisher.privBytes),
    accountPublicKeyB64: publisher.pubB64,
    myIdentityDhPrivateKeyB64: publisher.dhPrivB64,
    peerIdentityDhPublicKeyB64: peer.dhPubB64,
    deviceSetRecord: records.deviceSetRecord,
    prekeyBundleRecords: records.prekeyBundleRecords,
    nowMs: NOW,
    ttlMs: TTL,
    ...overrides,
  });
}

function resolveOpts(c, peer, publisher, overrides = {}) {
  return {
    cryptoProvider: c,
    myIdentityDhPrivateKeyB64: peer.dhPrivB64,
    peerIdentityDhPublicKeyB64: publisher.dhPubB64,
    peerAccountPublicKeyB64: publisher.pubB64,
    nowMs: NOW,
    ...overrides,
  };
}

test("device set seals to a peer and resolves: round-trip with full verification", async () => {
  const c = new BrowserCryptoProvider();
  const pub = await makeAccount(c);
  const peer = await makeAccount(c);
  const device = await makeDeviceKey(c);
  const records = await buildPublisherRecords(c, pub, device);

  const { record, slotRecordId } = await publish(c, pub, peer, records);
  assert.match(slotRecordId, /^[0-9a-f]{32}$/);
  assert.equal(record.recordId, slotRecordId);
  assert.equal(record.publisherPublicKeyB64, pub.pubB64);

  const resolved = await openSealedDeviceSetRecord({ ...resolveOpts(c, peer, pub), record });
  assert.equal(resolved.deviceSetRecord.devices.length, 1);
  assert.equal(resolved.deviceSetRecord.devices[0].devicePublicKeyB64, device.pubB64);
  assert.equal(resolved.prekeyBundleRecords.length, 1);
  assert.equal(resolved.prekeyBundleRecords[0].deviceId, DeviceRegistrationV1.deviceIdFor(device.pubB64));
});

test("commutative slot: peer independently derives the same slot the publisher used", async () => {
  const c = new BrowserCryptoProvider();
  const pub = await makeAccount(c);
  const peer = await makeAccount(c);
  const device = await makeDeviceKey(c);
  const { record, slotRecordId } = await publish(c, pub, peer, await buildPublisherRecords(c, pub, device));
  // The peer resolves WITHOUT being told the slot — open recomputes it from its
  // own dh-priv + the publisher's dh-pub and checks record.recordId matches.
  const resolved = await openSealedDeviceSetRecord({ ...resolveOpts(c, peer, pub), record });
  assert.ok(resolved.deviceSetRecord);
  assert.equal(record.recordId, slotRecordId);
});

test("resolve is idempotent — re-opening the same record yields the same set (no ratchet side-effects)", async () => {
  const c = new BrowserCryptoProvider();
  const pub = await makeAccount(c);
  const peer = await makeAccount(c);
  const device = await makeDeviceKey(c);
  const { record } = await publish(c, pub, peer, await buildPublisherRecords(c, pub, device));
  const a = await openSealedDeviceSetRecord({ ...resolveOpts(c, peer, pub), record });
  const b = await openSealedDeviceSetRecord({ ...resolveOpts(c, peer, pub), record });
  assert.deepEqual(b.deviceSetRecord.toJSON(), a.deviceSetRecord.toJSON());
  assert.deepEqual(b.prekeyBundleRecords[0].toJSON(), a.prekeyBundleRecords[0].toJSON());
});

test("a non-peer cannot open (different identity-DH ⇒ wrong key AND wrong slot)", async () => {
  const c = new BrowserCryptoProvider();
  const pub = await makeAccount(c);
  const peer = await makeAccount(c);
  const evil = await makeAccount(c);
  const device = await makeDeviceKey(c);
  const { record } = await publish(c, pub, peer, await buildPublisherRecords(c, pub, device));
  // Eve uses her own dh-priv against the publisher's dh-pub: derives a different
  // slot, so the recordId check fails before decryption is even attempted.
  await assert.rejects(
    () => openSealedDeviceSetRecord({ ...resolveOpts(c, evil, pub), record }),
    /does not match the peer-derived slot/,
  );
});

test("E7 cap: a device set larger than maxDevices is rejected", async () => {
  const c = new BrowserCryptoProvider();
  const pub = await makeAccount(c);
  const peer = await makeAccount(c);
  const device = await makeDeviceKey(c);
  // A real over-cap: build a 2-device set, cap at 1.
  const d2 = await makeDeviceKey(c);
  const deviceId1 = DeviceRegistrationV1.deviceIdFor(device.pubB64);
  const deviceId2 = DeviceRegistrationV1.deviceIdFor(d2.pubB64);
  const setBody = {
    v: 1, purpose: "rez:device-set:v1", accountIdentityPublicKeyB64: pub.pubB64, revision: 1,
    devices: [
      { deviceId: deviceId1, devicePublicKeyB64: device.pubB64, inboxId: "rez:inbox:a" },
      { deviceId: deviceId2, devicePublicKeyB64: d2.pubB64, inboxId: "rez:inbox:b" },
    ],
    issuedAtMs: NOW, expiresAtMs: NOW + TTL,
  };
  const deviceSetRecord = new DeviceSetRecordV1({ ...setBody, sig: await edSig(c, pub.privBytes, DeviceSetRecordV1.signableBytes(setBody)) });
  const one = (await buildPublisherRecords(c, pub, device)).prekeyBundleRecords;
  const { record: bigRecord } = await publish(c, pub, peer, { deviceSetRecord, prekeyBundleRecords: one });
  await assert.rejects(
    () => openSealedDeviceSetRecord({ ...resolveOpts(c, peer, pub, { maxDevices: 1 }), record: bigRecord }),
    /exceeds maxDevices/,
  );
});

test("E7 stale: a device set past expiry is rejected", async () => {
  const c = new BrowserCryptoProvider();
  const pub = await makeAccount(c);
  const peer = await makeAccount(c);
  const device = await makeDeviceKey(c);
  const { record } = await publish(c, pub, peer, await buildPublisherRecords(c, pub, device));
  await assert.rejects(
    () => openSealedDeviceSetRecord({ ...resolveOpts(c, peer, pub, { nowMs: NOW + TTL + 1 }), record }),
    /stale|expired/,
  );
});

test("wrong publisher: a record published under a non-peer account is rejected", async () => {
  const c = new BrowserCryptoProvider();
  const pub = await makeAccount(c);
  const peer = await makeAccount(c);
  const other = await makeAccount(c);
  const device = await makeDeviceKey(c);
  const { record } = await publish(c, pub, peer, await buildPublisherRecords(c, pub, device));
  // Resolver expects the set to be published by `other`, but it's published by `pub`.
  await assert.rejects(
    () => openSealedDeviceSetRecord({ ...resolveOpts(c, peer, pub, { peerAccountPublicKeyB64: other.pubB64 }), record }),
    /publisher is not the peer account/,
  );
});

test("R4 #8 freshness: a device set issued too far in the future is rejected", async () => {
  const c = new BrowserCryptoProvider();
  const pub = await makeAccount(c);
  const peer = await makeAccount(c);
  const device = await makeDeviceKey(c);
  const deviceId = DeviceRegistrationV1.deviceIdFor(device.pubB64);
  const future = NOW + 10 * 60_000; // 10 min ahead, beyond the 5-min skew bound
  const setBody = {
    v: 1, purpose: "rez:device-set:v1", accountIdentityPublicKeyB64: pub.pubB64, revision: 1,
    devices: [{ deviceId, devicePublicKeyB64: device.pubB64, inboxId: "rez:inbox:dev0" }],
    issuedAtMs: future, expiresAtMs: future + TTL,
  };
  const deviceSetRecord = new DeviceSetRecordV1({ ...setBody, sig: await edSig(c, pub.privBytes, DeviceSetRecordV1.signableBytes(setBody)) });
  const prekeyBundleRecords = (await buildPublisherRecords(c, pub, device)).prekeyBundleRecords;
  const { record } = await publish(c, pub, peer, { deviceSetRecord, prekeyBundleRecords });
  await assert.rejects(
    () => openSealedDeviceSetRecord({ ...resolveOpts(c, peer, pub), record }),
    /issued too far in the future/,
  );
});

test("R4 #8 freshness: an independently-expired prekey bundle is rejected even when the set is fresh", async () => {
  const c = new BrowserCryptoProvider();
  const pub = await makeAccount(c);
  const peer = await makeAccount(c);
  const device = await makeDeviceKey(c);
  const deviceId = DeviceRegistrationV1.deviceIdFor(device.pubB64);
  // The set is fresh (NOW..NOW+TTL) but its bundle expired in the past — a set
  // can outlive a bundle, and a session must never establish on a dead prekey.
  const setBody = {
    v: 1, purpose: "rez:device-set:v1", accountIdentityPublicKeyB64: pub.pubB64, revision: 1,
    devices: [{ deviceId, devicePublicKeyB64: device.pubB64, inboxId: "rez:inbox:dev0" }],
    issuedAtMs: NOW, expiresAtMs: NOW + TTL,
  };
  const deviceSetRecord = new DeviceSetRecordV1({ ...setBody, sig: await edSig(c, pub.privBytes, DeviceSetRecordV1.signableBytes(setBody)) });
  const bundleBody = {
    v: 1, purpose: "rez:device-prekey-bundle:v1", accountIdentityPublicKeyB64: pub.pubB64,
    devicePublicKeyB64: device.pubB64, deviceId, inboxId: "rez:inbox:dev0", prekeyVersion: 1,
    bundleJson: {
      receiverId: "rez:acct:peer", identitySigningPublicKeyB64: device.pubB64,
      identityDhPublicKeyB64: b64(44), identityDhSignatureB64: b64(64),
      signedPreKeyPublicB64: b64(44), signedPreKeySignatureB64: b64(64),
      accountIdentityPublicKeyB64: null, accountBindingSigB64: null,
      accountBindingIssuedAtMs: null, accountBindingExpiresAtMs: null,
      oneTimePreKeyPublicB64: b64(44),
    },
    issuedAtMs: NOW - 2 * TTL, expiresAtMs: NOW - 1,
  };
  const prekeyBundle = new DevicePrekeyBundleV1({ ...bundleBody, sig: await edSig(c, device.privBytes, DevicePrekeyBundleV1.signableBytes(bundleBody)) });
  const { record } = await publish(c, pub, peer, { deviceSetRecord, prekeyBundleRecords: [prekeyBundle] });
  await assert.rejects(
    () => openSealedDeviceSetRecord({ ...resolveOpts(c, peer, pub), record }),
    /prekey bundle is stale/,
  );
});

test("R4 #8 completeness: a set declaring a device with no prekey bundle is rejected", async () => {
  const c = new BrowserCryptoProvider();
  const pub = await makeAccount(c);
  const peer = await makeAccount(c);
  const device = await makeDeviceKey(c);
  const d2 = await makeDeviceKey(c);
  const deviceId1 = DeviceRegistrationV1.deviceIdFor(device.pubB64);
  const deviceId2 = DeviceRegistrationV1.deviceIdFor(d2.pubB64);
  // Two declared devices, but only device1 ships a bundle — device2 would be
  // silently unestablishable. The resolver must fail closed, not fan out partial.
  const setBody = {
    v: 1, purpose: "rez:device-set:v1", accountIdentityPublicKeyB64: pub.pubB64, revision: 1,
    devices: [
      { deviceId: deviceId1, devicePublicKeyB64: device.pubB64, inboxId: "rez:inbox:a" },
      { deviceId: deviceId2, devicePublicKeyB64: d2.pubB64, inboxId: "rez:inbox:b" },
    ],
    issuedAtMs: NOW, expiresAtMs: NOW + TTL,
  };
  const deviceSetRecord = new DeviceSetRecordV1({ ...setBody, sig: await edSig(c, pub.privBytes, DeviceSetRecordV1.signableBytes(setBody)) });
  const one = (await buildPublisherRecords(c, pub, device, { inboxId: "rez:inbox:a" })).prekeyBundleRecords;
  const { record } = await publish(c, pub, peer, { deviceSetRecord, prekeyBundleRecords: one });
  await assert.rejects(
    () => openSealedDeviceSetRecord({ ...resolveOpts(c, peer, pub), record }),
    /no prekey bundle/,
  );
});
