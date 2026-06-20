import {
  DeviceSetRecordV1,
  DevicePrekeyBundleV1,
  DEVICE_SET_RECORD_KIND,
  buildDurableRecordV1,
  durableRecordSignableBytes,
  bytesToBase64,
  base64ToBytes,
} from "@rezprotocol/core";
import { derivePeerScopedKey, sealToPeer, openFromPeer } from "./peerScopedSeal.js";

/**
 * deviceSetPublish — seal an account's device set TO a peer and publish it on the
 * durable-record overlay, plus the inverse (fetch → open → verify) (S2.5 Slice 3).
 *
 * The inner records (account-signed DeviceSetRecordV1, device-signed
 * DevicePrekeyBundleV1[]) are built+signed by the caller (PeerLinkService, which
 * holds the account B signer + this device's key C). This module is PURE
 * envelope crypto: it seals the inner records under the peer-scoped key, wraps
 * them in a DurableRecordV1 at the peer-derived slot, signs that with the account
 * key, and on the way back verifies every signature + the anti-misbinding slot
 * before handing the validated records back for session establishment.
 *
 * Privacy/security model:
 * - payload encrypted to the peer (static-static identity-DH; only the peer can open)
 * - slot = peer-derived coordinate (only the peer can locate the record)
 * - publisher = the account B pubkey; the durable sig binds the envelope to B
 * - the inner DeviceSetRecordV1 is independently B-signed, and each prekey bundle
 *   is independently C-signed — so a peer that opens the payload still verifies
 *   authenticity end-to-end, never trusting the (non-owner-gated) overlay.
 */

const SEAL_AAD = "rez:device-set:v1";

/**
 * Build the signed, sealed DurableRecordV1 carrying an account's device set,
 * addressed to one peer.
 *
 * @param {object} args
 * @param {object} args.cryptoProvider
 * @param {(bytes: Uint8Array) => Promise<Uint8Array>} args.accountSign — signs with the account B key
 * @param {string} args.accountPublicKeyB64 — the account B public key (durable publisher)
 * @param {string} args.myIdentityDhPrivateKeyB64 — my account identity-DH X25519 private (PKCS8 b64)
 * @param {string} args.peerIdentityDhPublicKeyB64 — peer account identity-DH X25519 public (SPKI b64)
 * @param {DeviceSetRecordV1} args.deviceSetRecord — already B-signed
 * @param {DevicePrekeyBundleV1[]} args.prekeyBundleRecords — already C-signed (one per device)
 * @param {number} args.nowMs
 * @param {number} args.ttlMs
 * @returns {Promise<{ record: object, slotRecordId: string }>}
 */
export async function buildSealedDeviceSetRecord({
  cryptoProvider,
  accountSign,
  accountPublicKeyB64,
  myIdentityDhPrivateKeyB64,
  peerIdentityDhPublicKeyB64,
  deviceSetRecord,
  prekeyBundleRecords,
  nowMs,
  ttlMs,
} = {}) {
  requireNonEmptyString(accountPublicKeyB64, "accountPublicKeyB64");
  if (typeof accountSign !== "function") {
    throw new Error("buildSealedDeviceSetRecord requires an accountSign(bytes) function");
  }
  if (!(deviceSetRecord instanceof DeviceSetRecordV1)) {
    throw new Error("buildSealedDeviceSetRecord requires a DeviceSetRecordV1");
  }
  if (!Array.isArray(prekeyBundleRecords) || prekeyBundleRecords.length === 0) {
    throw new Error("buildSealedDeviceSetRecord requires at least one DevicePrekeyBundleV1");
  }
  for (const b of prekeyBundleRecords) {
    if (!(b instanceof DevicePrekeyBundleV1)) {
      throw new Error("buildSealedDeviceSetRecord prekeyBundleRecords must all be DevicePrekeyBundleV1");
    }
  }
  if (!isFiniteNumber(nowMs) || !isFiniteNumber(ttlMs) || ttlMs <= 0) {
    throw new Error("buildSealedDeviceSetRecord requires numeric nowMs and positive ttlMs");
  }

  const { aeadKey, slotRecordId } = await derivePeerScopedKey({
    cryptoProvider,
    myIdentityDhPrivateKeyB64,
    peerIdentityDhPublicKeyB64,
  });

  const innerJson = JSON.stringify({
    deviceSet: deviceSetRecord.toJSON(),
    prekeyBundles: prekeyBundleRecords.map((b) => b.toJSON()),
  });
  const sealed = await sealToPeer({
    cryptoProvider,
    aeadKey,
    plaintextBytes: new TextEncoder().encode(innerJson),
    aad: SEAL_AAD,
  });
  const payloadB64 = bytesToBase64(
    new TextEncoder().encode(JSON.stringify({ nonceB64: sealed.nonceB64, ciphertextB64: sealed.ciphertextB64 })),
  );

  const record = buildDurableRecordV1({
    recordKind: DEVICE_SET_RECORD_KIND,
    recordId: slotRecordId,
    publisherPublicKeyB64: accountPublicKeyB64,
    payloadB64,
    issuedAtMs: nowMs,
    expiresAtMs: nowMs + ttlMs,
  });
  const sigBytes = await accountSign(durableRecordSignableBytes(record));
  if (!(sigBytes instanceof Uint8Array) || sigBytes.length === 0) {
    throw new Error("buildSealedDeviceSetRecord: accountSign returned no signature");
  }
  record.sigB64 = bytesToBase64(sigBytes);
  return { record, slotRecordId };
}

/**
 * Open + fully verify a peer's sealed device-set DurableRecordV1, returning the
 * validated inner records. Throws (never returns partial) on any failure:
 * wrong publisher, wrong/misbound slot, bad durable sig, decrypt failure, a set
 * not signed by the peer's account, a bundle not signed by its device, a bundle
 * not present in the set, a stale (expired) set, or an over-cap device count (E7).
 *
 * @param {object} args
 * @param {object} args.cryptoProvider
 * @param {object} args.record — the fetched DurableRecordV1
 * @param {string} args.myIdentityDhPrivateKeyB64
 * @param {string} args.peerIdentityDhPublicKeyB64
 * @param {string} args.peerAccountPublicKeyB64 — peer account B pubkey (publisher + set signer)
 * @param {number} args.nowMs
 * @param {number} [args.maxDevices=8] — E7 sender-side cap; reject oversized sets
 * @returns {Promise<{ deviceSetRecord: DeviceSetRecordV1, prekeyBundleRecords: DevicePrekeyBundleV1[] }>}
 */
export async function openSealedDeviceSetRecord({
  cryptoProvider,
  record,
  myIdentityDhPrivateKeyB64,
  peerIdentityDhPublicKeyB64,
  peerAccountPublicKeyB64,
  nowMs,
  maxDevices = 8,
} = {}) {
  if (!record || typeof record !== "object") {
    throw new Error("openSealedDeviceSetRecord requires a record");
  }
  requireNonEmptyString(peerAccountPublicKeyB64, "peerAccountPublicKeyB64");
  if (!isFiniteNumber(nowMs)) {
    throw new Error("openSealedDeviceSetRecord requires numeric nowMs");
  }
  if (!Number.isInteger(maxDevices) || maxDevices < 1) {
    throw new Error("openSealedDeviceSetRecord requires a positive integer maxDevices");
  }
  if (String(record.recordKind) !== DEVICE_SET_RECORD_KIND) {
    throw new Error("openSealedDeviceSetRecord: record is not a device-set record");
  }
  // The publisher MUST be the peer's account B key (anti-impersonation: a record
  // published under any other key is not the peer's device set).
  if (String(record.publisherPublicKeyB64) !== peerAccountPublicKeyB64) {
    throw new Error("openSealedDeviceSetRecord: publisher is not the peer account identity");
  }

  // Verify the durable envelope signature against the peer's account key
  // (defense-in-depth; the node also verifies on put/get).
  const durableSigOk = await cryptoProvider.verify({
    publicKey: base64ToBytes(peerAccountPublicKeyB64),
    msg: durableRecordSignableBytes(record),
    sig: base64ToBytes(requireNonEmptyString(record.sigB64, "record.sigB64")),
  });
  if (!durableSigOk) {
    throw new Error("openSealedDeviceSetRecord: durable record signature failed");
  }

  const { aeadKey, slotRecordId } = await derivePeerScopedKey({
    cryptoProvider,
    myIdentityDhPrivateKeyB64,
    peerIdentityDhPublicKeyB64,
  });
  // Anti-misbinding: the slot MUST be the peer-derived coordinate. A record at any
  // other recordId is not the device set sealed to ME by this peer.
  if (String(record.recordId) !== slotRecordId) {
    throw new Error("openSealedDeviceSetRecord: recordId does not match the peer-derived slot");
  }

  const envelope = parseJsonObject(decodeB64Utf8(record.payloadB64), "device-set payload");
  const plaintext = await openFromPeer({
    cryptoProvider,
    aeadKey,
    nonceB64: requireNonEmptyString(envelope.nonceB64, "payload.nonceB64"),
    ciphertextB64: requireNonEmptyString(envelope.ciphertextB64, "payload.ciphertextB64"),
    aad: SEAL_AAD,
  });
  const inner = parseJsonObject(new TextDecoder().decode(plaintext), "device-set plaintext");

  // Reconstruct + structurally validate the inner records (constructors validate).
  const deviceSetRecord = DeviceSetRecordV1.fromJSON(inner.deviceSet);
  // The set must be authentically the peer's account-level claim.
  if (deviceSetRecord.accountIdentityPublicKeyB64 !== peerAccountPublicKeyB64) {
    throw new Error("openSealedDeviceSetRecord: device set is not the peer account's");
  }
  const setSigOk = await cryptoProvider.verify({
    publicKey: base64ToBytes(peerAccountPublicKeyB64),
    msg: DeviceSetRecordV1.signableBytes(deviceSetRecord.toJSON()),
    sig: base64ToBytes(deviceSetRecord.sig.sigB64),
  });
  if (!setSigOk) {
    throw new Error("openSealedDeviceSetRecord: device set signature failed");
  }
  // E7 sender-side caps: reject oversized or stale sets so a bloated/expired
  // recipient list can't force N encryptions + N deposits per message.
  if (deviceSetRecord.devices.length > maxDevices) {
    throw new Error("openSealedDeviceSetRecord: device set exceeds maxDevices (" + deviceSetRecord.devices.length + " > " + maxDevices + ")");
  }
  if (deviceSetRecord.expiresAtMs <= nowMs) {
    throw new Error("openSealedDeviceSetRecord: device set is stale (expired)");
  }

  const setByDeviceId = new Map();
  for (const d of deviceSetRecord.devices) {
    setByDeviceId.set(d.deviceId, d);
  }

  const rawBundles = Array.isArray(inner.prekeyBundles) ? inner.prekeyBundles : [];
  const prekeyBundleRecords = [];
  for (const rawBundle of rawBundles) {
    const bundle = DevicePrekeyBundleV1.fromJSON(rawBundle);
    // Every bundle MUST correspond to a device the account vouches for, with
    // matching key + inbox — the account-signed set is the authority over which
    // (device, inbox) pairs exist; the bundle only adds the device-signed prekeys.
    const entry = setByDeviceId.get(bundle.deviceId);
    if (!entry) {
      throw new Error("openSealedDeviceSetRecord: prekey bundle for a device not in the set (" + bundle.deviceId + ")");
    }
    if (bundle.devicePublicKeyB64 !== entry.devicePublicKeyB64) {
      throw new Error("openSealedDeviceSetRecord: prekey bundle device key disagrees with the set");
    }
    if (bundle.inboxId !== entry.inboxId) {
      throw new Error("openSealedDeviceSetRecord: prekey bundle inbox disagrees with the set");
    }
    if (bundle.accountIdentityPublicKeyB64 !== peerAccountPublicKeyB64) {
      throw new Error("openSealedDeviceSetRecord: prekey bundle account does not match the peer");
    }
    const bundleSigOk = await cryptoProvider.verify({
      publicKey: base64ToBytes(bundle.devicePublicKeyB64),
      msg: DevicePrekeyBundleV1.signableBytes(bundle.toJSON()),
      sig: base64ToBytes(bundle.sig.sigB64),
    });
    if (!bundleSigOk) {
      throw new Error("openSealedDeviceSetRecord: prekey bundle signature failed (" + bundle.deviceId + ")");
    }
    prekeyBundleRecords.push(bundle);
  }

  return { deviceSetRecord, prekeyBundleRecords };
}

function requireNonEmptyString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("device-set publish requires " + label);
  }
  return value;
}

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function decodeB64Utf8(b64) {
  return new TextDecoder().decode(base64ToBytes(requireNonEmptyString(b64, "payloadB64")));
}

function parseJsonObject(text, label) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error("device-set " + label + " is not valid JSON: " + (err && err.message ? err.message : "unknown"));
  }
  if (!parsed || typeof parsed !== "object") {
    throw new Error("device-set " + label + " must be a JSON object");
  }
  return parsed;
}
