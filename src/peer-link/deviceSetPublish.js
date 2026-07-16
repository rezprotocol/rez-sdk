import {
  DeviceSetRecordV1,
  DevicePrekeyBundleV1,
  DEVICE_SET_RECORD_KIND,
  buildDurableRecordV2,
  durableRecordV2SignableBytes,
  verifyDurableRecordV2,
  bytesToBase64,
  base64ToBytes,
  CAP_DEVICE_SET_PUBLISH,
} from "@rezprotocol/core";
import { derivePeerScopedKey, sealToPeer, openFromPeer } from "./peerScopedSeal.js";

/**
 * deviceSetPublish — seal an account's device set TO a peer and publish it on the
 * durable-record overlay, plus the inverse (fetch → open → verify) (S2.5 Slice 3).
 *
 * The inner records (DeviceSetRecordV1 signed by the envelope signer, device-signed
 * DevicePrekeyBundleV1[]) are built+signed by the caller (PeerLinkService, which
 * holds the account B signer + this device's key C). This module is PURE
 * envelope crypto: it seals the inner records under the peer-scoped key, wraps
 * them in a DurableRecordV2 at the peer-derived slot, signs that with the
 * envelope signer, and on the way back verifies every signature + the
 * anti-misbinding slot before handing the validated records back for session
 * establishment.
 *
 * Signing is DUAL-MODE (S2.5 S8 L5):
 * - direct: the account B key is both owner and signer (the shipped path)
 * - delegated: a device key C signs, carrying an AccountDeviceCapabilityV1 cert
 *   chain C←…←B that must grant "deviceSet.publish"
 *
 * Privacy/security model:
 * - payload encrypted to the peer (static-static identity-DH; only the peer can open)
 * - slot = peer-derived coordinate (only the peer can locate the record)
 * - owner = the account B pubkey (anchors slot + identity in both modes)
 * - the outer sig binds the envelope to the SIGNER; the cert chain proves the
 *   signer's authority over the owner account (verifyDurableRecordV2)
 * - the inner DeviceSetRecordV1 must be signed by the SAME key that signs the
 *   envelope (same-signer binding: authority is proven ONCE by the envelope's
 *   chain, and the sealed payload is integrity-bound to the envelope). Any
 *   re-sign of the set — same or different signer — requires a revision bump,
 *   or the receiver's equivocation floor rejects it.
 * - each prekey bundle is independently C-signed — so a peer that opens the
 *   payload still verifies authenticity end-to-end, never trusting the
 *   (non-owner-gated) overlay.
 */

const SEAL_AAD = "rez:device-set:v1";

// The capability a delegated signer's cert chain must grant to publish a
// device-set record. Fixed per record kind (never caller-chosen — a
// caller-supplied capability would let a confused deputy stamp a weaker one).
// Stamped on every record, direct included: direct mode grants the full
// account capability set, so the stamp is uniformly enforceable.
// SSOT: sourced from rez-core's CAP_DEVICE_SET_PUBLISH (audit leaf-3c F6) — the
// authorization vocabulary has a single owner and cannot drift from the node.
export const DEVICE_SET_PUBLISH_CAPABILITY = CAP_DEVICE_SET_PUBLISH;

// A self-signed device set / bundle carries an attacker-chosen issuedAtMs. The
// resolver must not honor one stamped far in the future (it would otherwise win
// every monotonic ordering against honest later publishes). Bound the lead to a
// few minutes of honest clock skew — mirrors the node's verifyDurableRecord.
const DEVICE_SET_MAX_FUTURE_SKEW_MS = 5 * 60_000;

/**
 * Build the signed, sealed DurableRecordV2 carrying an account's device set,
 * addressed to one peer.
 *
 * Direct mode (default): the account B key is owner AND signer; `accountSign`
 * signs. Delegated mode: pass ALL of `signerSign`/`signerPublicKeyB64`/
 * `certChain` — the device key C signs and the chain (which must grant
 * "deviceSet.publish") proves its authority; `accountSign` is not required
 * (a delegated device holds no B private key).
 *
 * @param {object} args
 * @param {object} args.cryptoProvider
 * @param {(bytes: Uint8Array) => Promise<Uint8Array>} [args.accountSign] — signs with the account B key (required in direct mode)
 * @param {string} args.accountPublicKeyB64 — the account B public key (durable OWNER in both modes)
 * @param {(bytes: Uint8Array) => Promise<Uint8Array>} [args.signerSign] — delegated: signs with the device key C
 * @param {string} [args.signerPublicKeyB64] — delegated: the device C public key
 * @param {object[]} [args.certChain] — delegated: AccountDeviceCapabilityV1 chain C←…←B
 * @param {string} args.myIdentityDhPrivateKeyB64 — my account identity-DH X25519 private (PKCS8 b64)
 * @param {string} args.peerIdentityDhPublicKeyB64 — peer account identity-DH X25519 public (SPKI b64)
 * @param {DeviceSetRecordV1} args.deviceSetRecord — already signed by the ENVELOPE signer (B direct / C delegated)
 * @param {DevicePrekeyBundleV1[]} args.prekeyBundleRecords — already C-signed (one per device)
 * @param {number} args.nowMs
 * @param {number} args.ttlMs
 * @returns {Promise<{ record: object, slotRecordId: string }>}
 */
export async function buildSealedDeviceSetRecord({
  cryptoProvider,
  accountSign,
  accountPublicKeyB64,
  signerSign = null,
  signerPublicKeyB64 = null,
  certChain = [],
  myIdentityDhPrivateKeyB64,
  peerIdentityDhPublicKeyB64,
  deviceSetRecord,
  prekeyBundleRecords,
  nowMs,
  ttlMs,
} = {}) {
  requireNonEmptyString(accountPublicKeyB64, "accountPublicKeyB64");
  const wantsDelegated = signerSign !== null
    || (typeof signerPublicKeyB64 === "string" && signerPublicKeyB64.length > 0)
    || (Array.isArray(certChain) && certChain.length > 0);
  if (wantsDelegated) {
    if (typeof signerSign !== "function") {
      throw new Error("buildSealedDeviceSetRecord delegated mode requires a signerSign(bytes) function");
    }
    requireNonEmptyString(signerPublicKeyB64, "signerPublicKeyB64");
    if (!Array.isArray(certChain) || certChain.length === 0) {
      throw new Error("buildSealedDeviceSetRecord delegated mode requires a non-empty certChain");
    }
  } else if (typeof accountSign !== "function") {
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

  const record = buildDurableRecordV2({
    recordKind: DEVICE_SET_RECORD_KIND,
    recordId: slotRecordId,
    ownerPublicKeyB64: accountPublicKeyB64,
    signerPublicKeyB64: wantsDelegated ? signerPublicKeyB64 : accountPublicKeyB64,
    certChain: wantsDelegated ? certChain : [],
    requiredCapability: DEVICE_SET_PUBLISH_CAPABILITY,
    payloadB64,
    issuedAtMs: nowMs,
    expiresAtMs: nowMs + ttlMs,
  });
  const sign = wantsDelegated ? signerSign : accountSign;
  const sigBytes = await sign(durableRecordV2SignableBytes(record));
  if (!(sigBytes instanceof Uint8Array) || sigBytes.length === 0) {
    throw new Error("buildSealedDeviceSetRecord: the envelope signer returned no signature");
  }
  record.sigB64 = bytesToBase64(sigBytes);
  return { record, slotRecordId };
}

/**
 * Open + fully verify a peer's sealed device-set DurableRecordV2, returning the
 * validated inner records. Throws (never returns partial) on any failure:
 * wrong owner, wrong/misbound slot, bad durable sig or cert-chain authority,
 * decrypt failure, a set not signed by the envelope signer, a bundle not signed
 * by its device, a bundle not present in the set, a stale (expired) set, or an
 * over-cap device count (E7).
 *
 * The envelope is verified by verifyDurableRecordV2 (sig against the SIGNER,
 * signer authority over the owner via the cert chain, time window); the inner
 * DeviceSetRecordV1 is then verified against that already-proven signer
 * (same-signer binding). `revocationState` (S2.5 S11) — the peer account's
 * `{ revokedCertIds, minValidIssuedAtMs }`, learned from its published
 * AccountAuthorityStateV1 — is fed to verifyDurableRecordV2 so a record signed by
 * a REVOKED device (or under a revoked ancestor cert) is rejected. Default null =
 * the pre-S11 primary path, byte-identical.
 *
 * @param {object} args
 * @param {object} args.cryptoProvider
 * @param {object} args.record — the fetched DurableRecordV2
 * @param {string} args.myIdentityDhPrivateKeyB64
 * @param {string} args.peerIdentityDhPublicKeyB64
 * @param {string} args.peerAccountPublicKeyB64 — peer account B pubkey (record OWNER + set authority root)
 * @param {number} args.nowMs
 * @param {number} [args.maxDevices=8] — E7 sender-side cap; reject oversized sets
 * @param {number} [args.maxFutureSkewMs] — reject sets/bundles issued beyond this lead
 * @param {object|null} [args.revocationState=null] — peer authority revocation projection
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
  maxFutureSkewMs = DEVICE_SET_MAX_FUTURE_SKEW_MS,
  revocationState = null,
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
  // Clean V1→V2 format bump (S8 L5): the device set is E6-gated machinery with
  // short-TTL records — no V1 record exists to grandfather. Fail loud.
  if (record.v !== 2) {
    throw new Error("openSealedDeviceSetRecord: record is not a DurableRecordV2");
  }
  // The owner MUST be the peer's account B key (anti-impersonation: a record
  // owned by any other account is not the peer's device set).
  if (String(record.ownerPublicKeyB64) !== peerAccountPublicKeyB64) {
    throw new Error("openSealedDeviceSetRecord: owner is not the peer account identity");
  }

  // Verify the durable envelope: signature against the SIGNER key, and the
  // signer's authority over the owner account (direct, or a cert chain granting
  // "deviceSet.publish") — defense-in-depth; the node also verifies on put/get.
  const outer = await verifyDurableRecordV2({ record, crypto: cryptoProvider, nowMs, revocationState });
  if (!outer.ok) {
    throw new Error("openSealedDeviceSetRecord: durable record verification failed (" + outer.reason + ")");
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
  // Same-signer binding: the inner set must be signed by the SAME key that
  // signed the (already authority-verified) envelope. Direct mode this is the
  // account B key exactly as before; delegated mode it is the proven device C.
  const setSigOk = await cryptoProvider.verify({
    publicKey: base64ToBytes(outer.signerPublicKeyB64),
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
  // Freshness (Audit R4 #8): reject a set issued beyond honest clock skew — a
  // far-future stamp would win monotonic ordering against legitimate later sets.
  if (Number.isFinite(maxFutureSkewMs) && deviceSetRecord.issuedAtMs > nowMs + maxFutureSkewMs) {
    throw new Error("openSealedDeviceSetRecord: device set is issued too far in the future");
  }

  const setByDeviceId = new Map();
  for (const d of deviceSetRecord.devices) {
    setByDeviceId.set(d.deviceId, d);
  }

  const rawBundles = Array.isArray(inner.prekeyBundles) ? inner.prekeyBundles : [];
  // E7 amplification bound (Audit P2): cap the bundle array and admit at most ONE
  // bundle per deviceId. The device cap bounds `devices.length`, but the bundle
  // array was unbounded — N DUPLICATE valid bundles for one device would each
  // drive a session establishment in the caller. Bound the count, then dedup.
  if (rawBundles.length > maxDevices) {
    throw new Error("openSealedDeviceSetRecord: prekey bundle array exceeds maxDevices (" + rawBundles.length + " > " + maxDevices + ")");
  }
  const prekeyBundleRecords = [];
  const seenBundleDeviceIds = new Set();
  for (const rawBundle of rawBundles) {
    const bundle = DevicePrekeyBundleV1.fromJSON(rawBundle);
    if (seenBundleDeviceIds.has(bundle.deviceId)) {
      throw new Error("openSealedDeviceSetRecord: duplicate prekey bundle for device (" + bundle.deviceId + ")");
    }
    seenBundleDeviceIds.add(bundle.deviceId);
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
    // Freshness (Audit R4 #8): each bundle expires INDEPENDENTLY of the set —
    // a set may be fresh while it still carries a long-stale (or far-future)
    // bundle. A session must never establish against an expired prekey bundle.
    if (bundle.expiresAtMs <= nowMs) {
      throw new Error("openSealedDeviceSetRecord: prekey bundle is stale (expired) for device (" + bundle.deviceId + ")");
    }
    if (Number.isFinite(maxFutureSkewMs) && bundle.issuedAtMs > nowMs + maxFutureSkewMs) {
      throw new Error("openSealedDeviceSetRecord: prekey bundle is issued too far in the future for device (" + bundle.deviceId + ")");
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

  // Completeness (Audit R4 #8): the account-signed set is the authority over
  // which devices exist; every declared device MUST ship a prekey bundle. A set
  // that declares a device but omits its bundle would otherwise leave that
  // device silently unestablishable — the sender fans out to a subset and the
  // missing device never receives mail, with no error. Fail closed instead.
  if (seenBundleDeviceIds.size !== setByDeviceId.size) {
    const missing = [];
    for (const deviceId of setByDeviceId.keys()) {
      if (!seenBundleDeviceIds.has(deviceId)) missing.push(deviceId);
    }
    throw new Error("openSealedDeviceSetRecord: device set declares devices with no prekey bundle (" + missing.join(",") + ")");
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
