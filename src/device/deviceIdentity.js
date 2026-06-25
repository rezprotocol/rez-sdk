import {
  bytesToBase64,
  DeviceRegistrationV1,
  DEVICE_REGISTRATION_VERSION,
  DEVICE_REGISTRATION_PURPOSE,
  DeviceInboxBindingV1,
  DEVICE_INBOX_BINDING_VERSION,
  DEVICE_INBOX_BINDING_PURPOSE,
  DeviceRevokeV1,
  DEVICE_REVOKE_VERSION,
  DEVICE_REVOKE_PURPOSE,
  verifyDeviceRegistrationV1,
} from "@rezprotocol/core";
import { signPayload } from "../auth/signing.js";

/**
 * Device-identity primitive for multi-device E2EE (S2.5 Slice 0).
 *
 * A device gets its OWN Ed25519 keypair (SPKI/PKCS8 DER base64, matching the
 * account-key convention the SDK already uses for session auth). The account
 * identity key then signs a `DeviceRegistrationV1` that vouches for the device
 * key; the self-certifying `deviceId = rez:dev:sha256(devicePublicKeyB64)` is
 * carried inside the signed body. This is the device→account trust chain every
 * later slice (per-device ratchet sessions, prekey bundles, the home
 * device-inbox binding, the durable cursor) keys on.
 *
 * Pure + additive: this module generates/signs/verifies. Persisting the device
 * keypair into the keystore and exposing it on the SDK surface is a separate,
 * migration-sensitive step.
 */

const DEFAULT_TTL_MS = 365 * 24 * 60 * 60 * 1000; // 365 days

function requireSubtle() {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw Object.assign(new Error("WebCrypto unavailable"), { code: "BAD_CONFIG", retryable: false });
  }
  return globalThis.crypto.subtle;
}

/**
 * Generate a fresh per-device Ed25519 keypair, exported in the SDK's key
 * convention (SPKI public / PKCS8 private, base64).
 *
 * @returns {Promise<{ publicKeyB64: string, privateKeyB64: string }>}
 */
export async function generateDeviceKeyPair() {
  const subtle = requireSubtle();
  const keyPair = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const publicKeyBytes = new Uint8Array(await subtle.exportKey("spki", keyPair.publicKey));
  const privateKeyBytes = new Uint8Array(await subtle.exportKey("pkcs8", keyPair.privateKey));
  return {
    publicKeyB64: bytesToBase64(publicKeyBytes),
    privateKeyB64: bytesToBase64(privateKeyBytes),
  };
}

/**
 * Build a DeviceRegistrationV1 and sign it with the ACCOUNT identity key.
 *
 * `signPayload` canonicalizes the body with the exact same `canonicalJSONStringify`
 * that `DeviceRegistrationV1.signableBytes` uses, so the produced signature
 * verifies against the same bytes — no representation drift between signer and
 * verifier.
 *
 * @param {object} opts
 * @param {{ publicKeyB64: string, privateKeyB64: string }} opts.account — account identity keypair
 * @param {string} opts.devicePublicKeyB64 — the device public key being authorized
 * @param {number} [opts.nowMs] — issuedAtMs (defaults to Date.now())
 * @param {number} [opts.ttlMs] — lifetime; expiresAtMs = issuedAtMs + ttlMs
 * @returns {Promise<DeviceRegistrationV1>}
 */
export async function buildSignedDeviceRegistration({ account, devicePublicKeyB64, nowMs, ttlMs = DEFAULT_TTL_MS } = {}) {
  if (!account || typeof account.publicKeyB64 !== "string" || account.publicKeyB64.length === 0) {
    throw new Error("buildSignedDeviceRegistration requires account.publicKeyB64");
  }
  if (typeof account.privateKeyB64 !== "string" || account.privateKeyB64.length === 0) {
    throw new Error("buildSignedDeviceRegistration requires account.privateKeyB64");
  }
  if (typeof devicePublicKeyB64 !== "string" || devicePublicKeyB64.length === 0) {
    throw new Error("buildSignedDeviceRegistration requires devicePublicKeyB64");
  }
  const issuedAtMs = typeof nowMs === "number" && Number.isFinite(nowMs) ? nowMs : Date.now();
  const expiresAtMs = issuedAtMs + ttlMs;
  const body = {
    v: DEVICE_REGISTRATION_VERSION,
    purpose: DEVICE_REGISTRATION_PURPOSE,
    accountIdentityPublicKeyB64: account.publicKeyB64,
    devicePublicKeyB64,
    deviceId: DeviceRegistrationV1.deviceIdFor(devicePublicKeyB64),
    issuedAtMs,
    expiresAtMs,
  };
  const sigB64 = await signPayload({ privateKeyB64: account.privateKeyB64, payload: body });
  return new DeviceRegistrationV1({ ...body, sig: { alg: "ed25519", sigB64 } });
}

/**
 * Build a DeviceInboxBindingV1 and sign it with the DEVICE key (C) — the device
 * asserting the inbox it receives at. The device→account chain is established
 * separately by DeviceRegistrationV1 (account-signed); a verifier that needs the
 * full chain checks BOTH. `device.deviceId` is self-certifying and re-derived.
 *
 * `signPayload` canonicalizes the body with the same `canonicalJSONStringify`
 * that `DeviceInboxBindingV1.signableBytes` uses, so the signature verifies
 * against the same bytes the home recomputes — no representation drift.
 *
 * @param {object} opts
 * @param {{ publicKeyB64: string, privateKeyB64: string }} opts.device — this device's keypair (C)
 * @param {string} opts.inboxId — the inbox this device receives at
 * @param {number} [opts.nowMs] — issuedAtMs (defaults to Date.now())
 * @param {number} [opts.ttlMs] — lifetime; expiresAtMs = issuedAtMs + ttlMs
 * @returns {Promise<DeviceInboxBindingV1>}
 */
export async function buildSignedDeviceInboxBinding({ device, inboxId, nowMs, ttlMs = DEFAULT_TTL_MS } = {}) {
  if (!device || typeof device.publicKeyB64 !== "string" || device.publicKeyB64.length === 0) {
    throw new Error("buildSignedDeviceInboxBinding requires device.publicKeyB64");
  }
  if (typeof device.privateKeyB64 !== "string" || device.privateKeyB64.length === 0) {
    throw new Error("buildSignedDeviceInboxBinding requires device.privateKeyB64");
  }
  if (typeof inboxId !== "string" || inboxId.trim().length === 0) {
    throw new Error("buildSignedDeviceInboxBinding requires inboxId");
  }
  const issuedAtMs = typeof nowMs === "number" && Number.isFinite(nowMs) ? nowMs : Date.now();
  const expiresAtMs = issuedAtMs + ttlMs;
  const body = {
    v: DEVICE_INBOX_BINDING_VERSION,
    purpose: DEVICE_INBOX_BINDING_PURPOSE,
    devicePublicKeyB64: device.publicKeyB64,
    deviceId: DeviceRegistrationV1.deviceIdFor(device.publicKeyB64),
    inboxId: inboxId.trim(),
    issuedAtMs,
    expiresAtMs,
  };
  const sigB64 = await signPayload({ privateKeyB64: device.privateKeyB64, payload: body });
  return new DeviceInboxBindingV1({ ...body, sig: { alg: "ed25519", sigB64 } });
}

/**
 * Build a DeviceRevokeV1 and sign it with the ACCOUNT identity key (B-sign) — a
 * PRIMARY device fail-closing one of its own devices at the home. The revoke
 * NAMES the account and the revoked device; `revokedDeviceId` is self-certifying
 * from `revokedDevicePublicKeyB64`. A DELEGATED device revokes by signing this
 * same body with its device key C instead (gated on the `device.revoke`
 * capability at the home) — that signing variant arrives with the seedless
 * keystore (S9); this builder closes the primary-path gap so `devices.revoke`
 * has a real record to send.
 *
 * @param {object} opts
 * @param {{ publicKeyB64: string, privateKeyB64: string }} opts.account — account identity keypair (B-sign)
 * @param {string} opts.revokedDevicePublicKeyB64 — the device public key being revoked
 * @param {number} [opts.nowMs] — issuedAtMs (defaults to Date.now())
 * @param {number} [opts.ttlMs] — lifetime; expiresAtMs = issuedAtMs + ttlMs
 * @returns {Promise<DeviceRevokeV1>}
 */
export async function buildSignedDeviceRevoke({ account, revokedDevicePublicKeyB64, nowMs, ttlMs = DEFAULT_TTL_MS } = {}) {
  if (!account || typeof account.publicKeyB64 !== "string" || account.publicKeyB64.length === 0) {
    throw new Error("buildSignedDeviceRevoke requires account.publicKeyB64");
  }
  if (typeof account.privateKeyB64 !== "string" || account.privateKeyB64.length === 0) {
    throw new Error("buildSignedDeviceRevoke requires account.privateKeyB64");
  }
  if (typeof revokedDevicePublicKeyB64 !== "string" || revokedDevicePublicKeyB64.length === 0) {
    throw new Error("buildSignedDeviceRevoke requires revokedDevicePublicKeyB64");
  }
  const issuedAtMs = typeof nowMs === "number" && Number.isFinite(nowMs) ? nowMs : Date.now();
  const expiresAtMs = issuedAtMs + ttlMs;
  const body = {
    v: DEVICE_REVOKE_VERSION,
    purpose: DEVICE_REVOKE_PURPOSE,
    accountIdentityPublicKeyB64: account.publicKeyB64,
    revokedDeviceId: DeviceRegistrationV1.deviceIdFor(revokedDevicePublicKeyB64),
    revokedDevicePublicKeyB64,
    issuedAtMs,
    expiresAtMs,
  };
  const sigB64 = await signPayload({ privateKeyB64: account.privateKeyB64, payload: body });
  return new DeviceRevokeV1({ ...body, sig: { alg: "ed25519", sigB64 } });
}

// WebCrypto (spki) verify adapter for the rez-core verifier. The SDK's account
// keys are SPKI/PKCS8 DER, not the raw-32 form rez-core's RCryptoProvider uses,
// so we inject a provider that imports the account key as SPKI.
const webCryptoVerifier = {
  async verify({ publicKey, msg, sig }) {
    const subtle = requireSubtle();
    let key;
    try {
      key = await subtle.importKey("spki", publicKey, "Ed25519", false, ["verify"]);
    } catch (err) {
      // A malformed account key can't verify anything — treat as verify-fail
      // (uniform with verifyPayload's error handling).
      return false;
    }
    return await subtle.verify("Ed25519", key, sig, msg) === true;
  },
};

/**
 * Verify a DeviceRegistrationV1 against an EXPECTED account, using the SDK's
 * WebCrypto provider. Delegates the trust-anchor + deviceId-match + signature +
 * window logic to the single rez-core verifier (SSOT); this only supplies the
 * spki-importing crypto and a safe default clock.
 *
 * `expectedAccountIdentityPublicKeyB64` is REQUIRED — a signature-valid
 * registration for the WRONG (attacker) account must not be accepted as a device
 * of the account you expect. `nowMs` defaults to the current time so expiry is
 * never silently skipped.
 *
 * @param {object} opts
 * @param {object} opts.registration — DeviceRegistrationV1 instance or its toJSON()
 * @param {string} opts.expectedAccountIdentityPublicKeyB64 — REQUIRED trust anchor
 * @param {number} [opts.nowMs] — epoch ms; defaults to Date.now()
 * @returns {Promise<{ ok: boolean, reason?: string, deviceId?: string }>}
 */
export async function verifyDeviceRegistration({ registration, expectedAccountIdentityPublicKeyB64, nowMs } = {}) {
  const effectiveNowMs = typeof nowMs === "number" && Number.isFinite(nowMs) ? nowMs : Date.now();
  return verifyDeviceRegistrationV1({
    registration,
    expectedAccountIdentityPublicKeyB64,
    crypto: webCryptoVerifier,
    nowMs: effectiveNowMs,
  });
}
