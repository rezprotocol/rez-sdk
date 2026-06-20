import { bytesToBase64, base64ToBytes, bytesToHex } from "@rezprotocol/core";

/**
 * peerScopedSeal — encrypt a durable-record payload TO a peer account using a
 * STABLE, idempotent key derived from both accounts' long-term identity-DH keys
 * (S2.5 Slice 3). This is deliberately SEPARATE from the double ratchet: durable
 * records are fetched/re-fetched/cached, and the ratchet is non-idempotent
 * (re-decrypting consumed ciphertext advances/breaks the chain). Re-opening the
 * same sealed record here decrypts identically with zero ratchet side-effects.
 *
 * Key agreement: X25519(my identity-DH priv, peer identity-DH pub). DH is
 * commutative, so both accounts derive the same root independently with no
 * online exchange. Identity-DH keys are account-level (the same on all of an
 * account's devices), so a device set sealed to a peer ACCOUNT is readable by
 * EVERY one of that peer's devices — which is exactly right for an account-level
 * "these are my devices" statement.
 *
 * Privacy: the slot recordId is ALSO derived from the shared root, so the durable
 * slot `sha256(publisherPub | kind:recordId)` is computable only by a peer who
 * holds the shared secret. A non-peer who merely knows the account's public key
 * cannot locate — let alone decrypt — the record.
 */

const AEAD_INFO = new TextEncoder().encode("rez:peer-scoped-seal:aead:v1");
const SLOT_INFO = new TextEncoder().encode("rez:peer-scoped-seal:slot:v1");
const SLOT_BYTES = 16;
const NONCE_BYTES = 12;

/**
 * Derive the stable per-peer AEAD key + slot recordId from the static-static
 * identity-DH agreement. Both sides pass (theirPriv, otherPub) and get the same
 * result.
 *
 * @param {object} args
 * @param {object} args.cryptoProvider — RCryptoProvider (dhDerive/hkdfSha256)
 * @param {string} args.myIdentityDhPrivateKeyB64 — my account identity-DH X25519 PKCS8 (base64)
 * @param {string} args.peerIdentityDhPublicKeyB64 — peer account identity-DH X25519 SPKI (base64)
 * @returns {Promise<{ aeadKey: Uint8Array, slotRecordId: string }>}
 */
export async function derivePeerScopedKey({ cryptoProvider, myIdentityDhPrivateKeyB64, peerIdentityDhPublicKeyB64 } = {}) {
  if (!cryptoProvider || typeof cryptoProvider.dhDerive !== "function" || typeof cryptoProvider.hkdfSha256 !== "function") {
    throw new Error("derivePeerScopedKey requires a cryptoProvider with dhDerive + hkdfSha256");
  }
  requireB64(myIdentityDhPrivateKeyB64, "myIdentityDhPrivateKeyB64");
  requireB64(peerIdentityDhPublicKeyB64, "peerIdentityDhPublicKeyB64");
  const shared = await cryptoProvider.dhDerive({
    privateKey: base64ToBytes(myIdentityDhPrivateKeyB64),
    publicKey: base64ToBytes(peerIdentityDhPublicKeyB64),
    alg: "X25519",
    fmt: "spki",
  });
  if (!(shared instanceof Uint8Array) || shared.length === 0) {
    throw new Error("derivePeerScopedKey: dhDerive returned no shared secret");
  }
  const aeadKey = await cryptoProvider.hkdfSha256(shared, { info: AEAD_INFO, length: 32 });
  const slotBytes = await cryptoProvider.hkdfSha256(shared, { info: SLOT_INFO, length: SLOT_BYTES });
  return { aeadKey, slotRecordId: bytesToHex(slotBytes) };
}

/**
 * Seal a plaintext payload under a peer-scoped AEAD key. A fresh random nonce is
 * generated per seal (so re-publishing produces a fresh ciphertext); the nonce
 * travels with the ciphertext, so OPENING is fully deterministic/idempotent.
 *
 * @returns {Promise<{ nonceB64: string, ciphertextB64: string }>}
 */
export async function sealToPeer({ cryptoProvider, aeadKey, plaintextBytes, aad = null } = {}) {
  requireAeadKey(aeadKey);
  if (!(plaintextBytes instanceof Uint8Array) || plaintextBytes.length === 0) {
    throw new Error("sealToPeer requires non-empty plaintextBytes");
  }
  if (typeof cryptoProvider.randomBytes !== "function" || typeof cryptoProvider.aeadEncrypt !== "function") {
    throw new Error("sealToPeer requires a cryptoProvider with randomBytes + aeadEncrypt");
  }
  const nonce = cryptoProvider.randomBytes(NONCE_BYTES);
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_BYTES) {
    throw new Error("sealToPeer: randomBytes returned an invalid nonce");
  }
  const ciphertext = await cryptoProvider.aeadEncrypt({
    key: aeadKey, nonce, plaintext: plaintextBytes, aad: normalizeAad(aad),
  });
  return { nonceB64: bytesToBase64(nonce), ciphertextB64: bytesToBase64(ciphertext) };
}

/**
 * Open a peer-scoped sealed payload. Pure — re-opening the same record always
 * yields the same plaintext (no ratchet/state mutation). Throws on auth failure
 * (wrong key / tampered ciphertext / wrong aad).
 *
 * @returns {Promise<Uint8Array>}
 */
export async function openFromPeer({ cryptoProvider, aeadKey, nonceB64, ciphertextB64, aad = null } = {}) {
  requireAeadKey(aeadKey);
  requireB64(nonceB64, "nonceB64");
  requireB64(ciphertextB64, "ciphertextB64");
  if (typeof cryptoProvider.aeadDecrypt !== "function") {
    throw new Error("openFromPeer requires a cryptoProvider with aeadDecrypt");
  }
  return cryptoProvider.aeadDecrypt({
    key: aeadKey,
    nonce: base64ToBytes(nonceB64),
    ciphertext: base64ToBytes(ciphertextB64),
    aad: normalizeAad(aad),
  });
}

function normalizeAad(aad) {
  if (aad == null) return new Uint8Array(0);
  if (aad instanceof Uint8Array) return aad;
  if (typeof aad === "string") return new TextEncoder().encode(aad);
  throw new Error("aad must be a Uint8Array, string, or null");
}

function requireAeadKey(aeadKey) {
  if (!(aeadKey instanceof Uint8Array) || aeadKey.length !== 32) {
    throw new Error("peer-scoped seal requires a 32-byte aeadKey");
  }
}

function requireB64(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("peer-scoped seal requires " + label);
  }
}
