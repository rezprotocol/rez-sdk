import { base64ToBytes } from "@rezprotocol/core";
import { sealToPeer, openFromPeer } from "./peerScopedSeal.js";

/**
 * accountStateSeal — encrypt an account-state self-replication event (S2.5 S14) so
 * that ONLY the account's own devices can open it. The account "talks to itself"
 * across devices: a device fans a relationship-graph delta out to its sibling
 * inboxes, and every sibling — which shares the account's long-term identity-DH
 * key — derives the SAME AEAD key and opens it. A peer (different account DH)
 * cannot.
 *
 * Key agreement is a self static-static X25519: DH(accountDhPriv, accountDhPub).
 * The account identity-DH keypair is the same on all of an account's devices (it
 * is seed-derived on a primary and delivered to a delegated device in the S10
 * link ceremony, and `_loadAccountKeyRecord` enforces stored === injected), so
 * every device derives an identical secret with no online exchange. DH(priv, its
 * own pub) is deterministic and computable only with the private key.
 *
 * Like peerScopedSeal — and DELIBERATELY separate from the live double ratchet —
 * this is idempotent: the fresh per-seal nonce travels with the ciphertext, so
 * re-opening the same sealed event always yields the same plaintext with zero
 * ratchet side-effects (a self-event may be re-drained on reconnect).
 *
 * The AEAD envelope + seal/open are the SAME generic key-based primitive
 * peerScopedSeal uses (re-exported here under account-state names); only the key
 * DERIVATION differs (self static-static + a distinct HKDF info for domain
 * separation).
 */

const AEAD_INFO = new TextEncoder().encode("rez:account-state-seal:aead:v1");

/**
 * Derive the stable account-state AEAD key from the account's own identity-DH
 * keypair (self static-static X25519 → HKDF). Every device of the account derives
 * the identical 32-byte key.
 *
 * @param {object} args
 * @param {object} args.cryptoProvider — RCryptoProvider (dhDerive + hkdfSha256)
 * @param {string} args.accountIdentityDhPrivateKeyB64 — account identity-DH X25519 PKCS8 (base64)
 * @param {string} args.accountIdentityDhPublicKeyB64 — account identity-DH X25519 SPKI (base64)
 * @returns {Promise<Uint8Array>} 32-byte AEAD key
 */
export async function deriveAccountStateKey({ cryptoProvider, accountIdentityDhPrivateKeyB64, accountIdentityDhPublicKeyB64 } = {}) {
  if (!cryptoProvider || typeof cryptoProvider.dhDerive !== "function" || typeof cryptoProvider.hkdfSha256 !== "function") {
    throw new Error("deriveAccountStateKey requires a cryptoProvider with dhDerive + hkdfSha256");
  }
  requireB64(accountIdentityDhPrivateKeyB64, "accountIdentityDhPrivateKeyB64");
  requireB64(accountIdentityDhPublicKeyB64, "accountIdentityDhPublicKeyB64");
  const shared = await cryptoProvider.dhDerive({
    privateKey: base64ToBytes(accountIdentityDhPrivateKeyB64),
    publicKey: base64ToBytes(accountIdentityDhPublicKeyB64),
    alg: "X25519",
    fmt: "spki",
  });
  if (!(shared instanceof Uint8Array) || shared.length === 0) {
    throw new Error("deriveAccountStateKey: dhDerive returned no shared secret");
  }
  return cryptoProvider.hkdfSha256(shared, { info: AEAD_INFO, length: 32 });
}

// The AEAD envelope for an account-state event is the same generic key-based
// primitive as a peer-scoped seal (a fresh nonce travels with the ciphertext;
// opening is idempotent). Re-exported under account-state names so callers read
// clearly and a future domain change has one place to diverge.
export const sealAccountStateEvent = sealToPeer;
export const openAccountStateEvent = openFromPeer;

// The OUTER-envelope discriminator for a self account-state deposit. The sibling's
// inbound protocol service recognizes this shape and opens it with the
// account-state key (NOT the peer trial-decrypt path). SSOT for both the sender's
// wrap and the receiver's recognize, so the two never drift.
export const ACCOUNT_STATE_ENVELOPE_VERSION = 1;

/** Wrap a sealed account-state event into the outer deposit envelope object. */
export function wrapAccountStateEnvelope({ nonceB64, ciphertextB64 } = {}) {
  if (typeof nonceB64 !== "string" || !nonceB64 || typeof ciphertextB64 !== "string" || !ciphertextB64) {
    throw new Error("wrapAccountStateEnvelope requires nonceB64 + ciphertextB64");
  }
  return { accountState: ACCOUNT_STATE_ENVELOPE_VERSION, nonceB64, ciphertextB64 };
}

/** True when a parsed outer envelope is a self account-state deposit. */
export function isAccountStateEnvelope(bodyObj) {
  return Boolean(
    bodyObj
    && bodyObj.accountState === ACCOUNT_STATE_ENVELOPE_VERSION
    && typeof bodyObj.nonceB64 === "string" && bodyObj.nonceB64.length > 0
    && typeof bodyObj.ciphertextB64 === "string" && bodyObj.ciphertextB64.length > 0,
  );
}

/**
 * The SIBLING device inboxes to fan a self account-state event out to, derived
 * from the home-served account device set, EXCLUDING this device's own inbox +
 * deviceId (never deposit to self). Each entry's inbox comes from the sibling's
 * self-published DevicePrekeyBundleV1 (top-level inboxId). Deduped by inbox.
 *
 * @returns {Array<{ deviceId: string, inboxId: string }>}
 */
export function siblingInboxesFromDeviceSet({ devices, ownInboxId, ownDeviceId } = {}) {
  const own = typeof ownInboxId === "string" ? ownInboxId.trim() : "";
  const ownDev = typeof ownDeviceId === "string" ? ownDeviceId.trim() : "";
  const out = [];
  const seen = new Set();
  for (const entry of Array.isArray(devices) ? devices : []) {
    const bundle = entry && typeof entry === "object" && entry.bundle ? entry.bundle : entry;
    const inboxId = bundle && typeof bundle.inboxId === "string" ? bundle.inboxId.trim() : "";
    const deviceId = bundle && typeof bundle.deviceId === "string" && bundle.deviceId.trim()
      ? bundle.deviceId.trim()
      : (entry && typeof entry.deviceId === "string" ? entry.deviceId.trim() : "");
    if (!inboxId || !deviceId) continue;
    if (inboxId === own || (ownDev && deviceId === ownDev)) continue; // never self
    if (seen.has(inboxId)) continue;
    seen.add(inboxId);
    out.push({ deviceId, inboxId });
  }
  return out;
}

function requireB64(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("account-state seal requires " + label);
  }
}
