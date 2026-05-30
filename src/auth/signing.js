import { base64ToBytes, bytesToBase64, canonicalJSONStringify } from "@rezprotocol/core";

function requireSubtle() {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw Object.assign(new Error("WebCrypto unavailable"), { code: "BAD_CONFIG", retryable: false });
  }
  return globalThis.crypto.subtle;
}

/**
 * Sign a payload object using Ed25519 via WebCrypto.
 */
export async function signPayload({ privateKeyB64, payload } = {}) {
  const subtle = requireSubtle();
  const privateKeyBytes = base64ToBytes(String(privateKeyB64 || ""));
  const key = await subtle.importKey("pkcs8", privateKeyBytes, "Ed25519", false, ["sign"]);
  const bytes = new TextEncoder().encode(canonicalJSONStringify(payload || {}));
  const sig = await subtle.sign("Ed25519", key, bytes);
  return bytesToBase64(new Uint8Array(sig));
}

/**
 * Verify a payload object's Ed25519 signature using WebCrypto.
 *
 * Returns true only when the signature verifies against the given public key
 * over canonical-JSON bytes of `payload`. Returns false on any error so the
 * caller can treat verify-failure uniformly.
 */
export async function verifyPayload({ publicKeyB64, payload, signatureB64 } = {}) {
  if (typeof publicKeyB64 !== "string" || publicKeyB64.length === 0) return false;
  if (typeof signatureB64 !== "string" || signatureB64.length === 0) return false;
  let subtle;
  try {
    subtle = requireSubtle();
  } catch {
    return false;
  }
  let publicKeyBytes;
  let signatureBytes;
  try {
    publicKeyBytes = base64ToBytes(publicKeyB64);
    signatureBytes = base64ToBytes(signatureB64);
  } catch {
    return false;
  }
  let key;
  try {
    key = await subtle.importKey("spki", publicKeyBytes, "Ed25519", false, ["verify"]);
  } catch {
    return false;
  }
  const bytes = new TextEncoder().encode(canonicalJSONStringify(payload || {}));
  try {
    return await subtle.verify("Ed25519", key, signatureBytes, bytes) === true;
  } catch {
    return false;
  }
}
