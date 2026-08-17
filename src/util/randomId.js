/**
 * SDK-generated identifiers (SDK-5).
 *
 * `Math.random()` is a fast, seedable, non-crypto PRNG whose internal state is
 * recoverable from a handful of outputs. None of the ids below are secrets, so
 * this is not a key-recovery hole — but predictability and collisions are free
 * to avoid here, and one of these ids is not merely cosmetic: the
 * `UplinkPoolClient` device id participates in session identity metadata and is
 * echoed by the node in `session.ready`.
 *
 * FAIL, do not degrade. The old shape used `crypto.randomUUID` when it existed
 * and fell through to `Math.random()` when it did not — a silent downgrade on
 * exactly the platform where you would most want to be told. A runtime with no
 * Web Crypto cannot run this SDK's actual cryptography
 * either, so an id generated there is the least of the caller's problems; say so
 * at the point it is discovered rather than shipping weaker ids in silence.
 *
 * NOT for anything that must be unguessable — keys, nonces and ratchet material
 * come from the crypto provider, never from here.
 */

function requireWebCrypto() {
  const webcrypto = globalThis.crypto;
  if (!webcrypto || typeof webcrypto.getRandomValues !== "function") {
    throw new Error(
      "rez-sdk requires Web Crypto (globalThis.crypto.getRandomValues) to generate identifiers. "
      + "No such global is available in this runtime — refusing to fall back to Math.random(). "
      + "On Node this means a build older than 19, or a bundler that stripped the global.",
    );
  }
  return webcrypto;
}

/**
 * A short opaque token — 8 lowercase hex chars (32 bits) by default, enough to
 * separate ids that are already scoped by a mailbox, subscription map, or
 * timestamp.
 *
 * @param {number} bytes how many random bytes to draw
 * @returns {string} lowercase hex, 2 chars per byte
 */
export function randomToken(bytes = 4) {
  if (!Number.isInteger(bytes) || bytes < 1) {
    throw new Error("randomToken(bytes) requires a positive integer");
  }
  const buf = new Uint8Array(bytes);
  requireWebCrypto().getRandomValues(buf);
  let out = "";
  for (const byte of buf) out += byte.toString(16).padStart(2, "0");
  return out;
}

/**
 * A full UUID v4, for ids that must not collide across processes or hosts.
 * Falls back to 16 random bytes only when `randomUUID` is absent while
 * `getRandomValues` is present (some hardened/older embeddings) — that is a
 * narrower gap than the old one, and both paths are crypto-grade.
 */
export function randomUuid() {
  const webcrypto = requireWebCrypto();
  if (typeof webcrypto.randomUUID === "function") return webcrypto.randomUUID();
  return randomToken(16);
}
