import {
  bytesToBase64,
  deriveCeremonySecrets,
  DEVICE_LINK_RENDEZVOUS_KEY_LABEL,
} from "@rezprotocol/core";

const SEED_DERIVATION_SALT = new TextEncoder().encode("rez-v1");

/**
 * PSK → rendezvous Ed25519 keypair R. Both ceremony sides derive it, so R
 * signs every ceremony record AND its public key IS the fetch coordinate —
 * only PSK holders can write to (or even locate) the ceremony slots.
 *
 * The second HKDF preserves the original SeedKeys(seed, label) derivation,
 * while the injected crypto provider turns the final 32-byte private seed
 * into the canonical PKCS#8/SPKI pair on both Node and WebCrypto runtimes.
 */
export async function deriveRendezvousKeyPair({ crypto, psk } = {}) {
  const secrets = await deriveCeremonySecrets({ crypto, psk });
  if (!crypto || typeof crypto.signingKeyPairFromSeed !== "function") {
    throw new Error("deriveRendezvousKeyPair requires crypto.signingKeyPairFromSeed(seed)");
  }
  const rawPrivate = await crypto.hkdfSha256(secrets.rendezvousSeed, {
    salt: SEED_DERIVATION_SALT,
    info: new TextEncoder().encode(DEVICE_LINK_RENDEZVOUS_KEY_LABEL),
    length: 32,
  });
  const keys = await crypto.signingKeyPairFromSeed(rawPrivate);
  return {
    publicKeyB64: bytesToBase64(keys.publicKey),
    privateKeyB64: bytesToBase64(keys.privateKey),
  };
}
