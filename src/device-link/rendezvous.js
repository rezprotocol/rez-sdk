import { SeedKeys } from "../crypto/seedDerivation.js";
import { deriveCeremonySecrets, DEVICE_LINK_RENDEZVOUS_KEY_LABEL } from "@rezprotocol/core";

/**
 * PSK → rendezvous Ed25519 keypair R. Both ceremony sides derive it, so R
 * signs every ceremony record AND its public key IS the fetch coordinate —
 * only PSK holders can write to (or even locate) the ceremony slots.
 *
 * The 32-byte seed derivation is core protocol (deviceLinkV1); the seed →
 * keypair step needs SeedKeys (node:crypto) and therefore lives here, the
 * only device-link file allowed to touch it (rez-core's barrel must stay
 * browser-safe). Desktop-only for now, like every SeedKeys consumer.
 */
export async function deriveRendezvousKeyPair({ crypto, psk } = {}) {
  const secrets = await deriveCeremonySecrets({ crypto, psk });
  const keys = SeedKeys.deriveEd25519({
    seed: secrets.rendezvousSeed,
    label: DEVICE_LINK_RENDEZVOUS_KEY_LABEL,
  });
  return { publicKeyB64: keys.publicKeyB64, privateKeyB64: keys.privateKeyB64 };
}
