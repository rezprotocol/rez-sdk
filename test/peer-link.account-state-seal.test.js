import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase64 } from "@rezprotocol/core";
// REAL crypto — self static-static X25519 + AES-256-GCM via WebCrypto.
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";
import { deriveAccountStateKey, sealAccountStateEvent, openAccountStateEvent } from "../src/peer-link/accountStateSeal.js";
import { derivePeerScopedKey } from "../src/peer-link/peerScopedSeal.js";

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);

// One account's long-term identity-DH keypair (shared by all its devices).
async function makeAccountDh(crypto) {
  const dh = await crypto.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
  return { pubB64: bytesToBase64(dh.publicKey), privB64: bytesToBase64(dh.privateKey) };
}

test("every device of one account derives the SAME account-state key (self static-static DH)", async () => {
  const crypto = new BrowserCryptoProvider();
  const acct = await makeAccountDh(crypto);
  // Two independent derivations (as two sibling devices would do) from the SAME
  // account DH must match.
  const k1 = await deriveAccountStateKey({ cryptoProvider: crypto, accountIdentityDhPrivateKeyB64: acct.privB64, accountIdentityDhPublicKeyB64: acct.pubB64 });
  const k2 = await deriveAccountStateKey({ cryptoProvider: crypto, accountIdentityDhPrivateKeyB64: acct.privB64, accountIdentityDhPublicKeyB64: acct.pubB64 });
  assert.equal(k1.length, 32);
  assert.deepEqual(k1, k2, "deterministic across devices");
});

test("seal/open round-trips; open is idempotent (re-drain safe)", async () => {
  const crypto = new BrowserCryptoProvider();
  const acct = await makeAccountDh(crypto);
  const aeadKey = await deriveAccountStateKey({ cryptoProvider: crypto, accountIdentityDhPrivateKeyB64: acct.privB64, accountIdentityDhPublicKeyB64: acct.pubB64 });

  const sealed = await sealAccountStateEvent({ cryptoProvider: crypto, aeadKey, plaintextBytes: enc("contact.upsert carol") });
  const open1 = await openAccountStateEvent({ cryptoProvider: crypto, aeadKey, nonceB64: sealed.nonceB64, ciphertextB64: sealed.ciphertextB64 });
  const open2 = await openAccountStateEvent({ cryptoProvider: crypto, aeadKey, nonceB64: sealed.nonceB64, ciphertextB64: sealed.ciphertextB64 });
  assert.equal(dec(open1), "contact.upsert carol");
  assert.deepEqual(open2, open1, "re-opening the same event decrypts identically (no ratchet side-effects)");
});

test("a DIFFERENT account (a peer) derives a different key and CANNOT open the self-event", async () => {
  const crypto = new BrowserCryptoProvider();
  const alice = await makeAccountDh(crypto);
  const carol = await makeAccountDh(crypto);
  const aliceKey = await deriveAccountStateKey({ cryptoProvider: crypto, accountIdentityDhPrivateKeyB64: alice.privB64, accountIdentityDhPublicKeyB64: alice.pubB64 });
  const carolKey = await deriveAccountStateKey({ cryptoProvider: crypto, accountIdentityDhPrivateKeyB64: carol.privB64, accountIdentityDhPublicKeyB64: carol.pubB64 });
  assert.notDeepEqual(aliceKey, carolKey);

  const sealed = await sealAccountStateEvent({ cryptoProvider: crypto, aeadKey: aliceKey, plaintextBytes: enc("secret") });
  await assert.rejects(
    () => openAccountStateEvent({ cryptoProvider: crypto, aeadKey: carolKey, nonceB64: sealed.nonceB64, ciphertextB64: sealed.ciphertextB64 }),
    "carol's account-state key cannot open alice's self-event",
  );
});

test("domain separation: the account-state key differs from the peer-scoped key for the same DH inputs", async () => {
  const crypto = new BrowserCryptoProvider();
  const acct = await makeAccountDh(crypto);
  // Same self DH inputs into both derivations — only the HKDF info differs.
  const accountStateKey = await deriveAccountStateKey({ cryptoProvider: crypto, accountIdentityDhPrivateKeyB64: acct.privB64, accountIdentityDhPublicKeyB64: acct.pubB64 });
  const { aeadKey: peerScopedSelfKey } = await derivePeerScopedKey({ cryptoProvider: crypto, myIdentityDhPrivateKeyB64: acct.privB64, peerIdentityDhPublicKeyB64: acct.pubB64 });
  assert.notDeepEqual(accountStateKey, peerScopedSelfKey, "distinct HKDF info ⇒ distinct keys (no cross-domain reuse)");
});
