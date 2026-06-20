import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase64 } from "@rezprotocol/core";
// REAL crypto — static-static X25519 + AES-256-GCM via WebCrypto.
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";
import { derivePeerScopedKey, sealToPeer, openFromPeer } from "../src/peer-link/peerScopedSeal.js";

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);

async function makeAccount(crypto) {
  // Account-level identity-DH keypair (X25519 SPKI/PKCS8), the stable long-term
  // key the seal agrees on.
  const dh = await crypto.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
  return { pubB64: bytesToBase64(dh.publicKey), privB64: bytesToBase64(dh.privateKey) };
}

test("both peers independently derive the SAME aeadKey + slot (commutative static-static DH)", async () => {
  const crypto = new BrowserCryptoProvider();
  const a = await makeAccount(crypto);
  const b = await makeAccount(crypto);

  const fromA = await derivePeerScopedKey({ cryptoProvider: crypto, myIdentityDhPrivateKeyB64: a.privB64, peerIdentityDhPublicKeyB64: b.pubB64 });
  const fromB = await derivePeerScopedKey({ cryptoProvider: crypto, myIdentityDhPrivateKeyB64: b.privB64, peerIdentityDhPublicKeyB64: a.pubB64 });

  assert.deepEqual(fromA.aeadKey, fromB.aeadKey, "both sides derive the same AEAD key");
  assert.equal(fromA.slotRecordId, fromB.slotRecordId, "both sides derive the same slot recordId");
  assert.equal(fromA.aeadKey.length, 32);
  assert.match(fromA.slotRecordId, /^[0-9a-f]{32}$/);
  // aead key and slot id are domain-separated (not the same bytes).
  assert.notEqual(bytesToBase64(fromA.aeadKey).slice(0, 22), fromA.slotRecordId);
});

test("seal/open round-trips; open is idempotent (no state mutation)", async () => {
  const crypto = new BrowserCryptoProvider();
  const a = await makeAccount(crypto);
  const b = await makeAccount(crypto);
  const { aeadKey } = await derivePeerScopedKey({ cryptoProvider: crypto, myIdentityDhPrivateKeyB64: a.privB64, peerIdentityDhPublicKeyB64: b.pubB64 });

  const sealed = await sealToPeer({ cryptoProvider: crypto, aeadKey, plaintextBytes: enc("my device set"), aad: "rez:device-set:v1" });
  const { aeadKey: bKey } = await derivePeerScopedKey({ cryptoProvider: crypto, myIdentityDhPrivateKeyB64: b.privB64, peerIdentityDhPublicKeyB64: a.pubB64 });

  const open1 = await openFromPeer({ cryptoProvider: crypto, aeadKey: bKey, nonceB64: sealed.nonceB64, ciphertextB64: sealed.ciphertextB64, aad: "rez:device-set:v1" });
  const open2 = await openFromPeer({ cryptoProvider: crypto, aeadKey: bKey, nonceB64: sealed.nonceB64, ciphertextB64: sealed.ciphertextB64, aad: "rez:device-set:v1" });
  assert.equal(dec(open1), "my device set");
  assert.deepEqual(open2, open1, "re-opening the same sealed record decrypts identically");
});

test("a non-peer (different identity-DH key) derives a different key and CANNOT open", async () => {
  const crypto = new BrowserCryptoProvider();
  const a = await makeAccount(crypto);
  const b = await makeAccount(crypto);
  const evil = await makeAccount(crypto);
  const { aeadKey } = await derivePeerScopedKey({ cryptoProvider: crypto, myIdentityDhPrivateKeyB64: a.privB64, peerIdentityDhPublicKeyB64: b.pubB64 });
  const sealed = await sealToPeer({ cryptoProvider: crypto, aeadKey, plaintextBytes: enc("secret"), aad: "rez:device-set:v1" });

  // Eve agrees with A's pubkey but is not B — different shared secret.
  const eve = await derivePeerScopedKey({ cryptoProvider: crypto, myIdentityDhPrivateKeyB64: evil.privB64, peerIdentityDhPublicKeyB64: a.pubB64 });
  assert.notDeepEqual(eve.aeadKey, aeadKey);
  assert.notEqual(eve.slotRecordId, (await derivePeerScopedKey({ cryptoProvider: crypto, myIdentityDhPrivateKeyB64: a.privB64, peerIdentityDhPublicKeyB64: b.pubB64 })).slotRecordId);
  await assert.rejects(() => openFromPeer({ cryptoProvider: crypto, aeadKey: eve.aeadKey, nonceB64: sealed.nonceB64, ciphertextB64: sealed.ciphertextB64, aad: "rez:device-set:v1" }));
});

test("aad mismatch fails authentication (a sealed record can't be relocated to another context)", async () => {
  const crypto = new BrowserCryptoProvider();
  const a = await makeAccount(crypto);
  const b = await makeAccount(crypto);
  const { aeadKey } = await derivePeerScopedKey({ cryptoProvider: crypto, myIdentityDhPrivateKeyB64: a.privB64, peerIdentityDhPublicKeyB64: b.pubB64 });
  const sealed = await sealToPeer({ cryptoProvider: crypto, aeadKey, plaintextBytes: enc("x"), aad: "rez:device-set:v1" });
  await assert.rejects(() => openFromPeer({ cryptoProvider: crypto, aeadKey, nonceB64: sealed.nonceB64, ciphertextB64: sealed.ciphertextB64, aad: "rez:something-else" }));
});
