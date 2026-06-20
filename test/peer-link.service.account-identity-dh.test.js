import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase64, deriveAccountIdFromPublicKey, DeviceRegistrationV1 } from "@rezprotocol/core";
import { SeedKeys } from "@rezprotocol/core/src/crypto/seedDerivation.js";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService } from "../src/peer-link/PeerLinkService.js";
import { derivePeerScopedKey } from "../src/peer-link/peerScopedSeal.js";
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

// Audit P1 — the account-level identity-DH key (X3DH DH1 + the device-set
// peer-scoped seal) was generated random per-device-local, so a 2nd device of an
// account derived a DIFFERENT key and could not open a device set sealed to the
// account. The fix: seed-derive it and inject it (same on every device). These
// tests prove two devices of one account now share ONE identity-DH key, that the
// peer-scoped seal slot agrees across those devices, and that the legacy
// (no-injection) path is unchanged.

const enc = (s) => new TextEncoder().encode(s);
const FAR_FUTURE = 10_000_000_000_000;
const DH_LABEL = "rez/identity/x3dh-dh/v1";

function makeStorageProvider() {
  const m = new Map();
  const kv = {
    async get(k) { return m.has(k) ? m.get(k) : undefined; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { return m.delete(k); },
    async keys(prefix) { const o = []; for (const k of m.keys()) if (!prefix || k.startsWith(prefix)) o.push(k); return o; },
  };
  const peerLinkStorage = createKeyValueBackedPeerLinkStorage({ keyValueStore: kv });
  return { getPeerLinkStorage() { return peerLinkStorage; }, getKeyValueStore() { return kv; }, peerLinkStorage };
}

// One account "device": same B (chat-server) identity + same injected account
// identity-DH key, but its own device key C and its own storage.
async function makeDevice(crypto, b, accountId, accountPubB64, { accountIdentityDhKeyPair } = {}) {
  const authority = {
    signer: {
      getSignerRef() { return { accountId, keyId: "invite-ed25519-v1", alg: "ed25519", signerPublicKeyB64: accountPubB64 }; },
      async sign(bytes) { return crypto.sign({ privateKey: b.privateKey, msg: bytes }); },
    },
    verifier: { async verify() { return true; } },
  };
  const dk = await crypto.generateSigningKeyPair();
  const deviceKeyPair = { publicKeyB64: bytesToBase64(dk.publicKey), privateKeyB64: bytesToBase64(dk.privateKey) };
  const svc = new PeerLinkService({
    storageProvider: makeStorageProvider(),
    clock: () => 1,
    ownerAccountId: accountId,
    getInviteAuthority: () => authority,
    inviteBinding: { mailboxId: "rez:inbox:m", capabilityId: "rez:inbox:m" },
    cryptoProvider: crypto,
    deviceKeyPair,
    deviceId: DeviceRegistrationV1.deviceIdFor(deviceKeyPair.publicKeyB64),
    accountIdentityDhKeyPair: accountIdentityDhKeyPair || null,
  });
  // Materialize + bind the account identity (loads/persists the DH key, then
  // B vouches for the X3DH signing subkey so _requireBoundX3dhIdentity resolves).
  const challenge = await svc.getOrCreateAccountBindingChallenge({ ownerAccountId: accountId });
  const bindingSig = await crypto.sign({ privateKey: b.privateKey, msg: enc("x3dh-subkey-binding:" + challenge.x3dhIdentityPublicKeyB64) });
  await svc.upsertAccountBinding({
    ownerAccountId: accountId,
    accountBinding: {
      accountId,
      accountIdentityPublicKeyB64: accountPubB64,
      x3dhIdentityPublicKeyB64: challenge.x3dhIdentityPublicKeyB64,
      issuedAtMs: 1,
      expiresAtMs: FAR_FUTURE,
      accountBindingSigB64: bytesToBase64(bindingSig),
    },
  });
  const bound = await svc._requireBoundX3dhIdentity(accountId);
  return { svc, identityDhPubB64: bytesToBase64(bound.identityDhKeyPair.publicKey), identityDhPrivB64: bytesToBase64(bound.identityDhKeyPair.privateKey) };
}

test("two devices of one account share the SEED-DERIVED identity-DH key; seal slots agree", async () => {
  const crypto = new BrowserCryptoProvider();
  const b = await crypto.generateSigningKeyPair();
  const accountPubB64 = bytesToBase64(b.publicKey);
  const accountId = deriveAccountIdFromPublicKey(b.publicKey);
  const seed = Buffer.alloc(64, 42);
  const seededDh = SeedKeys.deriveX25519({ seed, label: DH_LABEL });

  const devA = await makeDevice(crypto, b, accountId, accountPubB64, { accountIdentityDhKeyPair: seededDh });
  const devB = await makeDevice(crypto, b, accountId, accountPubB64, { accountIdentityDhKeyPair: seededDh });

  // Both devices loaded the injected seed-derived key — not a random per-device one.
  assert.equal(devA.identityDhPubB64, seededDh.publicKeyB64, "device A uses the seed-derived account DH key");
  assert.equal(devB.identityDhPubB64, seededDh.publicKeyB64, "device B uses the SAME key");

  // The peer-scoped seal slot a peer publishes is therefore identical for both
  // devices: derivePeerScopedKey(ourDhPriv, peerDhPub) → same slot on A and B.
  const peerDh = SeedKeys.deriveX25519({ seed: Buffer.alloc(64, 7), label: DH_LABEL });
  const slotA = await derivePeerScopedKey({ cryptoProvider: crypto, myIdentityDhPrivateKeyB64: devA.identityDhPrivB64, peerIdentityDhPublicKeyB64: peerDh.publicKeyB64 });
  const slotB = await derivePeerScopedKey({ cryptoProvider: crypto, myIdentityDhPrivateKeyB64: devB.identityDhPrivB64, peerIdentityDhPublicKeyB64: peerDh.publicKeyB64 });
  assert.equal(slotA.slotRecordId, slotB.slotRecordId, "both devices locate the SAME sealed device-set slot");
  assert.deepEqual([...slotA.aeadKey], [...slotB.aeadKey], "and derive the SAME AEAD key");
});

test("without an injected key the legacy path still generates a (device-local random) key", async () => {
  const crypto = new BrowserCryptoProvider();
  const b = await crypto.generateSigningKeyPair();
  const accountPubB64 = bytesToBase64(b.publicKey);
  const accountId = deriveAccountIdFromPublicKey(b.publicKey);

  // Two legacy devices (no injected key) generate DIFFERENT random keys — this is
  // exactly the bug the seed-derivation fixes, and it is preserved for the legacy
  // (web / pre-migration) path that has no seed-derived key to inject.
  const a = await makeDevice(crypto, b, accountId, accountPubB64, {});
  const c = await makeDevice(crypto, b, accountId, accountPubB64, {});
  assert.notEqual(a.identityDhPubB64, c.identityDhPubB64, "legacy device-local keys differ");
});

test("no in-place migration (Audit R2 #3): an injected key that mismatches a stored random DH key fails loud, not silently replaces it", async () => {
  const crypto = new BrowserCryptoProvider();
  const b = await crypto.generateSigningKeyPair();
  const accountPubB64 = bytesToBase64(b.publicKey);
  const accountId = deriveAccountIdFromPublicKey(b.publicKey);

  // First materialize WITHOUT an injected key (a legacy vault persists a random
  // DH key), then construct again over the SAME storage WITH the seed-derived
  // key. Silently rebuilding to the injected key would rotate the account's
  // long-term DH key out from under already-linked peers (who hold the OLD pubkey
  // and would compute a different device-set slot) — so it must fail loud, not
  // migrate. A fresh account seed-derives at creation and never hits this.
  const sp = makeStorageProvider();
  const authority = {
    signer: {
      getSignerRef() { return { accountId, keyId: "invite-ed25519-v1", alg: "ed25519", signerPublicKeyB64: accountPubB64 }; },
      async sign(bytes) { return crypto.sign({ privateKey: b.privateKey, msg: bytes }); },
    },
    verifier: { async verify() { return true; } },
  };
  const dk = await crypto.generateSigningKeyPair();
  const deviceKeyPair = { publicKeyB64: bytesToBase64(dk.publicKey), privateKeyB64: bytesToBase64(dk.privateKey) };
  const common = {
    storageProvider: sp, clock: () => 1, ownerAccountId: accountId,
    getInviteAuthority: () => authority, inviteBinding: { mailboxId: "rez:inbox:m", capabilityId: "rez:inbox:m" },
    cryptoProvider: crypto, deviceKeyPair, deviceId: DeviceRegistrationV1.deviceIdFor(deviceKeyPair.publicKeyB64),
  };
  const legacy = new PeerLinkService({ ...common });
  const challenge = await legacy.getOrCreateAccountBindingChallenge({ ownerAccountId: accountId });
  const bindingSig = await crypto.sign({ privateKey: b.privateKey, msg: enc("x3dh-subkey-binding:" + challenge.x3dhIdentityPublicKeyB64) });
  await legacy.upsertAccountBinding({
    ownerAccountId: accountId,
    accountBinding: {
      accountId, accountIdentityPublicKeyB64: accountPubB64,
      x3dhIdentityPublicKeyB64: challenge.x3dhIdentityPublicKeyB64,
      issuedAtMs: 1, expiresAtMs: FAR_FUTURE, accountBindingSigB64: bytesToBase64(bindingSig),
    },
  });
  const randomDhPub = bytesToBase64((await legacy._requireBoundX3dhIdentity(accountId)).identityDhKeyPair.publicKey);

  const seededDh = SeedKeys.deriveX25519({ seed: Buffer.alloc(64, 99), label: DH_LABEL });
  assert.notEqual(randomDhPub, seededDh.publicKeyB64, "precondition: stored random key differs from the seed key");

  const upgraded = new PeerLinkService({ ...common, accountIdentityDhKeyPair: seededDh });
  await assert.rejects(
    () => upgraded._requireBoundX3dhIdentity(accountId),
    (err) => err && err.code === "ACCOUNT_IDENTITY_DH_MISMATCH",
  );

  // The stored random key is left untouched (no silent rotation that would break
  // already-linked peers): the persisted DH pub is still the original random one.
  const rec = await sp.peerLinkStorage.keys.getAccountIdentity(accountId);
  assert.equal(rec.x3dhIdentityDhKeyMaterial.publicKeyB64, randomDhPub, "the stored DH key was NOT silently replaced");
});
