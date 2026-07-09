import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase64, DeviceRegistrationV1 } from "@rezprotocol/core";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService } from "../src/peer-link/PeerLinkService.js";
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

function makeStorageProvider() {
  const m = new Map();
  const kv = {
    async get(k) { return m.has(k) ? m.get(k) : undefined; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { return m.delete(k); },
    async keys(prefix) { const out = []; for (const k of m.keys()) if (!prefix || k.startsWith(prefix)) out.push(k); return out; },
  };
  const peerLinkStorage = createKeyValueBackedPeerLinkStorage({ keyValueStore: kv });
  return { getPeerLinkStorage() { return peerLinkStorage; }, getKeyValueStore() { return kv; } };
}

async function makeDeviceService(crypto) {
  const kp = await crypto.generateSigningKeyPair();
  const devicePub = bytesToBase64(kp.publicKey);
  const deviceId = DeviceRegistrationV1.deviceIdFor(devicePub);
  const svc = new PeerLinkService({
    storageProvider: makeStorageProvider(),
    ownerAccountId: "rez:acct:alice",
    cryptoProvider: crypto,
    getInviteAuthority: () => ({ sign: async () => new Uint8Array(64), verify: async () => true }),
    deviceKeyPair: { publicKeyB64: devicePub, privateKeyB64: bytesToBase64(kp.privateKey) },
    deviceId,
    clock: () => 1000,
  });
  return { svc, deviceId, devicePub };
}

const enc = (s) => new TextEncoder().encode(s);

test("AF5: sign/verify round-trips; the signature carries the signer's self-cert device identity", async () => {
  const crypto = new BrowserCryptoProvider();
  const { svc, deviceId, devicePub } = await makeDeviceService(crypto);
  const signable = enc("account-state-event-body");
  const signed = await svc.signAccountStateEvent(signable);
  assert.equal(signed.originDeviceId, deviceId);
  assert.equal(signed.originDevicePublicKeyB64, devicePub);
  assert.equal(await svc.verifyAccountStateEventSig({ signableBytes: signable, ...signed }), true);
});

test("AF5/F2: a TAMPERED body fails verification", async () => {
  const crypto = new BrowserCryptoProvider();
  const { svc } = await makeDeviceService(crypto);
  const signed = await svc.signAccountStateEvent(enc("original"));
  assert.equal(await svc.verifyAccountStateEventSig({ signableBytes: enc("tampered"), ...signed }), false);
});

test("AF5/F2: a FORGED originDeviceId (not the self-cert of the signing key) fails — no origin impersonation", async () => {
  const crypto = new BrowserCryptoProvider();
  const { svc, devicePub } = await makeDeviceService(crypto);
  const signable = enc("body");
  const signed = await svc.signAccountStateEvent(signable);
  // Claim a DIFFERENT origin device id while keeping the real pubkey+sig.
  const forged = await svc.verifyAccountStateEventSig({
    signableBytes: signable,
    originDeviceId: "rez:dev:" + "f".repeat(64),
    originDevicePublicKeyB64: devicePub,
    sigB64: signed.sigB64,
  });
  assert.equal(forged, false, "self-cert mismatch (deviceId != deviceIdFor(pub)) is rejected");
});

test("AF5: a signature from ANOTHER device does not verify against a claimed sibling identity", async () => {
  const crypto = new BrowserCryptoProvider();
  const a = await makeDeviceService(crypto);
  const b = await makeDeviceService(crypto);
  const signable = enc("body");
  const signedByA = await a.svc.signAccountStateEvent(signable);
  // Attacker (device A) tries to attribute the event to device B's identity: it
  // cannot produce B's pubkey+matching sig, so claiming B's deviceId with A's sig
  // fails self-cert, and using A's pubkey but B's deviceId also fails self-cert.
  const spoofB = await b.svc.verifyAccountStateEventSig({
    signableBytes: signable,
    originDeviceId: b.deviceId,
    originDevicePublicKeyB64: signedByA.originDevicePublicKeyB64,
    sigB64: signedByA.sigB64,
  });
  assert.equal(spoofB, false);
});
