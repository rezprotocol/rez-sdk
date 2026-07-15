import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase64, DeviceRegistrationV1 } from "@rezprotocol/core";
import {
  generateDeviceKeyPair,
  buildSignedDeviceRegistration,
  verifyDeviceRegistration,
} from "../src/device/index.js";
import { verifyPayload } from "../src/auth/signing.js";

// Account keypair in the SDK convention (SPKI public / PKCS8 private, base64) —
// the same export path Identity.generate() uses.
async function generateAccountKeyPair() {
  const subtle = globalThis.crypto.subtle;
  const kp = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pub = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));
  const priv = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
  return { publicKeyB64: bytesToBase64(pub), privateKeyB64: bytesToBase64(priv) };
}

const NOW = 1_700_000_000_000;

test("generateDeviceKeyPair returns a distinct SPKI/PKCS8 base64 keypair", async () => {
  const a = await generateDeviceKeyPair();
  const b = await generateDeviceKeyPair();
  assert.ok(a.publicKeyB64.length > 0 && a.privateKeyB64.length > 0);
  assert.notEqual(a.publicKeyB64, a.privateKeyB64);
  assert.notEqual(a.publicKeyB64, b.publicKeyB64, "fresh each call");
});

test("account key signs a device registration that verifies end-to-end (WebCrypto)", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  const reg = await buildSignedDeviceRegistration({ account, devicePublicKeyB64: device.publicKeyB64, nowMs: NOW });

  assert.equal(reg.accountIdentityPublicKeyB64, account.publicKeyB64);
  assert.equal(reg.devicePublicKeyB64, device.publicKeyB64);
  assert.equal(reg.deviceId, DeviceRegistrationV1.deviceIdFor(device.publicKeyB64), "self-certifying deviceId");

  const res = await verifyDeviceRegistration({ registration: reg, expectedAccountIdentityPublicKeyB64: account.publicKeyB64, nowMs: NOW + 1000 });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.deviceId, reg.deviceId);
});

test("TRUST ANCHOR: a valid registration is rejected when the expected account differs", async () => {
  const attacker = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  const evil = await buildSignedDeviceRegistration({ account: attacker, devicePublicKeyB64: device.publicKeyB64, nowMs: NOW });
  const victim = await generateAccountKeyPair();
  const res = await verifyDeviceRegistration({ registration: evil, expectedAccountIdentityPublicKeyB64: victim.publicKeyB64, nowMs: NOW + 1000 });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "account mismatch (not the expected account)");
});

test("verify defaults nowMs to the current clock (expiry never silently skipped)", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  // Built with default issuedAtMs (now); verified with default nowMs (now) → valid.
  const fresh = await buildSignedDeviceRegistration({ account, devicePublicKeyB64: device.publicKeyB64 });
  const ok = await verifyDeviceRegistration({ registration: fresh, expectedAccountIdentityPublicKeyB64: account.publicKeyB64 });
  assert.equal(ok.ok, true, ok.reason);
  // A registration that expired in the past is rejected under the default clock.
  const stale = await buildSignedDeviceRegistration({ account, devicePublicKeyB64: device.publicKeyB64, nowMs: NOW, ttlMs: 60 * 1000 });
  const expired = await verifyDeviceRegistration({ registration: stale, expectedAccountIdentityPublicKeyB64: account.publicKeyB64 });
  assert.equal(expired.ok, false);
  assert.equal(expired.reason, "expired");
});

test("the signed registration round-trips through toJSON/fromJSON and still verifies", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  const reg = await buildSignedDeviceRegistration({ account, devicePublicKeyB64: device.publicKeyB64, nowMs: NOW });
  const back = DeviceRegistrationV1.fromJSON(reg.toJSON());
  const res = await verifyDeviceRegistration({ registration: back, expectedAccountIdentityPublicKeyB64: account.publicKeyB64, nowMs: NOW + 1000 });
  assert.equal(res.ok, true, res.reason);
});

test("tampering the signed body (extending expiry) fails verification", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  const reg = await buildSignedDeviceRegistration({ account, devicePublicKeyB64: device.publicKeyB64, nowMs: NOW });
  const tampered = reg.toJSON();
  tampered.expiresAtMs = tampered.expiresAtMs + 10 * 365 * 24 * 60 * 60 * 1000;
  const res = await verifyDeviceRegistration({ registration: tampered, expectedAccountIdentityPublicKeyB64: account.publicKeyB64, nowMs: NOW + 1000 });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature invalid");
});

test("verify enforces the issued/expires window when nowMs is given", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  const ttlMs = 60 * 1000;
  const reg = await buildSignedDeviceRegistration({ account, devicePublicKeyB64: device.publicKeyB64, nowMs: NOW, ttlMs });
  const anchor = account.publicKeyB64;

  const early = await verifyDeviceRegistration({ registration: reg, expectedAccountIdentityPublicKeyB64: anchor, nowMs: NOW - 1 });
  assert.equal(early.ok, false);
  assert.equal(early.reason, "not yet valid");

  const expired = await verifyDeviceRegistration({ registration: reg, expectedAccountIdentityPublicKeyB64: anchor, nowMs: NOW + ttlMs + 1 });
  assert.equal(expired.ok, false);
  assert.equal(expired.reason, "expired");
});

test("buildSignedDeviceRegistration validates its inputs", async () => {
  const device = await generateDeviceKeyPair();
  await assert.rejects(
    () => buildSignedDeviceRegistration({ account: null, devicePublicKeyB64: device.publicKeyB64 }),
    /requires account.publicKeyB64/,
  );
  const account = await generateAccountKeyPair();
  await assert.rejects(
    () => buildSignedDeviceRegistration({ account, devicePublicKeyB64: "" }),
    /requires devicePublicKeyB64/,
  );
});
