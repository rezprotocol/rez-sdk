import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase64, DeviceRegistrationV1 } from "@rezprotocol/core";

import { IdentityCapability } from "../src/capabilities/IdentityCapability.js";
import { generateDeviceKeyPair, verifyDeviceRegistration } from "../src/device/index.js";

async function generateAccountKeyPair() {
  const subtle = globalThis.crypto.subtle;
  const kp = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pub = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));
  const priv = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
  return { publicKeyB64: bytesToBase64(pub), privateKeyB64: bytesToBase64(priv) };
}

// Minimal stubs for the non-identity collaborators IdentityCapability holds.
const poolStub = { authState: "authenticated", getSessionInfo: () => ({}) };
const eventBusStub = { on: () => () => {} };

function makeIdentity({ account, device, deviceId }) {
  return {
    accountId: "rez:acct:test",
    deviceId,
    publicKeyB64: account.publicKeyB64,
    privateKeyB64: account.privateKeyB64,
    deviceKey: device ? { publicKeyB64: device.publicKeyB64, privateKeyB64: device.privateKeyB64 } : undefined,
  };
}

const NOW = 1_700_000_000_000;

test("getDeviceKeyPublicKeyB64 surfaces the persisted device public key", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  const deviceId = DeviceRegistrationV1.deviceIdFor(device.publicKeyB64);
  const cap = new IdentityCapability({ pool: poolStub, eventBus: eventBusStub, identity: makeIdentity({ account, device, deviceId }) });

  assert.equal(cap.getDeviceKeyPublicKeyB64(), device.publicKeyB64);
  assert.equal(cap.getDeviceId(), deviceId);
});

test("buildDeviceRegistration produces an account-signed registration that verifies end-to-end", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  const deviceId = DeviceRegistrationV1.deviceIdFor(device.publicKeyB64);
  const cap = new IdentityCapability({ pool: poolStub, eventBus: eventBusStub, identity: makeIdentity({ account, device, deviceId }) });

  const reg = await cap.buildDeviceRegistration({ nowMs: NOW });
  assert.equal(reg.devicePublicKeyB64, device.publicKeyB64);
  assert.equal(reg.accountIdentityPublicKeyB64, account.publicKeyB64);
  assert.equal(reg.deviceId, deviceId, "self-certifying deviceId");

  const res = await verifyDeviceRegistration({
    registration: reg,
    expectedAccountIdentityPublicKeyB64: account.publicKeyB64,
    nowMs: NOW + 1000,
  });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.deviceId, deviceId);
});

test("a v1-style identity with no device key exposes null and fails loud on registration", async () => {
  const account = await generateAccountKeyPair();
  const cap = new IdentityCapability({
    pool: poolStub,
    eventBus: eventBusStub,
    identity: makeIdentity({ account, device: null, deviceId: "rez:dev:legacy" }),
  });

  assert.equal(cap.getDeviceKeyPublicKeyB64(), null);
  await assert.rejects(() => cap.buildDeviceRegistration({ nowMs: NOW }), /no device key/);
});
