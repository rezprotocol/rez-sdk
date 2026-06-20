import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase64, DeviceRegistrationV1, REZ_CONTRACT_TYPES } from "@rezprotocol/core";

import { IdentityCapability } from "../src/capabilities/IdentityCapability.js";
import { DevicesCapability } from "../src/capabilities/DevicesCapability.js";
import { RezClient } from "../src/client/RezClient.js";
import { generateDeviceKeyPair } from "../src/device/index.js";
import { verifyPayload } from "../src/auth/signing.js";

const T = REZ_CONTRACT_TYPES;
const NOW = 1_700_000_000_000;
const INBOX = "rez:inbox:device-bind-test";

async function generateAccountKeyPair() {
  const subtle = globalThis.crypto.subtle;
  const kp = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pub = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));
  const priv = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
  return { publicKeyB64: bytesToBase64(pub), privateKeyB64: bytesToBase64(priv) };
}

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

test("buildDeviceInboxBinding produces a DEVICE-signed binding that verifies against the device key", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  const deviceId = DeviceRegistrationV1.deviceIdFor(device.publicKeyB64);
  const cap = new IdentityCapability({ pool: poolStub, eventBus: eventBusStub, identity: makeIdentity({ account, device, deviceId }) });

  const binding = await cap.buildDeviceInboxBinding({ inboxId: INBOX, nowMs: NOW });
  assert.equal(binding.devicePublicKeyB64, device.publicKeyB64);
  assert.equal(binding.deviceId, deviceId, "self-certifying deviceId");
  assert.equal(binding.inboxId, INBOX);
  assert.equal(binding.issuedAtMs, NOW);
  assert.ok(binding.expiresAtMs > NOW);

  // The signature is over the canonical signed body, by the DEVICE key (C) —
  // NOT the account key. Verify against the device public key exactly as the
  // home's DeviceHandler does (signableBytes over the same body keys).
  const body = {
    v: binding.v,
    purpose: binding.purpose,
    devicePublicKeyB64: binding.devicePublicKeyB64,
    deviceId: binding.deviceId,
    inboxId: binding.inboxId,
    issuedAtMs: binding.issuedAtMs,
    expiresAtMs: binding.expiresAtMs,
  };
  const okDevice = await verifyPayload({ publicKeyB64: device.publicKeyB64, payload: body, signatureB64: binding.sig.sigB64 });
  assert.equal(okDevice, true, "binding verifies against the device key");
  const okAccount = await verifyPayload({ publicKeyB64: account.publicKeyB64, payload: body, signatureB64: binding.sig.sigB64 });
  assert.equal(okAccount, false, "binding is NOT signed by the account key");
});

test("buildDeviceInboxBinding fails loud without a device key or inboxId", async () => {
  const account = await generateAccountKeyPair();
  const noDevice = new IdentityCapability({ pool: poolStub, eventBus: eventBusStub, identity: makeIdentity({ account, device: null, deviceId: null }) });
  await assert.rejects(() => noDevice.buildDeviceInboxBinding({ inboxId: INBOX }), /no device keypair/);

  const device = await generateDeviceKeyPair();
  const deviceId = DeviceRegistrationV1.deviceIdFor(device.publicKeyB64);
  const cap = new IdentityCapability({ pool: poolStub, eventBus: eventBusStub, identity: makeIdentity({ account, device, deviceId }) });
  await assert.rejects(() => cap.buildDeviceInboxBinding({ inboxId: "  " }), /inboxId is required/);
});

test("DevicesCapability.bind sends DEVICE_BIND with both records verbatim and returns the body", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  const deviceId = DeviceRegistrationV1.deviceIdFor(device.publicKeyB64);
  const idCap = new IdentityCapability({ pool: poolStub, eventBus: eventBusStub, identity: makeIdentity({ account, device, deviceId }) });
  const reg = await idCap.buildDeviceRegistration({ nowMs: NOW });
  const binding = await idCap.buildDeviceInboxBinding({ inboxId: INBOX, nowMs: NOW });

  const calls = [];
  const pool = {
    async sendRequest(req) {
      calls.push(req);
      return { body: { inboxId: INBOX, deviceId } };
    },
  };
  const cap = new DevicesCapability({ pool });
  const res = await cap.bind({ deviceRegistration: reg, deviceInboxBinding: binding });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].type, T.DEVICE_BIND);
  assert.equal(calls[0].expectedResponseType, T.DEVICE_BIND_RES);
  assert.deepEqual(calls[0].body.deviceRegistration, reg.toJSON(), "registration carried verbatim");
  assert.deepEqual(calls[0].body.deviceInboxBinding, binding.toJSON(), "binding carried verbatim");
  assert.deepEqual(res, { inboxId: INBOX, deviceId });

  await assert.rejects(() => cap.bind({ deviceRegistration: reg }), /requires deviceRegistration and deviceInboxBinding/);
});

test("DevicesCapability.revoke sends DEVICE_REVOKE with the revoke record and returns the body", async () => {
  const calls = [];
  const pool = {
    async sendRequest(req) {
      calls.push(req);
      return { body: { inboxId: INBOX, revokedDeviceId: "rez:dev:gone", revoked: true } };
    },
  };
  const cap = new DevicesCapability({ pool });
  const revokeJson = { v: 1, accountIdentityPublicKeyB64: "acct", revokedDeviceId: "rez:dev:gone" };
  const res = await cap.revoke({ deviceRevoke: revokeJson });

  assert.equal(calls[0].type, T.DEVICE_REVOKE);
  assert.equal(calls[0].expectedResponseType, T.DEVICE_REVOKE_RES);
  assert.deepEqual(calls[0].body.deviceRevoke, revokeJson);
  assert.equal(res.revoked, true);

  await assert.rejects(() => cap.revoke({}), /requires deviceRevoke/);
});

test("RezClient exposes a devices capability", () => {
  const client = new RezClient({
    pool: { authState: "idle" },
    eventBus: { on: () => () => {} },
    authMachine: {},
    identity: { accountId: "rez:acct:test", publicKeyB64: "p", privateKeyB64: "s" },
  });
  assert.ok(client.devices instanceof DevicesCapability);
});
