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

  await assert.rejects(() => cap.bind({ deviceRegistration: reg }), /requires deviceInboxBinding/);

  // S10: a DELEGATED session binds WITHOUT a registration — the session cert
  // chain IS the registration. The body must OMIT the key, not send null.
  const delegated = await cap.bind({ deviceInboxBinding: binding });
  assert.equal(calls.length, 2);
  assert.equal("deviceRegistration" in calls[1].body, false, "no registration key on a delegated bind");
  assert.deepEqual(calls[1].body.deviceInboxBinding, binding.toJSON());
  assert.deepEqual(delegated, { inboxId: INBOX, deviceId });
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

// ---- S2.5 S11: account device-mutation authority (build + submit + authority-state) ----

test("IdentityCapability.buildAccountDeviceMutation signs with the ACCOUNT key by default", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  const deviceId = DeviceRegistrationV1.deviceIdFor(device.publicKeyB64);
  const cap = new IdentityCapability({ pool: poolStub, eventBus: eventBusStub, identity: makeIdentity({ account, device, deviceId }) });

  const target = await generateDeviceKeyPair();
  const mutation = await cap.buildAccountDeviceMutation({
    opId: "op-a", expectedRevision: 2, action: "device.revoke",
    target: { revokedDeviceId: DeviceRegistrationV1.deviceIdFor(target.publicKeyB64) },
    nowMs: NOW,
  });
  assert.equal(mutation.accountIdentityPublicKeyB64, account.publicKeyB64);
  assert.equal(mutation.signerPublicKeyB64, account.publicKeyB64, "default signs with the account key");
});

test("IdentityCapability.buildAccountDeviceMutation signWith:'device' signs with the device key C", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  const deviceId = DeviceRegistrationV1.deviceIdFor(device.publicKeyB64);
  const cap = new IdentityCapability({ pool: poolStub, eventBus: eventBusStub, identity: makeIdentity({ account, device, deviceId }) });

  const target = await generateDeviceKeyPair();
  const mutation = await cap.buildAccountDeviceMutation({
    opId: "op-b", expectedRevision: 0, action: "device.revoke",
    target: { revokedDeviceId: DeviceRegistrationV1.deviceIdFor(target.publicKeyB64) },
    signWith: "device", nowMs: NOW,
  });
  assert.equal(mutation.accountIdentityPublicKeyB64, account.publicKeyB64, "still names the account");
  assert.equal(mutation.signerPublicKeyB64, device.publicKeyB64, "delegated signs with C");
});

test("IdentityCapability.buildAccountDeviceMutation signWith:'device' fails loud without a device key", async () => {
  const account = await generateAccountKeyPair();
  const cap = new IdentityCapability({ pool: poolStub, eventBus: eventBusStub, identity: makeIdentity({ account, device: null, deviceId: null }) });
  await assert.rejects(
    () => cap.buildAccountDeviceMutation({ opId: "x", expectedRevision: 0, action: "device.revoke", target: { revokedDeviceId: "rez:dev:z" }, signWith: "device" }),
    /no device keypair/,
  );
});

test("buildAccountAuthorityState signs the epoch snapshot with the account key", async () => {
  const account = await generateAccountKeyPair();
  const cap = new IdentityCapability({ pool: poolStub, eventBus: eventBusStub, identity: makeIdentity({ account, device: null, deviceId: null }) });
  const aCap = "rez:cap:" + "a".repeat(64);
  const bCap = "rez:cap:" + "b".repeat(64);
  const state = await cap.buildAccountAuthorityState({ epoch: 4, revokedCertIds: [bCap, aCap], nowMs: NOW });
  assert.equal(state.accountIdentityPublicKeyB64, account.publicKeyB64);
  assert.equal(state.signerPublicKeyB64, account.publicKeyB64);
  assert.deepEqual(state.revokedCertIds, [aCap, bCap]);
});

test("DevicesCapability.submitDeviceMutation sends ACCOUNT_DEVICE_MUTATION_SUBMIT verbatim", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair();
  const deviceId = DeviceRegistrationV1.deviceIdFor(device.publicKeyB64);
  const idCap = new IdentityCapability({ pool: poolStub, eventBus: eventBusStub, identity: makeIdentity({ account, device, deviceId }) });
  const target = await generateDeviceKeyPair();
  const mutation = await idCap.buildAccountDeviceMutation({
    opId: "op-c", expectedRevision: 0, action: "device.revoke",
    target: { revokedDeviceId: DeviceRegistrationV1.deviceIdFor(target.publicKeyB64) }, nowMs: NOW,
  });

  const calls = [];
  const pool = {
    async sendRequest(req) {
      calls.push(req);
      return { body: { revision: 1, devices: [], authorityState: { epoch: 1, revokedCertIds: [], minValidIssuedAtMs: 0 } } };
    },
  };
  const cap = new DevicesCapability({ pool });
  const res = await cap.submitDeviceMutation({ mutation });

  assert.equal(calls[0].type, T.ACCOUNT_DEVICE_MUTATION_SUBMIT);
  assert.equal(calls[0].expectedResponseType, T.ACCOUNT_DEVICE_MUTATION_SUBMIT_RES);
  assert.deepEqual(calls[0].body.mutation, mutation.toJSON(), "mutation carried verbatim");
  assert.equal(res.revision, 1);

  await assert.rejects(() => cap.submitDeviceMutation({}), /requires mutation/);
});

test("DevicesCapability.getAuthorityState sends ACCOUNT_AUTHORITY_STATE_GET (with + without an explicit account)", async () => {
  const calls = [];
  const pool = {
    async sendRequest(req) {
      calls.push(req);
      return { body: { epoch: 3, revokedCertIds: ["rez:cap:x"], minValidIssuedAtMs: 7 } };
    },
  };
  const cap = new DevicesCapability({ pool });

  const res = await cap.getAuthorityState({ accountIdentityPublicKeyB64: "acct-pub" });
  assert.equal(calls[0].type, T.ACCOUNT_AUTHORITY_STATE_GET);
  assert.equal(calls[0].expectedResponseType, T.ACCOUNT_AUTHORITY_STATE_GET_RES);
  assert.equal(calls[0].body.accountIdentityPublicKeyB64, "acct-pub");
  assert.equal(res.epoch, 3);

  await cap.getAuthorityState();
  assert.equal("accountIdentityPublicKeyB64" in calls[1].body, false, "omits the key when not supplied (home defaults to session account)");
});

test("DevicesCapability.publishDeviceBundle sends ACCOUNT_DEVICE_BUNDLE_PUBLISH verbatim", async () => {
  const calls = [];
  const pool = {
    async sendRequest(req) { calls.push(req); return { body: { deviceId: "rez:dev:x", prekeyVersion: 3, applied: true } }; },
  };
  const cap = new DevicesCapability({ pool });
  const bundle = { v: 1, deviceId: "rez:dev:x", prekeyVersion: 3 };
  const res = await cap.publishDeviceBundle({ bundle });
  assert.equal(calls[0].type, T.ACCOUNT_DEVICE_BUNDLE_PUBLISH);
  assert.equal(calls[0].expectedResponseType, T.ACCOUNT_DEVICE_BUNDLE_PUBLISH_RES);
  assert.deepEqual(calls[0].body.bundle, bundle);
  assert.equal(res.applied, true);
  await assert.rejects(() => cap.publishDeviceBundle({}), /requires bundle/);
});

test("DevicesCapability.getAccountDeviceSet sends ACCOUNT_DEVICE_SET_GET and returns the devices array", async () => {
  const calls = [];
  const pool = {
    async sendRequest(req) { calls.push(req); return { body: { devices: [{ deviceId: "rez:dev:a", prekeyVersion: 1, bundle: { deviceId: "rez:dev:a" } }] } }; },
  };
  const cap = new DevicesCapability({ pool });
  const res = await cap.getAccountDeviceSet({ accountIdentityPublicKeyB64: "acct-pub" });
  assert.equal(calls[0].type, T.ACCOUNT_DEVICE_SET_GET);
  assert.equal(calls[0].expectedResponseType, T.ACCOUNT_DEVICE_SET_GET_RES);
  assert.equal(calls[0].body.accountIdentityPublicKeyB64, "acct-pub");
  assert.equal(res.devices.length, 1);
  assert.equal(res.devices[0].deviceId, "rez:dev:a");

  await cap.getAccountDeviceSet();
  assert.equal("accountIdentityPublicKeyB64" in calls[1].body, false, "omits the key when not supplied");
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
