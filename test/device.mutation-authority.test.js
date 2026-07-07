import test from "node:test";
import assert from "node:assert/strict";
import {
  bytesToBase64,
  DeviceRegistrationV1,
  DeviceInboxBindingV1,
  DEVICE_INBOX_BINDING_PURPOSE,
  AccountDeviceMutationV1,
  AccountAuthorityStateV1,
} from "@rezprotocol/core";
import {
  generateDeviceKeyPair,
  buildSignedAccountDeviceMutation,
  buildSignedAccountAuthorityState,
} from "../src/device/index.js";
import { verifyPayload } from "../src/auth/signing.js";

// S2.5 S11 L9: dual-mode AccountDeviceMutationV1 + AccountAuthorityStateV1
// builders. REAL WebCrypto — the produced signature must verify against the exact
// bytes the record's signableBytes recomputes (no representation drift), proven by
// verifying the signature over signableBytes, not a mock.

async function generateAccountKeyPair() {
  const subtle = globalThis.crypto.subtle;
  const kp = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pub = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));
  const priv = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
  return { publicKeyB64: bytesToBase64(pub), privateKeyB64: bytesToBase64(priv) };
}

async function signedDeviceBinding({ device, inboxId, nowMs }) {
  const body = {
    v: 1, purpose: DEVICE_INBOX_BINDING_PURPOSE,
    devicePublicKeyB64: device.publicKeyB64, deviceId: DeviceRegistrationV1.deviceIdFor(device.publicKeyB64),
    inboxId, issuedAtMs: nowMs, expiresAtMs: nowMs + 3_600_000,
  };
  const subtle = globalThis.crypto.subtle;
  const key = await subtle.importKey("pkcs8", Buffer.from(device.privateKeyB64, "base64"), "Ed25519", false, ["sign"]);
  const { canonicalJSONStringify } = await import("@rezprotocol/core");
  const sig = new Uint8Array(await subtle.sign("Ed25519", key, new TextEncoder().encode(canonicalJSONStringify(body))));
  return new DeviceInboxBindingV1({ ...body, sig: { alg: "ed25519", sigB64: bytesToBase64(sig) } });
}

const NOW = 1_700_000_000_000;

test("PRIMARY device.add mutation: account-signed, signer == account, verifies over signableBytes", async () => {
  const account = await generateAccountKeyPair();
  const sibling = await generateDeviceKeyPair();
  const binding = await signedDeviceBinding({ device: sibling, inboxId: "inbox:new-device", nowMs: NOW });

  const mutation = await buildSignedAccountDeviceMutation({
    signer: account,
    accountIdentityPublicKeyB64: account.publicKeyB64,
    opId: "op-1", expectedRevision: 0, action: "device.add",
    target: { deviceInboxBinding: binding.toJSON() },
    nowMs: NOW,
  });

  assert.ok(mutation instanceof AccountDeviceMutationV1);
  assert.equal(mutation.accountIdentityPublicKeyB64, account.publicKeyB64);
  assert.equal(mutation.signerPublicKeyB64, account.publicKeyB64, "primary signs with the account key");
  assert.equal(mutation.action, "device.add");
  assert.equal(mutation.expectedRevision, 0);

  const ok = await verifyPayload({
    publicKeyB64: account.publicKeyB64,
    payload: JSON.parse(new TextDecoder().decode(AccountDeviceMutationV1.signableBytes(mutation))),
    signatureB64: mutation.sig.sigB64,
  });
  assert.equal(ok, true, "signature verifies over the record's canonical signable bytes");
});

test("DELEGATED device.revoke mutation: device-signed, signer == device key C (not account)", async () => {
  const account = await generateAccountKeyPair();
  const device = await generateDeviceKeyPair(); // the delegated submitter C
  const target = await generateDeviceKeyPair();

  const mutation = await buildSignedAccountDeviceMutation({
    signer: device,
    accountIdentityPublicKeyB64: account.publicKeyB64,
    opId: "op-2", expectedRevision: 3, action: "device.revoke",
    target: { revokedDeviceId: DeviceRegistrationV1.deviceIdFor(target.publicKeyB64), revokedCertId: "rez:cap:leaf-x" },
    nowMs: NOW,
  });

  assert.equal(mutation.accountIdentityPublicKeyB64, account.publicKeyB64, "names the account");
  assert.equal(mutation.signerPublicKeyB64, device.publicKeyB64, "delegated signs with C, not the account");
  assert.notEqual(mutation.signerPublicKeyB64, account.publicKeyB64);

  const ok = await verifyPayload({
    publicKeyB64: device.publicKeyB64,
    payload: JSON.parse(new TextDecoder().decode(AccountDeviceMutationV1.signableBytes(mutation))),
    signatureB64: mutation.sig.sigB64,
  });
  assert.equal(ok, true);
});

test("mutation envelope is short-lived (default 5-minute TTL)", async () => {
  const account = await generateAccountKeyPair();
  const target = await generateDeviceKeyPair();
  const mutation = await buildSignedAccountDeviceMutation({
    signer: account, accountIdentityPublicKeyB64: account.publicKeyB64,
    opId: "op-3", expectedRevision: 0, action: "device.revoke",
    target: { revokedDeviceId: DeviceRegistrationV1.deviceIdFor(target.publicKeyB64) },
    nowMs: NOW,
  });
  assert.equal(mutation.expiresAtMs - mutation.issuedAtMs, 5 * 60 * 1000);
});

test("mutation builder fails loud on a bad action / missing opId / negative revision", async () => {
  const account = await generateAccountKeyPair();
  await assert.rejects(() => buildSignedAccountDeviceMutation({ signer: account, accountIdentityPublicKeyB64: account.publicKeyB64, opId: "x", expectedRevision: 0, action: "device.frobnicate", target: {} }), /action must be/);
  await assert.rejects(() => buildSignedAccountDeviceMutation({ signer: account, accountIdentityPublicKeyB64: account.publicKeyB64, opId: "", expectedRevision: 0, action: "device.revoke", target: {} }), /non-empty opId/);
  await assert.rejects(() => buildSignedAccountDeviceMutation({ signer: account, accountIdentityPublicKeyB64: account.publicKeyB64, opId: "x", expectedRevision: -1, action: "device.revoke", target: {} }), /non-negative integer expectedRevision/);
});

test("authority-state: revokedCertIds are sorted + deduped before signing (canonical, verifies)", async () => {
  const account = await generateAccountKeyPair();
  const state = await buildSignedAccountAuthorityState({
    signer: account,
    accountIdentityPublicKeyB64: account.publicKeyB64,
    epoch: 5,
    revokedCertIds: ["rez:cap:zzz", "rez:cap:aaa", "rez:cap:zzz", "rez:cap:mmm"],
    minValidIssuedAtMs: 42,
    nowMs: NOW,
  });

  assert.ok(state instanceof AccountAuthorityStateV1);
  assert.deepEqual(state.revokedCertIds, ["rez:cap:aaa", "rez:cap:mmm", "rez:cap:zzz"], "sorted + deduped");
  assert.equal(state.epoch, 5);
  assert.equal(state.minValidIssuedAtMs, 42);
  assert.deepEqual(state.toRevocationState(), { revokedCertIds: ["rez:cap:aaa", "rez:cap:mmm", "rez:cap:zzz"], minValidIssuedAtMs: 42 });

  const ok = await verifyPayload({
    publicKeyB64: account.publicKeyB64,
    payload: JSON.parse(new TextDecoder().decode(AccountAuthorityStateV1.signableBytes(state))),
    signatureB64: state.sig.sigB64,
  });
  assert.equal(ok, true, "the signature matches the normalized canonical form");
});

test("authority-state: an empty revocation set still signs a valid epoch snapshot", async () => {
  const account = await generateAccountKeyPair();
  const state = await buildSignedAccountAuthorityState({
    signer: account, accountIdentityPublicKeyB64: account.publicKeyB64, epoch: 1, nowMs: NOW,
  });
  assert.deepEqual(state.revokedCertIds, []);
  assert.equal(state.minValidIssuedAtMs, 0);
  const ok = await verifyPayload({
    publicKeyB64: account.publicKeyB64,
    payload: JSON.parse(new TextDecoder().decode(AccountAuthorityStateV1.signableBytes(state))),
    signatureB64: state.sig.sigB64,
  });
  assert.equal(ok, true);
});
