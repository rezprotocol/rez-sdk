import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  REZ_CONTRACT_TYPES,
  AccountDeviceCapabilityV1,
  ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
  DeviceRegistrationV1,
  relayKeyIdForNodePublicKeyB64,
  nodeKeyIdForNodePublicKeyB64,
} from "@rezprotocol/core";
import { AuthStateMachine } from "../src/auth/AuthStateMachine.js";
import { signPayload, verifyPayload } from "../src/auth/signing.js";

// S2.5 S7 / audit F1: the SDK side of cert-backed delegated session auth. A
// PRIMARY device signs the session-auth payload with its account root key
// (B-sign) — unchanged. A DELEGATED device holds no B-sign private key: it signs
// with its per-device key C and attaches { signerPublicKeyB64, certChain } so the
// node can anchor the chain to the claimed account. Real Ed25519 (node:crypto
// SPKI/PKCS8) through the live AuthStateMachine, with a stub transport that signs
// a real challenge and captures the produced authenticate body.

const T = REZ_CONTRACT_TYPES;
const noopBus = { emit() {} };

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyB64: Buffer.from(publicKey.export({ format: "der", type: "spki" })).toString("base64"),
    privateKeyB64: Buffer.from(privateKey.export({ format: "der", type: "pkcs8" })).toString("base64"),
  };
}

function buildLeafCert({ account, signer, granteePubB64, capabilities, now }) {
  const fields = {
    v: 1,
    purpose: ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
    accountIdentityPublicKeyB64: account,
    parentCertId: null,
    granteeDevicePublicKeyB64: granteePubB64,
    granteeDeviceId: DeviceRegistrationV1.deviceIdFor(granteePubB64),
    capabilities,
    maxDelegationDepth: 0,
    issuedAtMs: now - 1000,
    expiresAtMs: now + 3_600_000,
    signerPublicKeyB64: signer.publicKeyB64,
  };
  const certId = AccountDeviceCapabilityV1.deriveCertId(fields);
  const msg = AccountDeviceCapabilityV1.signableBytes({ ...fields, certId });
  const sigB64 = Buffer.from(
    crypto.sign(null, Buffer.from(msg), crypto.createPrivateKey({ key: Buffer.from(signer.privateKeyB64, "base64"), format: "der", type: "pkcs8" })),
  ).toString("base64");
  return new AccountDeviceCapabilityV1({ ...fields, certId, sig: { alg: "ed25519", sigB64 } });
}

// Stub transport: signs a real session-challenge with `node`, captures the
// authenticate body, and returns session.ready.
function makeTransport({ node, captured }) {
  return {
    url: "ws://node.test/ws",
    async sendRequest({ type, body }) {
      if (type === T.SESSION_HELLO) {
        captured.hello = body;
        const now = Date.now();
        const base = {
          challengeId: "ch-1",
          nonceB64: Buffer.from(crypto.randomBytes(16)).toString("base64"),
          issuedAtMs: now,
          expiresAtMs: now + 60_000,
          // ADR-RELAY-IDENTITY: the SDK validates the challenge binding, so
          // the fake node's IDs must derive from its real key.
          nodeKeyId: nodeKeyIdForNodePublicKeyB64(node.publicKeyB64),
          nodePublicKeyB64: node.publicKeyB64,
          relayKeyId: relayKeyIdForNodePublicKeyB64(node.publicKeyB64),
          wsPath: "/ws",
        };
        const signatureB64 = await signPayload({
          privateKeyB64: node.privateKeyB64,
          payload: {
            kind: "session-challenge",
            challengeId: base.challengeId,
            nonceB64: base.nonceB64,
            issuedAtMs: base.issuedAtMs,
            expiresAtMs: base.expiresAtMs,
            nodeKeyId: base.nodeKeyId,
            nodePublicKeyB64: base.nodePublicKeyB64,
            relayKeyId: base.relayKeyId,
            accountIdentityPublicKeyB64: body.accountIdentityPublicKeyB64,
            sessionDeviceId: body.deviceId,
            wsPath: base.wsPath,
          },
        });
        captured.challenge = { ...base, signatureB64 };
        return { t: T.SESSION_CHALLENGE, body: { ...base, signatureB64 } };
      }
      if (type === T.SESSION_AUTHENTICATE) {
        captured.auth = body;
        return { t: T.SESSION_READY, body: { serverTime: Date.now() } };
      }
      throw new Error("unexpected request type " + type);
    },
  };
}

// The canonical session-auth payload, for re-verifying the SDK's signature.
function authPayload({ captured, accountPubB64, deviceId }) {
  return {
    kind: "session-auth",
    challengeId: captured.challenge.challengeId,
    nonceB64: captured.challenge.nonceB64,
    nodeKeyId: captured.challenge.nodeKeyId,
    nodePublicKeyB64: captured.challenge.nodePublicKeyB64,
    relayKeyId: captured.challenge.relayKeyId,
    publicKeyB64: accountPubB64,
    deviceId,
    wsPath: captured.challenge.wsPath,
  };
}

test("primary device: signs session-auth with B-sign, no cert chain in the body", async () => {
  const node = genKey();
  const B = genKey();
  const captured = {};
  const sm = new AuthStateMachine({
    identity: { publicKeyB64: B.publicKeyB64, privateKeyB64: B.privateKeyB64, deviceId: "dev:primary" },
    eventBus: noopBus,
  });
  await sm.authenticate(makeTransport({ node, captured }));

  assert.equal(captured.auth.signerPublicKeyB64, undefined, "primary body carries no signer key");
  assert.equal(captured.auth.certChain, undefined, "primary body carries no cert chain");
  const ok = await verifyPayload({
    publicKeyB64: B.publicKeyB64,
    signatureB64: captured.auth.signatureB64,
    payload: authPayload({ captured, accountPubB64: B.publicKeyB64, deviceId: "dev:primary" }),
  });
  assert.equal(ok, true, "primary signature verifies against B-sign");
});

test("delegated device: signs with C and attaches signerPublicKeyB64 + certChain", async () => {
  const node = genKey();
  const B = genKey(); // account root (no private key on the delegated identity)
  const C = genKey(); // per-device key
  const now = Date.now();
  const deviceId = DeviceRegistrationV1.deviceIdFor(C.publicKeyB64);
  const cert = buildLeafCert({ account: B.publicKeyB64, signer: B, granteePubB64: C.publicKeyB64, capabilities: ["peerLink.create"], now });

  const captured = {};
  const sm = new AuthStateMachine({
    identity: {
      publicKeyB64: B.publicKeyB64, // claimed account; NO privateKeyB64
      deviceId,
      deviceKey: { publicKeyB64: C.publicKeyB64, privateKeyB64: C.privateKeyB64 },
      certChain: [cert.toJSON()],
    },
    eventBus: noopBus,
  });
  await sm.authenticate(makeTransport({ node, captured }));

  assert.equal(captured.hello.accountIdentityPublicKeyB64, B.publicKeyB64, "hello still claims account B");
  assert.equal(captured.hello.deviceId, deviceId, "hello carries C's self-cert deviceId");
  assert.equal(captured.auth.signerPublicKeyB64, C.publicKeyB64, "authenticate body carries C as the signer");
  assert.deepEqual(captured.auth.certChain, [cert.toJSON()], "authenticate body carries the cert chain verbatim");

  const okC = await verifyPayload({
    publicKeyB64: C.publicKeyB64,
    signatureB64: captured.auth.signatureB64,
    payload: authPayload({ captured, accountPubB64: B.publicKeyB64, deviceId }),
  });
  assert.equal(okC, true, "delegated signature verifies against C");
  const okB = await verifyPayload({
    publicKeyB64: B.publicKeyB64,
    signatureB64: captured.auth.signatureB64,
    payload: authPayload({ captured, accountPubB64: B.publicKeyB64, deviceId }),
  });
  assert.equal(okB, false, "delegated signature does NOT verify against B (signed by C)");
});

test("constructor fails loud for an identity with neither a private key nor a delegation", () => {
  assert.throws(
    () => new AuthStateMachine({ identity: { publicKeyB64: genKey().publicKeyB64 }, eventBus: noopBus }),
    /privateKeyB64 \(primary\) or identity\.deviceKey \+ certChain \(delegated\)/,
  );
});
