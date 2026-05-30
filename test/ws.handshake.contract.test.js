import test from "node:test";
import assert from "node:assert/strict";
import { UplinkPoolClient } from "../src/index.js";
import { REZ_CONTRACT_TYPES, CONTRACT_VERSION } from "@rezprotocol/core";
import { canonicalJSONStringify, deriveAccountIdFromPublicKey } from "@rezprotocol/core";
import { FakeWsHarness } from "./support/FakeWsHarness.js";
import { isHelloFrame, parseFrame, sendReady, sendListThreadsResponse, sendChallenge, getTestNodePublicKeyB64 } from "./support/ContractWsTestUtil.js";

async function createIdentityKeyPair() {
  const keyPair = await globalThis.crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const publicKeyBytes = new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", keyPair.publicKey));
  const privateKeyBytes = new Uint8Array(await globalThis.crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  return {
    publicKeyBytes,
    privateKeyBytes,
    accountId: deriveAccountIdFromPublicKey(publicKeyBytes),
    accountIdentityPublicKeyB64: Buffer.from(publicKeyBytes).toString("base64"),
    accountIdentityPrivateKeyB64: Buffer.from(privateKeyBytes).toString("base64"),
  };
}

test("sdk hello handshake includes contractVersion and completes authenticated bootstrap", async () => {
  const harness = new FakeWsHarness();
  const identity = await createIdentityKeyPair();
  let sawHello = false;
  let sawAuthenticate = false;
  harness.register("ws://a/ws", (ws) => {
    ws.addEventListener("message", async (evt) => {
      const frame = parseFrame(evt);
      if (isHelloFrame(frame)) {
        sawHello = true;
        assert.equal(frame.body.contractVersion, CONTRACT_VERSION);
        assert.equal(typeof frame.body.deviceId, "string");
        assert.ok(frame.body.deviceId.length > 0);
        await sendChallenge(ws, frame.id, frame.body || {});
        return;
      }
      if (frame?.t === REZ_CONTRACT_TYPES.SESSION_AUTHENTICATE) {
        sawAuthenticate = true;
        sendReady(ws, frame.id, "a");
        return;
      }
      sendListThreadsResponse(ws, frame.id, "a");
    });
  });

  const client = new UplinkPoolClient({
    uplinks: ["ws://a/ws"],
    wsFactory: (url) => harness.factory(url),
    accountId: identity.accountId,
    accountIdentityPublicKeyB64: identity.accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64: identity.accountIdentityPrivateKeyB64,
  });
  await client.connect();
  assert.equal(sawHello, true);
  assert.equal(sawAuthenticate, true);
  await client.request(REZ_CONTRACT_TYPES.MAILBOX_LIST, { mailboxId: "mbox:test" });
  await client.close();
});

test("sdk can complete session challenge authentication when identity keys are configured", async () => {
  const harness = new FakeWsHarness();
  const {
    publicKeyBytes,
    accountId,
    accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64,
  } = await createIdentityKeyPair();
  let sawAuthenticate = false;
  let helloDeviceId = "";
  let capturedChallenge = null;
  harness.register("ws://auth/ws", (ws) => {
    ws.addEventListener("message", async (evt) => {
      const frame = parseFrame(evt);
      if (isHelloFrame(frame)) {
        assert.equal(frame.body.contractVersion, CONTRACT_VERSION);
        assert.equal(frame.body.accountIdentityPublicKeyB64, accountIdentityPublicKeyB64);
        helloDeviceId = String(frame.body.deviceId || "");
        capturedChallenge = await sendChallenge(ws, frame.id, frame.body || {});
        return;
      }
      if (frame && frame.t === REZ_CONTRACT_TYPES.SESSION_AUTHENTICATE) {
        const verifyKey = await globalThis.crypto.subtle.importKey("spki", publicKeyBytes, "Ed25519", true, ["verify"]);
        // CRITICAL-2: the SDK now binds the node identity into the signed
        // session-auth payload so the signature is non-portable across nodes.
        // Reconstruct the same canonical payload the SDK signed.
        const payload = new TextEncoder().encode(canonicalJSONStringify({
          kind: "session-auth",
          challengeId: capturedChallenge.challengeId,
          nonceB64: capturedChallenge.nonceB64,
          nodeKeyId: capturedChallenge.nodeKeyId,
          nodePublicKeyB64: capturedChallenge.nodePublicKeyB64,
          relayKeyId: capturedChallenge.relayKeyId,
          publicKeyB64: accountIdentityPublicKeyB64,
          deviceId: helloDeviceId,
          wsPath: capturedChallenge.wsPath,
        }));
        const ok = await globalThis.crypto.subtle.verify(
          "Ed25519",
          verifyKey,
          Buffer.from(String((frame.body && frame.body.signatureB64) || ""), "base64"),
          payload,
        );
        assert.equal(ok, true);
        assert.equal(frame.body && frame.body.hostedInboxDelegation, undefined);
        assert.equal(frame.body && frame.body.x3dhBinding, undefined);
        sawAuthenticate = true;
        sendReady(ws, frame.id, "auth");
        return;
      }
      sendListThreadsResponse(ws, frame.id, "auth");
    });
  });

  const client = new UplinkPoolClient({
    uplinks: ["ws://auth/ws"],
    wsFactory: (url) => harness.factory(url),
    accountId,
    accountIdentityPublicKeyB64,
    accountIdentityPrivateKeyB64,
  });
  await client.connect();
  assert.equal(sawAuthenticate, true);
  await client.close();
});
