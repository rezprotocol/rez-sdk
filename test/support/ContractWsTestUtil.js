import { REZ_CONTRACT_TYPES, CONTRACT_VERSION, deriveAccountIdFromPublicKey, canonicalJSONStringify, bytesToBase64 } from "@rezprotocol/core";

const T = REZ_CONTRACT_TYPES;

// Persistent fake-server node identity used to sign challenges. The SDK now
// verifies the challenge signature before signing back (docs/SECURITY_AUDIT.md
// CRITICAL-2), so the test server needs a real keypair.
let TEST_NODE_IDENTITY = null;
async function getTestNodeIdentity() {
  if (TEST_NODE_IDENTITY) return TEST_NODE_IDENTITY;
  const keyPair = await globalThis.crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const publicKeyBytes = new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", keyPair.publicKey));
  TEST_NODE_IDENTITY = {
    nodeKeyId: "test-node-key",
    nodePublicKeyB64: bytesToBase64(publicKeyBytes),
    relayKeyId: "test-relay-key",
    privateCryptoKey: keyPair.privateKey,
  };
  return TEST_NODE_IDENTITY;
}

export async function getTestNodePublicKeyB64() {
  const id = await getTestNodeIdentity();
  return id.nodePublicKeyB64;
}

async function signChallengeWithNodeKey(payload) {
  const id = await getTestNodeIdentity();
  const bytes = new TextEncoder().encode(canonicalJSONStringify(payload));
  const sig = await globalThis.crypto.subtle.sign("Ed25519", id.privateCryptoKey, bytes);
  return bytesToBase64(new Uint8Array(sig));
}

export function parseFrame(evt) {
  return JSON.parse(evt.data);
}

export function sendReady(ws, id, label = "x") {
  ws.send(JSON.stringify({
    id,
    t: T.SESSION_READY,
    type: T.SESSION_READY,
    v: CONTRACT_VERSION,
    body: {
      serverTime: Date.now(),
      accountId: "acct",
      capabilities: {
        contractVersion: CONTRACT_VERSION,
        deviceId: "dev",
        localInboxId: `ibox:${label}`,
        capabilities: [],
      },
    },
  }));
}

export async function sendChallenge(ws, id, helloBody = {}) {
  const node = await getTestNodeIdentity();
  const issuedAtMs = Date.now();
  const expiresAtMs = issuedAtMs + 30_000;
  const challengeId = `c_${id}`;
  const nonceB64 = "AQID";
  const wsPath = "/ws";
  const accountIdentityPublicKeyB64 = String((helloBody && helloBody.accountIdentityPublicKeyB64) || "");
  const sessionDeviceId = String((helloBody && helloBody.deviceId) || "");
  const signatureB64 = await signChallengeWithNodeKey({
    kind: "session-challenge",
    challengeId,
    nonceB64,
    issuedAtMs,
    expiresAtMs,
    nodeKeyId: node.nodeKeyId,
    nodePublicKeyB64: node.nodePublicKeyB64,
    relayKeyId: node.relayKeyId,
    accountIdentityPublicKeyB64,
    sessionDeviceId,
    wsPath,
  });
  // Test fakes may close the socket while sendChallenge is still resolving
  // (it's async because WebCrypto signing is async); only send if still open.
  const openState = typeof ws.OPEN === "number" ? ws.OPEN : 1;
  if (ws.readyState === openState) {
    ws.send(JSON.stringify({
      id,
      t: T.SESSION_CHALLENGE,
      type: T.SESSION_CHALLENGE,
      v: CONTRACT_VERSION,
      body: {
        challengeId,
        nonceB64,
        issuedAtMs,
        expiresAtMs,
        nodeKeyId: node.nodeKeyId,
        nodePublicKeyB64: node.nodePublicKeyB64,
        relayKeyId: node.relayKeyId,
        wsPath,
        signatureB64,
        localInboxId: "inbox:hosted:test",
      },
    }));
  }
  return {
    challengeId,
    nonceB64,
    nodeKeyId: node.nodeKeyId,
    nodePublicKeyB64: node.nodePublicKeyB64,
    relayKeyId: node.relayKeyId,
    wsPath,
    issuedAtMs,
    expiresAtMs,
  };
}

export function isAuthenticateFrame(frame) {
  return frame && frame.t === T.SESSION_AUTHENTICATE;
}

/**
 * Handles the full hello→challenge→authenticate→ready handshake.
 * Returns true if the frame was consumed (caller should return early).
 *
 * `sendChallenge` is async (it has to sign with WebCrypto), but this helper
 * fires it without awaiting so the caller's `if (handleHandshake(...)) return;`
 * pattern still works with a synchronous truthy/falsey check. The challenge
 * lands on the wire a tick or two later; the SDK awaits it before signing
 * the authenticate frame.
 */
export function handleHandshake(ws, frame, label = "x") {
  if (isHelloFrame(frame)) {
    sendChallenge(ws, frame.id, frame.body || {}).catch(() => { /* test transport closed */ });
    return true;
  }
  if (isAuthenticateFrame(frame)) {
    sendReady(ws, frame.id, label);
    return true;
  }
  return false;
}

/**
 * Send a generic successful response — used by pool tests that just need
 * any valid response frame. Sends a plain JSON envelope with the request's
 * type + ".res" and body merged with patch.
 */
export function sendSuccessResponse(ws, id, label = "x", patch = {}) {
  ws.send(JSON.stringify({
    id,
    t: T.MAILBOX_LIST_RES,
    type: T.MAILBOX_LIST_RES,
    v: CONTRACT_VERSION,
    body: { mailboxId: `mbox:${label}`, items: [], nextCursor: null, ...patch },
  }));
}

// Backward-compatible aliases — pool tests use these names
export function sendListThreadsResponse(ws, id, label = "x", patch = {}) {
  sendSuccessResponse(ws, id, label, patch);
}

export function sendThreadUpsert(ws, id, label = "x", patch = {}) {
  sendSuccessResponse(ws, id, label, patch);
}

export function sendMessageUpsert(ws, id, patch = {}) {
  ws.send(JSON.stringify({
    id,
    t: T.EVT_MAILBOX_DEPOSITED,
    type: T.EVT_MAILBOX_DEPOSITED,
    v: CONTRACT_VERSION,
    body: {
      mailboxId: patch.mailboxId || "mbox:test",
      eventId: patch.id || "evt:test",
      objectId: patch.objectId || "obj:test",
      createdAtMs: patch.createdAtMs || Date.now(),
    },
  }));
}

export function sendError(ws, id, { code, message, retryable = false } = {}) {
  ws.send(JSON.stringify({
    id,
    t: T.ERROR,
    type: T.ERROR,
    v: CONTRACT_VERSION,
    body: {
      code: code || "BAD_REQUEST",
      message: message || "bad request",
      detail: { retryable },
    },
  }));
}

export function sendRecord(ws, id, record) {
  const body = typeof record.toJSON === "function" ? record.toJSON() : record;
  const type = typeof record.constructor.type === "string" ? record.constructor.type : "";
  ws.send(JSON.stringify({
    id,
    t: type,
    type,
    v: CONTRACT_VERSION,
    body,
  }));
}

export function isHelloFrame(frame) {
  return frame && frame.t === T.SESSION_HELLO;
}

/**
 * Generate an Ed25519 identity key pair for test UplinkPoolClient construction.
 * Returns { accountId, accountIdentityPublicKeyB64, accountIdentityPrivateKeyB64 }.
 */
export async function createTestIdentityKeyPair() {
  const keyPair = await globalThis.crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const publicKeyBytes = new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", keyPair.publicKey));
  const privateKeyBytes = new Uint8Array(await globalThis.crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  return {
    accountId: deriveAccountIdFromPublicKey(publicKeyBytes),
    accountIdentityPublicKeyB64: Buffer.from(publicKeyBytes).toString("base64"),
    accountIdentityPrivateKeyB64: Buffer.from(privateKeyBytes).toString("base64"),
  };
}
