import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  REZ_CONTRACT_TYPES,
  relayKeyIdForNodePublicKeyB64,
  nodeKeyIdForNodePublicKeyB64,
} from "@rezprotocol/core";
import { AuthStateMachine, AUTH_MODES, AUTH_STATES } from "../src/auth/AuthStateMachine.js";
import { signPayload, verifyPayload } from "../src/auth/signing.js";
import { RelayContractFloorStore } from "../src/relay/RelayContractFloorStore.js";
import { SDK_EVENTS } from "../src/events/SdkEvents.js";

// SESSION_AUTH_V5 slice 2A/2B, SDK side: the claimant-mode handshake through
// the live AuthStateMachine against a stub node that signs real Ed25519
// challenges — same technique as auth.delegated.test.js.

const T = REZ_CONTRACT_TYPES;
const noopBus = { emit() {} };

function collectBus() {
  const events = [];
  return { events, emit(name, payload) { events.push({ name, payload }); } };
}

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyB64: Buffer.from(publicKey.export({ format: "der", type: "spki" })).toString("base64"),
    privateKeyB64: Buffer.from(privateKey.export({ format: "der", type: "pkcs8" })).toString("base64"),
  };
}

/**
 * Stub node transport for CLAIMANT mode: answers hello with a real signed
 * session-challenge-claimant, verifies the machine's session-auth-claimant
 * signature against the claimant key, then returns session.ready.
 * `challengeKind` lets a test serve a wrong-domain challenge signature.
 */
function makeClaimantTransport({ node, captured, challengeKind = "session-challenge-claimant" }) {
  return {
    url: "ws://node.test/ws",
    async sendRequest({ type, body }) {
      if (type === T.SESSION_HELLO) {
        captured.hello = body;
        const now = Date.now();
        const base = {
          challengeId: "ch-claimant-1",
          nonceB64: Buffer.from(crypto.randomBytes(16)).toString("base64"),
          issuedAtMs: now,
          expiresAtMs: now + 60_000,
          nodeKeyId: nodeKeyIdForNodePublicKeyB64(node.publicKeyB64),
          nodePublicKeyB64: node.publicKeyB64,
          relayKeyId: relayKeyIdForNodePublicKeyB64(node.publicKeyB64),
          wsPath: "/ws",
        };
        const signatureB64 = await signPayload({
          privateKeyB64: node.privateKeyB64,
          payload: {
            kind: challengeKind,
            challengeId: base.challengeId,
            nonceB64: base.nonceB64,
            issuedAtMs: base.issuedAtMs,
            expiresAtMs: base.expiresAtMs,
            nodeKeyId: base.nodeKeyId,
            nodePublicKeyB64: base.nodePublicKeyB64,
            relayKeyId: base.relayKeyId,
            claimantPublicKeyB64: body.claimantPublicKeyB64,
            wsPath: base.wsPath,
          },
        });
        captured.challenge = { ...base, signatureB64 };
        return { t: T.SESSION_CHALLENGE, body: captured.challenge };
      }
      if (type === "session.authenticate") {
        captured.authenticate = body;
        const c = captured.challenge;
        captured.authSignatureValid = await verifyPayload({
          publicKeyB64: captured.hello.claimantPublicKeyB64,
          signatureB64: body.signatureB64,
          payload: {
            kind: "session-auth-claimant",
            challengeId: c.challengeId,
            nonceB64: c.nonceB64,
            nodeKeyId: c.nodeKeyId,
            nodePublicKeyB64: c.nodePublicKeyB64,
            relayKeyId: c.relayKeyId,
            claimantPublicKeyB64: captured.hello.claimantPublicKeyB64,
            wsPath: c.wsPath,
          },
        });
        return { t: T.SESSION_READY, body: { serverTime: Date.now() } };
      }
      throw new Error("unexpected request type: " + type);
    },
  };
}

test("claimant handshake: hello carries ONLY the claimant identity, the proof verifies, sessionInfo carries the verified v5 tuple", async () => {
  const node = genKey();
  const claimant = genKey();
  const captured = {};
  const machine = new AuthStateMachine({
    claimantIdentity: { claimantPublicKeyB64: claimant.publicKeyB64, privateKeyB64: claimant.privateKeyB64 },
    eventBus: noopBus,
  });
  assert.equal(machine.mode, AUTH_MODES.CLAIMANT);

  const info = await machine.authenticate(makeClaimantTransport({ node, captured }));

  assert.equal(captured.hello.contractVersion, 5);
  assert.equal(captured.hello.authMode, "claimant");
  assert.equal(captured.hello.claimantPublicKeyB64, claimant.publicKeyB64);
  assert.ok(!("deviceId" in captured.hello), "no deviceId — correlation metadata never enters the claimant hello");
  assert.ok(!("accountIdentityPublicKeyB64" in captured.hello), "no account identity in the claimant hello");

  assert.equal(captured.authSignatureValid, true, "the node verified the claimant's domain-separated proof");
  assert.ok(!("signerPublicKeyB64" in captured.authenticate) && !("certChain" in captured.authenticate),
    "no delegation fields — claimant mode has none");

  assert.equal(machine.state, AUTH_STATES.AUTHENTICATED);
  assert.equal(info.contractVersion, 5);
  assert.equal(info.authMode, AUTH_MODES.CLAIMANT);
  assert.equal(info.nodePublicKeyB64, node.publicKeyB64);
});

test("a wrong-domain challenge signature is refused — the machine FAILS and never sends authenticate (no fallback of any kind)", async () => {
  const node = genKey();
  const claimant = genKey();
  const captured = {};
  const machine = new AuthStateMachine({
    claimantIdentity: { claimantPublicKeyB64: claimant.publicKeyB64, privateKeyB64: claimant.privateKeyB64 },
    eventBus: noopBus,
  });
  await assert.rejects(
    () => machine.authenticate(makeClaimantTransport({ node, captured, challengeKind: "session-challenge" })),
    /challenge signature did not verify/,
  );
  assert.equal(machine.state, AUTH_STATES.FAILED);
  assert.equal(captured.authenticate, undefined, "no signature ever left the machine");
});

test("construction takes ONE mode: both identities is an error, claimant mode requires both key halves", () => {
  const k = genKey();
  assert.throws(() => new AuthStateMachine({
    identity: { publicKeyB64: k.publicKeyB64, privateKeyB64: k.privateKeyB64 },
    claimantIdentity: { claimantPublicKeyB64: k.publicKeyB64, privateKeyB64: k.privateKeyB64 },
    eventBus: noopBus,
  }), /never both/);
  assert.throws(() => new AuthStateMachine({
    claimantIdentity: { claimantPublicKeyB64: k.publicKeyB64 },
    eventBus: noopBus,
  }), /privateKeyB64/);
});

test("2B: a claimant authentication records floor 5 for the VERIFIED relay identity", async () => {
  const node = genKey();
  const claimant = genKey();
  const store = new RelayContractFloorStore();
  const machine = new AuthStateMachine({
    claimantIdentity: { claimantPublicKeyB64: claimant.publicKeyB64, privateKeyB64: claimant.privateKeyB64 },
    eventBus: noopBus,
    relayContractFloor: { store },
  });
  await machine.authenticate(makeClaimantTransport({ node, captured: {} }));
  assert.equal(store.floorFor(node.publicKeyB64), 5);
});

test("2B enforcement (opt-in): account-mode auth toward a pinned known-v5 relay is refused BEFORE any hello; record-only default proceeds and surfaces the condition", async () => {
  const node = genKey();
  const account = genKey();
  const store = new RelayContractFloorStore();
  store.recordObserved({ relayIdentityB64: node.publicKeyB64, contractVersion: 5 });

  // enforce: true + pinned identity → refused pre-hello.
  let helloSent = false;
  const refusingTransport = { url: "ws://node.test/ws", async sendRequest() { helloSent = true; throw new Error("should never be reached"); } };
  const enforced = new AuthStateMachine({
    identity: { publicKeyB64: account.publicKeyB64, privateKeyB64: account.privateKeyB64, deviceId: "rez:dev:" + "a".repeat(64) },
    eventBus: noopBus,
    expectedNodePublicKeyB64: node.publicKeyB64,
    relayContractFloor: { store, enforce: true },
  });
  await assert.rejects(
    () => enforced.authenticate(refusingTransport),
    (err) => err.serverCode === "DOWNGRADE_REFUSED",
  );
  assert.equal(helloSent, false, "refused before any identity-bearing frame left the client");
  assert.equal(enforced.state, AUTH_STATES.FAILED);

  // Default (record-only): the account handshake proceeds; the downgrade is
  // surfaced as an OBSERVATION event, and the stored floor is NOT lowered.
  const bus = collectBus();
  const captured = {};
  const observing = new AuthStateMachine({
    identity: { publicKeyB64: account.publicKeyB64, privateKeyB64: account.privateKeyB64, deviceId: "rez:dev:" + "a".repeat(64) },
    eventBus: bus,
    expectedNodePublicKeyB64: node.publicKeyB64,
    relayContractFloor: { store },
  });
  const accountTransport = {
    url: "ws://node.test/ws",
    async sendRequest({ type, body }) {
      if (type === T.SESSION_HELLO) {
        captured.hello = body;
        const now = Date.now();
        const base = {
          challengeId: "ch-acct-1",
          nonceB64: Buffer.from(crypto.randomBytes(16)).toString("base64"),
          issuedAtMs: now,
          expiresAtMs: now + 60_000,
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
        return { t: T.SESSION_CHALLENGE, body: { ...base, signatureB64 } };
      }
      return { t: T.SESSION_READY, body: { serverTime: Date.now() } };
    },
  };
  const info = await observing.authenticate(accountTransport);
  assert.equal(info.contractVersion, 4);
  assert.equal(info.authMode, AUTH_MODES.ACCOUNT);
  assert.equal(store.floorFor(node.publicKeyB64), 5, "a lower observation NEVER lowers the floor (frozen monotonicity)");
  const condition = bus.events.find((e) => e.name === SDK_EVENTS.AUTH_DOWNGRADE_CONDITION);
  assert.ok(condition, "the downgrade condition was surfaced as an observation");
  assert.equal(condition.payload.floor, 5);
  assert.equal(condition.payload.observedCurrent, 4);
});
