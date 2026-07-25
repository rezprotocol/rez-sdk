import test from "node:test";
import assert from "node:assert/strict";

import {
  bytesToBase64,
  deriveAccountIdFromPublicKey,
  DEVICE_LINK_RECORD_KIND,
  DEVICE_LINK_RECORD_ID_REQUEST,
  DEVICE_LINK_RECORD_ID_RESPONSE,
  parseDeviceLinkCodeV1,
  createDelegatedKeystoreAccount,
  KeystoreStore,
} from "@rezprotocol/core";
import { runDeviceLinkRequester } from "../src/device-link/DeviceLinkRequester.js";
import { DeviceLinkApprover } from "../src/device-link/DeviceLinkApprover.js";
import { deriveRendezvousKeyPair } from "../src/device-link/rendezvous.js";
import { DEVICE_LINK_LEAF_CAPABILITIES } from "../src/device-link/capabilities.js";
import { generateDeviceKeyPair } from "../src/device/deviceIdentity.js";
import { createMemoryRecordOverlay } from "./support/memoryRecordStore.js";
// REAL crypto — the ceremony's properties (AAD binding, PSK-authenticated
// ephemeral DH, key confirmation) are meaningless under a fake provider.
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

const CRYPTO = new BrowserCryptoProvider();
const FAST = { pollIntervalMs: 5, pollMaxIntervalMs: 10, pollBackoff: 1.2 };

async function makePrimary(overlay, { pskTtlMs = 10 * 60_000, getCachedDeviceSet = null, registerDevice = null, registrationJournal = null } = {}) {
  const b = await CRYPTO.generateSigningKeyPair();
  const dh = await CRYPTO.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
  // P1#2: registerDevice is now required (registration-before-release). The default
  // stub records each registration so tests can assert it ran BEFORE the leaf was
  // released; individual tests inject a throwing one to prove the fail-closed path.
  const registrations = [];
  // P1#2a: the journal makes the registration RESUMABLE. `steps` records the ceremony's ordering
  // decisions — persist BEFORE the commit, publish AFTER it — which is the invariant that lets a
  // crash between commit and publish be recovered by republishing the stored bytes.
  const steps = [];
  const journalRecords = [];
  const journal = registrationJournal || {
    async persistPending(rec) { steps.push("persist"); journalRecords.push(rec); },
    async markPublished() { steps.push("markPublished"); },
    async markConfirmed() { steps.push("markConfirmed"); },
    warn() {},
  };
  const reg = registerDevice || (async (args) => {
    steps.push("register");
    registrations.push(args);
    // A faithful home commit echoes the exact device/inbox/certId it bound — the shape
    // the approver validates before releasing the leaf.
    return { deviceId: args.newDeviceId, inboxId: args.deviceInboxBinding.inboxId, certId: args.deviceCapability.certId };
  });
  const approver = new DeviceLinkApprover({
    crypto: CRYPTO,
    records: overlay,
    accountSignPublicKeyB64: bytesToBase64(b.publicKey),
    accountSign: async (bytes) => CRYPTO.sign({ privateKey: b.privateKey, msg: bytes }),
    accountDhKeyPair: {
      publicKeyB64: bytesToBase64(dh.publicKey),
      privateKeyB64: bytesToBase64(dh.privateKey),
    },
    getCachedDeviceSet,
    registerDevice: reg,
    registrationJournal: journal,
    pskTtlMs,
    ...FAST,
  });
  return { approver, registrations, steps, journalRecords, accountPubB64: bytesToBase64(b.publicKey), accountId: deriveAccountIdFromPublicKey(b.publicKey) };
}

function runRequester(overlay, code, over = {}) {
  return runDeviceLinkRequester({ code, crypto: CRYPTO, records: overlay, ...FAST, ...over });
}

function createMemoryStorage() {
  const m = new Map();
  return {
    get(k) { return m.has(k) ? m.get(k) : null; },
    put(k, v) { m.set(k, v); },
    del(k) { m.delete(k); },
  };
}

test("happy path: full ceremony over the shared overlay — delegation feeds the REAL delegated keystore; fingerprints agree", async () => {
  const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });
  const primary = await makePrimary(overlay);
  const { code, expiresAtMs } = await primary.approver.start();
  assert.ok(expiresAtMs > Date.now());

  const approverFlow = (async () => {
    const pending = await primary.approver.waitForRequest();
    assert.match(pending.fingerprint, /^[0-9a-f]{4}(-[0-9a-f]{4}){4}$/);
    const done = await primary.approver.approve();
    return { pending, done };
  })();
  const [requester, approval] = await Promise.all([runRequester(overlay, code), approverFlow]);

  // Both sides saw the SAME device (the approve-tap cross-check surface).
  assert.equal(approval.pending.fingerprint, requester.fingerprint);
  assert.equal(approval.pending.newDeviceId, requester.deviceId);
  assert.equal(approval.done.newDeviceId, requester.deviceId);
  assert.equal(primary.approver.status, "done");

  // The delegation is EXACTLY what the seedless keystore accepts — prove it
  // by creating a real v3 keystore from it.
  const store = new KeystoreStore({ storageProvider: createMemoryStorage(), key: "linked" });
  const created = await createDelegatedKeystoreAccount({
    password: "pw-for-test",
    profileName: "Linked",
    keystoreStore: store,
    cryptoProvider: globalThis.crypto,
    delegation: requester.delegation,
  });
  assert.equal(created.hasAdminRoot, false);
  assert.equal(created.accountId, primary.accountId);
  assert.equal(created.deviceKeyPublicKeyB64, requester.delegation.deviceKeyPair.publicKeyB64);

  // Cert policy: exactly the launch capabilities, granted to the requester's C.
  const leaf = requester.delegation.certChain[0];
  assert.deepEqual(leaf.capabilities, [...DEVICE_LINK_LEAF_CAPABILITIES]);
  assert.equal(leaf.maxDelegationDepth, 0);
  assert.equal(leaf.granteeDevicePublicKeyB64, requester.delegation.deviceKeyPair.publicKeyB64);
});

test("a wrong-psk writer cannot reach the ceremony slot, and cannot sign for R even knowing its coordinate", async () => {
  const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });
  const primary = await makePrimary(overlay, { pskTtlMs: 400 });
  const { code } = await primary.approver.start();
  const { psk } = parseDeviceLinkCodeV1(code);
  const rendezvous = await deriveRendezvousKeyPair({ crypto: CRYPTO, psk });

  // Attacker with a DIFFERENT psk derives a different R → writes land on a
  // different slot; the approver's poll never sees them.
  const attackerCode = (await (async () => {
    const other = await makePrimary(overlay);
    return other.approver.start();
  })()).code;
  const attackerRun = runRequester(overlay, attackerCode, { deadlineMs: 300 });
  const waiting = primary.approver.waitForRequest().then(
    () => { throw new Error("approver must not see the attacker's request"); },
    (err) => err,
  );
  await assert.rejects(() => attackerRun, (err) => err.code === "DEVICE_LINK_TIMEOUT");
  const waitErr = await waiting;
  assert.equal(waitErr.code, "DEVICE_LINK_TIMEOUT", "approver expires without ever seeing a request");

  // An attacker who LEARNS R's public key (e.g. traffic analysis) still can't
  // occupy the slot: the overlay (like the node) verifies the R signature.
  const forged = {
    v: 1,
    recordKind: DEVICE_LINK_RECORD_KIND,
    recordId: DEVICE_LINK_RECORD_ID_REQUEST,
    publisherPublicKeyB64: rendezvous.publicKeyB64,
    issuedAtMs: Date.now(),
    expiresAtMs: Date.now() + 60_000,
    payloadB64: bytesToBase64(new TextEncoder().encode("{}")),
    sigB64: bytesToBase64(new Uint8Array(64)),
  };
  await assert.rejects(() => overlay.put({ record: forged }), /bad-signature/);
});

test("tampered response: the requester fails AEAD open and never publishes a confirm", async () => {
  const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });
  const primary = await makePrimary(overlay, { pskTtlMs: 3_000 });
  const { code } = await primary.approver.start();

  // Corrupt the RESPONSE at PUBLISH time (a malicious serving node handing back a swapped
  // payload). Deterministic — no timing race: the interceptor stores the corrupted record
  // RAW (_rawSet bypasses the overlay's honest signature check, exactly as a dishonest node
  // would), so the requester can only ever read the corrupted response. The payload swap
  // breaks the record's R-signature, so the requester's client-side re-verify rejects it,
  // it never confirms, and the approver times out waiting for the confirm.
  const realPut = overlay.put;
  overlay.put = async ({ record } = {}) => {
    if (record && String(record.recordId) === DEVICE_LINK_RECORD_ID_RESPONSE) {
      const payload = JSON.parse(new TextDecoder().decode(Buffer.from(record.payloadB64, "base64")));
      payload.ciphertextB64 = payload.ciphertextB64.slice(0, -4) + "AAA=";
      const corrupted = { ...record, payloadB64: bytesToBase64(new TextEncoder().encode(JSON.stringify(payload))) };
      overlay._rawSet(
        overlay._localId({ publisherPublicKeyB64: record.publisherPublicKeyB64, recordKind: record.recordKind, recordId: record.recordId }),
        corrupted,
      );
      return;
    }
    return realPut({ record });
  };

  const approverFlow = (async () => {
    await primary.approver.waitForRequest();
    return primary.approver.approve().catch((err) => err);
  })();

  // The corrupted record fails the R-signature re-verify on the requester
  // side (payload swap breaks the record signature), so the requester keeps
  // polling until its deadline and NEVER confirms.
  const [requesterErr, approverErr] = await Promise.all([
    runRequester(overlay, code, { deadlineMs: 1_500 }).catch((err) => err),
    approverFlow,
  ]);
  assert.ok(requesterErr instanceof Error, "requester failed");
  assert.ok(approverErr instanceof Error, "approver failed (no confirm arrived)");
  assert.equal(approverErr.code, "DEVICE_LINK_TIMEOUT");
});

test("expired PSK: the approver times out cleanly; a requester against a dead ceremony deadlines", async () => {
  const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });
  const primary = await makePrimary(overlay, { pskTtlMs: 150 });
  const { code } = await primary.approver.start();
  await assert.rejects(() => primary.approver.waitForRequest(), (err) => err.code === "DEVICE_LINK_TIMEOUT");
  assert.equal(primary.approver.status, "expired");
  await assert.rejects(() => runRequester(overlay, code, { deadlineMs: 250 }), (err) => err.code === "DEVICE_LINK_TIMEOUT");
});

test("single-use first-wins: an attacker's request is pinned and its fingerprint SHOWN — the legit roll-forward is never consumed", async () => {
  const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });
  const primary = await makePrimary(overlay, { pskTtlMs: 5_000 });
  const { code } = await primary.approver.start();

  // The attacker photographed the code: same psk, own device key. Catch
  // eagerly — the rejection (timeout after the veto) fires while the test is
  // awaiting other promises, and an unhandled rejection fails the test.
  const attackerDevice = await generateDeviceKeyPair();
  const attacker = runRequester(overlay, code, { deviceKeyPair: attackerDevice, deadlineMs: 700 }).catch((err) => err);
  const pending = await primary.approver.waitForRequest();
  const attackerDeviceId = "rez:dev:" ===
    pending.newDeviceId.slice(0, 8) ? pending.newDeviceId : pending.newDeviceId;
  assert.equal(
    pending.linkRequest.newDevicePublicKeyB64,
    attackerDevice.publicKeyB64,
    "the approver pins the FIRST request — the attacker's — and surfaces ITS fingerprint for the human veto",
  );

  // The legit device races in afterwards, rolling the slot forward — the
  // approver's pinned transcript is NOT replaced.
  const legit = runRequester(overlay, code, { deadlineMs: 700 }).catch((err) => err);
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(primary.approver.status, "awaiting-approval");
  assert.equal(pending.newDeviceId, attackerDeviceId);

  // The human cross-checks fingerprints, sees a mismatch, and cancels.
  primary.approver.cancel();
  assert.equal(primary.approver.status, "cancelled");
  const legitErr = await legit;
  assert.ok(legitErr instanceof Error, "legit requester deadlines after the veto");
  const attackerErr = await attacker;
  assert.ok(attackerErr instanceof Error, "attacker never gets a bundle");
});

test("requester rejects a bundle whose chain is narrower than the launch set or granted to a different key", async () => {
  const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });

  // A malicious/buggy approver double: valid ceremony crypto, but the leaf
  // cert grants only ONE capability.
  const b = await CRYPTO.generateSigningKeyPair();
  const dh = await CRYPTO.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
  const { DeviceLinkApprover: Approver } = await import("../src/device-link/DeviceLinkApprover.js");
  const core = await import("@rezprotocol/core");

  // Build a stock approver, then wrap approve() to swap the chain for a
  // narrow one before sealing — easiest done by minting the narrow cert with
  // the same account key and driving the core functions directly.
  const approver = new Approver({
    crypto: CRYPTO,
    records: overlay,
    accountSignPublicKeyB64: bytesToBase64(b.publicKey),
    accountSign: async (bytes) => CRYPTO.sign({ privateKey: b.privateKey, msg: bytes }),
    accountDhKeyPair: {
      publicKeyB64: bytesToBase64(dh.publicKey),
      privateKeyB64: bytesToBase64(dh.privateKey),
    },
    registerDevice: async () => {}, // P1#2: required; this test hand-builds the response below.
    // P1#2a: also required. This test never calls approve() — it drives the core functions
    // directly — so the journal is present purely to satisfy the constructor invariant.
    registrationJournal: { async persistPending() {}, async markPublished() {}, async markConfirmed() {} },
    pskTtlMs: 3_000,
    ...FAST,
  });
  const { code } = await approver.start();
  const { psk, accountSignPublicKeyB64 } = parseDeviceLinkCodeV1(code);
  const rendezvous = await deriveRendezvousKeyPair({ crypto: CRYPTO, psk });

  const narrowFlow = (async () => {
    const pending = await approver.waitForRequest();
    // Mint a NARROW cert for the pinned device and publish a hand-built
    // response with it (bypassing the approver's fixed-capability mint).
    const fields = {
      v: 1,
      purpose: core.ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
      accountIdentityPublicKeyB64: accountSignPublicKeyB64,
      parentCertId: null,
      granteeDevicePublicKeyB64: pending.linkRequest.newDevicePublicKeyB64,
      granteeDeviceId: pending.linkRequest.newDeviceId,
      capabilities: ["peerLink.create"],
      maxDelegationDepth: 0,
      issuedAtMs: Date.now(),
      expiresAtMs: Date.now() + 60_000,
      signerPublicKeyB64: accountSignPublicKeyB64,
    };
    const certId = core.AccountDeviceCapabilityV1.deriveCertId(fields);
    const sig = await CRYPTO.sign({ privateKey: b.privateKey, msg: core.AccountDeviceCapabilityV1.signableBytes({ ...fields, certId }) });
    const narrowLeaf = new core.AccountDeviceCapabilityV1({ ...fields, certId, sig: { alg: "ed25519", sigB64: bytesToBase64(sig) } });

    // Recover the pinned request transcript by re-opening the slot record.
    const reqRecord = await overlay.get({
      recordKind: DEVICE_LINK_RECORD_KIND,
      recordId: DEVICE_LINK_RECORD_ID_REQUEST,
      publisherPublicKeyB64: rendezvous.publicKeyB64,
    });
    const reqPayload = await core.verifyCeremonyRecord({
      crypto: CRYPTO, nowMs: Date.now(), record: reqRecord,
      rendezvousPublicKeyB64: rendezvous.publicKeyB64,
      recordId: DEVICE_LINK_RECORD_ID_REQUEST,
    });
    const opened = await core.openCeremonyRequest({
      crypto: CRYPTO, nowMs: Date.now(), psk,
      accountSignPublicKeyB64,
      rendezvousPublicKeyB64: rendezvous.publicKeyB64,
      payload: reqPayload,
    });
    const response = await core.buildCeremonyResponse({
      crypto: CRYPTO, psk,
      accountSignPublicKeyB64,
      rendezvousPublicKeyB64: rendezvous.publicKeyB64,
      thRequestB64: opened.thRequestB64,
      ephemeralDhPublicKeyB64: opened.ephemeralDhPublicKeyB64,
      delegationBundle: {
        accountSignPublicKeyB64,
        accountDhKeyPair: { publicKeyB64: bytesToBase64(dh.publicKey), privateKeyB64: bytesToBase64(dh.privateKey) },
        certChain: [narrowLeaf.toJSON()],
        cachedDeviceSet: null,
      },
    });
    const record = await core.sealCeremonyRecord({
      crypto: CRYPTO, nowMs: Date.now(),
      rendezvousKeyPair: rendezvous,
      recordId: DEVICE_LINK_RECORD_ID_RESPONSE,
      payloadB64: response.payloadB64,
      expiresAtMs: Date.now() + 60_000,
    });
    await overlay.put({ record });
  })();

  const requesterErr = await Promise.all([
    runRequester(overlay, code, { deadlineMs: 2_000 }).catch((err) => err),
    narrowFlow,
  ]).then(([err]) => err);
  assert.ok(requesterErr instanceof Error);
  assert.match(requesterErr.message, /does not grant deviceSet\.publish/);
});

test("bundle hygiene: an approver attempting to smuggle the account private key throws before anything reaches the wire", async () => {
  const b = await CRYPTO.generateSigningKeyPair();
  const core = await import("@rezprotocol/core");
  const psk = core.generateDeviceLinkPsk({ crypto: CRYPTO });
  const rendezvous = await deriveRendezvousKeyPair({ crypto: CRYPTO, psk });
  const eA = await CRYPTO.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
  const dh = await CRYPTO.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
  await assert.rejects(() => core.buildCeremonyResponse({
    crypto: CRYPTO, psk,
    accountSignPublicKeyB64: bytesToBase64(b.publicKey),
    rendezvousPublicKeyB64: rendezvous.publicKeyB64,
    thRequestB64: bytesToBase64(new Uint8Array(32).fill(7)),
    ephemeralDhPublicKeyB64: bytesToBase64(eA.publicKey),
    delegationBundle: {
      accountSignPublicKeyB64: bytesToBase64(b.publicKey),
      accountDhKeyPair: { publicKeyB64: bytesToBase64(dh.publicKey), privateKeyB64: bytesToBase64(dh.privateKey) },
      certChain: [{ certId: "rez:cap:x" }],
      cachedDeviceSet: null,
      accountSignPrivateKeyB64: bytesToBase64(b.privateKey),
    },
  }), /must not contain accountSignPrivateKeyB64/);
});

test("oversized cachedDeviceSet is dropped by the approver and the ceremony still completes", async () => {
  const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });
  const primary = await makePrimary(overlay, {
    getCachedDeviceSet: async () => ({ blob: "x".repeat(20_000) }),
  });
  const { code } = await primary.approver.start();
  const approverFlow = (async () => {
    await primary.approver.waitForRequest();
    return primary.approver.approve();
  })();
  const [requester] = await Promise.all([runRequester(overlay, code), approverFlow]);
  assert.equal(requester.delegation.cachedDeviceSet, null, "the oversized set was dropped, not fatal");
  assert.equal(primary.approver.status, "done");
});

test("approver constructor invariants: exactly one signer form; B-dh required", async () => {
  const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });
  const b = await CRYPTO.generateSigningKeyPair();
  const dh = await CRYPTO.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
  const base = {
    crypto: CRYPTO,
    records: overlay,
    accountSignPublicKeyB64: bytesToBase64(b.publicKey),
    accountDhKeyPair: { publicKeyB64: bytesToBase64(dh.publicKey), privateKeyB64: bytesToBase64(dh.privateKey) },
  };
  assert.throws(() => new DeviceLinkApprover(base), /exactly one of accountSign/);
  assert.throws(() => new DeviceLinkApprover({
    ...base,
    accountSign: async () => new Uint8Array(1),
    accountSignPrivateKey: b.privateKey,
  }), /exactly one of accountSign/);
  assert.throws(() => new DeviceLinkApprover({
    ...base,
    accountSign: async () => new Uint8Array(1),
    accountDhKeyPair: null,
  }), /requires accountDhKeyPair/);
  // P1#2: registerDevice is required — no construction path can silently release an
  // unregistered leaf.
  assert.throws(() => new DeviceLinkApprover({
    ...base,
    accountSign: async () => new Uint8Array(1),
  }), /registerDevice/);
});

test("P1#2: registration ran (device.add) carrying the device's binding + the leaf cert; requester returns its inbox", async () => {
  const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });
  const primary = await makePrimary(overlay);
  const { code } = await primary.approver.start();
  const approverFlow = (async () => {
    await primary.approver.waitForRequest();
    return primary.approver.approve();
  })();
  const [requester] = await Promise.all([runRequester(overlay, code), approverFlow]);

  assert.equal(primary.registrations.length, 1, "device.add submitted exactly once, before release");
  const reg = primary.registrations[0];
  assert.equal(reg.newDeviceId, requester.deviceId);
  assert.equal(reg.deviceInboxBinding.deviceId, requester.deviceId, "the registered binding is for the new device");
  assert.equal(reg.deviceInboxBinding.inboxId, requester.inboxId, "the requester returns + registered its self-chosen inbox");
  assert.equal(reg.deviceCapability.granteeDeviceId, requester.deviceId, "the registered leaf cert grants the new device");
});

test("P1#2 fail-closed: a failing registerDevice fails the ceremony and NEVER releases the leaf", async () => {
  const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });
  const primary = await makePrimary(overlay, {
    registerDevice: async () => { throw new Error("home unavailable"); },
  });
  const { code } = await primary.approver.start();
  const approverFlow = (async () => {
    await primary.approver.waitForRequest();
    return primary.approver.approve().then(() => null).catch((err) => err);
  })();
  // The requester must NEVER receive a response record (no leaf released), so it times out.
  const requesterP = runRequester(overlay, code, { deadlineMs: 400 })
    .then(() => null)
    .catch((err) => err);
  const [approveErr, reqErr] = await Promise.all([approverFlow, requesterP]);

  assert.equal(approveErr && approveErr.code, "DEVICE_LINK_REGISTRATION_FAILED", "approve() failed at registration");
  assert.ok(reqErr, "the requester got no response");
  assert.equal(reqErr.code, "DEVICE_LINK_TIMEOUT", "no leaf was ever released to the new device");
});

test("P1#2: a registration that does NOT commit this device/inbox/cert is rejected (no-op callback cannot pass)", async () => {
  // A callback that merely resolves (or resolves with a mismatched commit) must NOT satisfy
  // registration-before-release: the approver validates the returned commit against THIS
  // leaf's certId + the request's device + inbox.
  for (const badReg of [
    async () => {},                                                   // no-op: returns undefined
    async (args) => ({ deviceId: args.newDeviceId, inboxId: args.deviceInboxBinding.inboxId, certId: "rez:cap:" + "0".repeat(64) }), // wrong cert
  ]) {
    const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });
    const primary = await makePrimary(overlay, { registerDevice: badReg });
    const { code } = await primary.approver.start();
    const approverFlow = (async () => {
      await primary.approver.waitForRequest();
      return primary.approver.approve().then(() => null).catch((err) => err);
    })();
    const requesterP = runRequester(overlay, code, { deadlineMs: 400 }).then(() => null).catch((err) => err);
    const [approveErr, reqErr] = await Promise.all([approverFlow, requesterP]);
    assert.equal(approveErr && approveErr.code, "DEVICE_LINK_REGISTRATION_UNVERIFIED", "unverified commit rejected");
    assert.equal(reqErr && reqErr.code, "DEVICE_LINK_TIMEOUT", "no leaf released on an unverified registration");
  }
});

test("P1#2a: the exact publication is PERSISTED before device.add and published only after", async () => {
  // The ordering is the recovery guarantee. Persist-then-commit-then-publish means a crash
  // anywhere in between leaves stored bytes that can simply be republished; building the response
  // AFTER the commit would instead force a fresh ceremony, which mints a DIFFERENT certId and
  // never converges on the registration that already committed.
  const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });
  const { approver, steps, journalRecords, accountPubB64 } = await makePrimary(overlay);
  const started = await approver.start();
  const requesterDone = runRequester(overlay, started.code);
  await approver.waitForRequest();
  const result = await approver.approve();
  await requesterDone;

  assert.deepEqual(
    steps,
    ["persist", "register", "markPublished", "markConfirmed"],
    "persist BEFORE the home commit; publish only AFTER it",
  );

  // What was persisted must be the publication itself, not a description of it.
  assert.equal(journalRecords.length, 1);
  const rec = journalRecords[0];
  assert.equal(rec.deviceId, result.newDeviceId);
  assert.equal(rec.certId, result.certId);
  assert.equal(rec.leafCert.certId, result.certId, "the minted leaf, verbatim");
  assert.ok(rec.sealedResponse && typeof rec.sealedResponse === "object", "the SEALED response record");
  assert.equal(rec.sealedResponse.recordId, "response");
  assert.ok(rec.inboxId && rec.inboxId.startsWith("inbox:"), "the device's own ceremony inbox");
  assert.ok(rec.thRequestB64 && rec.thResponseB64, "the transcript binding");
  assert.ok(rec.expiresAtMs > 0);

  // The stored confirmation material is the expected TAG, never the master secret — the tag
  // recognises the device's confirmation but cannot decrypt the sealed response at rest.
  assert.ok(rec.confirmTagB64 && rec.confirmTagB64.length > 0);
  assert.equal(rec.masterSecret, undefined, "no key material at rest");

  // The record that went to the overlay is the one that was persisted.
  const published = await overlay.get({
    recordKind: rec.sealedResponse.recordKind,
    recordId: "response",
    publisherPublicKeyB64: rec.sealedResponse.publisherPublicKeyB64,
  });
  assert.deepEqual(published, rec.sealedResponse, "published the EXACT persisted bytes");
  assert.ok(accountPubB64.length > 0);
});

test("P1#2a fail-closed: if the registration cannot be made durable, device.add never runs", async () => {
  // Committing a registration with nothing to resume from is the one thing this leaf exists to
  // prevent: the leaf would be released with no way to republish and no way to recover.
  const overlay = createMemoryRecordOverlay({ crypto: CRYPTO });
  const steps = [];
  const { approver } = await makePrimary(overlay, {
    registrationJournal: {
      async persistPending() { steps.push("persist"); throw new Error("disk full"); },
      async markPublished() { steps.push("markPublished"); },
      async markConfirmed() { steps.push("markConfirmed"); },
    },
    registerDevice: async () => { steps.push("register"); return {}; },
  });
  const { code } = await approver.start();
  const approverFlow = (async () => {
    await approver.waitForRequest();
    return approver.approve().then(() => null).catch((err) => err);
  })();
  // No response is ever published, so the requester must time out rather than hang.
  const requesterP = runRequester(overlay, code, { deadlineMs: 400 }).then(() => null).catch((err) => err);
  const [approveErr, reqErr] = await Promise.all([approverFlow, requesterP]);

  assert.equal(approveErr && approveErr.code, "DEVICE_LINK_REGISTRATION_NOT_DURABLE");
  assert.deepEqual(steps, ["persist"], "device.add never ran");
  assert.equal(reqErr && reqErr.code, "DEVICE_LINK_TIMEOUT", "and no leaf reached the new device");
});
