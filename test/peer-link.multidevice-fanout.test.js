import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase64, deriveAccountIdFromPublicKey, DeviceRegistrationV1, DevicePrekeyBundleV1 } from "@rezprotocol/core";
import { SeedKeys } from "@rezprotocol/core/src/crypto/seedDerivation.js";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService } from "../src/peer-link/PeerLinkService.js";
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

// S2.5 S12 L7 — the MULTI-DEVICE device set, un-mocked. Two devices of ONE
// account (sharing the seed-derived account identity-DH key) each self-publish a
// bundle; one device assembles the account's full device set and seals it to a
// peer; the peer establishes an INITIATOR session to BOTH devices; each device
// completes its responder via its ACCOUNT-GLOBAL preKeyState; a message from the
// peer reaches BOTH devices (the actual fan-out property). Real X25519/Ed25519.
const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
const FAR_FUTURE = 10_000_000_000_000;
const DH_LABEL = "rez/identity/x3dh-dh/v1";

function makeStorageProvider() {
  const m = new Map();
  const kv = {
    async get(k) { return m.has(k) ? m.get(k) : undefined; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { return m.delete(k); },
    async keys(prefix) { const o = []; for (const k of m.keys()) if (!prefix || k.startsWith(prefix)) o.push(k); return o; },
  };
  const peerLinkStorage = createKeyValueBackedPeerLinkStorage({ keyValueStore: kv });
  return { getPeerLinkStorage() { return peerLinkStorage; }, getKeyValueStore() { return kv; }, peerLinkStorage };
}

// One account "device": same B + injected account identity-DH, its own device key
// C, its own inbox, its own storage.
async function makeDevice(crypto, b, accountId, accountPubB64, mailboxId, accountIdentityDhKeyPair) {
  const authority = {
    signer: {
      getSignerRef() { return { accountId, keyId: "invite-ed25519-v1", alg: "ed25519", signerPublicKeyB64: accountPubB64 }; },
      async sign(bytes) { return crypto.sign({ privateKey: b.privateKey, msg: bytes }); },
    },
    verifier: { async verify() { return true; } },
  };
  const dk = await crypto.generateSigningKeyPair();
  const deviceKeyPair = { publicKeyB64: bytesToBase64(dk.publicKey), privateKeyB64: bytesToBase64(dk.privateKey) };
  const sp = makeStorageProvider();
  const svc = new PeerLinkService({
    storageProvider: sp,
    clock: () => 1,
    ownerAccountId: accountId,
    getInviteAuthority: () => authority,
    inviteBinding: { mailboxId, capabilityId: mailboxId },
    cryptoProvider: crypto,
    deviceKeyPair,
    deviceId: DeviceRegistrationV1.deviceIdFor(deviceKeyPair.publicKeyB64),
    accountIdentityDhKeyPair: accountIdentityDhKeyPair || null,
  });
  const challenge = await svc.getOrCreateAccountBindingChallenge({ ownerAccountId: accountId });
  const bindingSig = await crypto.sign({ privateKey: b.privateKey, msg: enc("x3dh-subkey-binding:" + challenge.x3dhIdentityPublicKeyB64) });
  await svc.upsertAccountBinding({
    ownerAccountId: accountId,
    accountBinding: {
      accountId, accountIdentityPublicKeyB64: accountPubB64,
      x3dhIdentityPublicKeyB64: challenge.x3dhIdentityPublicKeyB64,
      issuedAtMs: 1, expiresAtMs: FAR_FUTURE, accountBindingSigB64: bytesToBase64(bindingSig),
    },
  });
  const bound = await svc._requireBoundX3dhIdentity(accountId);
  return { svc, sp, accountId, accountPubB64, mailboxId, deviceId: svc.deviceId, identityDhPubB64: bytesToBase64(bound.identityDhKeyPair.publicKey) };
}

async function makeAccount(crypto, { seedByte, mailboxes }) {
  const b = await crypto.generateSigningKeyPair();
  const accountPubB64 = bytesToBase64(b.publicKey);
  const accountId = deriveAccountIdFromPublicKey(b.publicKey);
  const seededDh = SeedKeys.deriveX25519({ seed: Buffer.alloc(64, seedByte), label: DH_LABEL });
  const devices = [];
  for (const mailboxId of mailboxes) {
    devices.push(await makeDevice(crypto, b, accountId, accountPubB64, mailboxId, seededDh));
  }
  return { b, accountPubB64, accountId, seededDh, devices };
}

function link(fromDevice, toAccountId, toAccountPubB64, toIdentityDhPubB64, peerLinkId) {
  return fromDevice.sp.peerLinkStorage.peerLinks.create({
    peerLinkId, localAccountId: fromDevice.accountId, peerAccountId: toAccountId,
    state: "session_established",
    remoteIdentityDhPublicKeyB64: toIdentityDhPubB64,
    remoteAccountIdentityPublicKeyB64: toAccountPubB64,
    version: 1,
  });
}

test("multi-device fan-out: a peer resolves a 2-device set, establishes BOTH devices, and a message reaches BOTH", async () => {
  const crypto = new BrowserCryptoProvider();
  const accountA = await makeAccount(crypto, { seedByte: 42, mailboxes: ["rez:inbox:a1", "rez:inbox:a2"] });
  const carol = await makeAccount(crypto, { seedByte: 7, mailboxes: ["rez:inbox:carol"] });
  const [a1, a2] = accountA.devices;
  const c = carol.devices[0];

  // Peer links: carol ⇄ account A (A's shared identity DH), each A device ⇄ carol.
  await link(c, accountA.accountId, accountA.accountPubB64, accountA.seededDh.publicKeyB64, "pl_carol_A");
  await link(a1, carol.accountId, carol.accountPubB64, c.identityDhPubB64, "pl_A_carol");
  await link(a2, carol.accountId, carol.accountPubB64, c.identityDhPubB64, "pl_A_carol");

  // Each A device self-publishes its bundle (account-global preKeyState retained).
  const b1 = await a1.svc.buildAndRetainAccountDeviceBundle({});
  const b2 = await a2.svc.buildAndRetainAccountDeviceBundle({});
  assert.ok(b1 instanceof DevicePrekeyBundleV1 && b2 instanceof DevicePrekeyBundleV1);
  // The account-global sentinel slot was populated (not a per-peer slot).
  const sentinel = await a1.sp.peerLinkStorage.keys.getDevicePreKey(accountA.accountId, "@self-device-bundle");
  assert.ok(sentinel && typeof sentinel === "object", "account-global preKeyState retained");

  // Device A1 assembles the account's 2-device set from the aggregated bundles.
  const accountDeviceSet = [{ deviceId: a1.deviceId, bundle: b1.toJSON() }, { deviceId: a2.deviceId, bundle: b2.toJSON() }];
  const { record } = await a1.svc.buildDeviceSetRecordForPeer({ peerAccountId: carol.accountId, accountDeviceSet, revision: 3 });

  // Carol resolves + ingests → establishes an initiator session to BOTH devices.
  const ingested = await c.svc.ingestPeerDeviceSet({ peerAccountId: accountA.accountId, record });
  assert.equal(ingested.deviceSetRecord.devices.length, 2, "the set enumerates both devices");
  assert.equal(ingested.deviceSetRecord.revision, 3, "carries the S11 authority revision");
  assert.equal(ingested.established.length, 2, "carol established a session to EACH device");
  const establishedByDevice = new Map(ingested.established.map((e) => [e.peerDeviceId, e.handshakeData]));
  assert.ok(establishedByDevice.has(a1.deviceId) && establishedByDevice.has(a2.deviceId));

  // Each device completes its responder session from carol's handshake, using its
  // ACCOUNT-GLOBAL preKeyState (no per-peer bundle was ever built for carol).
  await a1.svc.completeDeviceSetResponder({ peerAccountId: carol.accountId, peerDeviceId: c.deviceId, handshakeData: establishedByDevice.get(a1.deviceId) });
  await a2.svc.completeDeviceSetResponder({ peerAccountId: carol.accountId, peerDeviceId: c.deviceId, handshakeData: establishedByDevice.get(a2.deviceId) });

  // FAN-OUT: carol encrypts once per device → the message reaches BOTH inboxes.
  const toA1 = await c.svc.encryptDirectMessageForDevice({ peerAccountId: accountA.accountId, peerLinkId: "pl_carol_A", peerDeviceId: a1.deviceId, plaintextBytes: enc("hi both devices") });
  const toA2 = await c.svc.encryptDirectMessageForDevice({ peerAccountId: accountA.accountId, peerLinkId: "pl_carol_A", peerDeviceId: a2.deviceId, plaintextBytes: enc("hi both devices") });

  const gotA1 = await a1.svc.decryptFromDevice({ peerAccountId: carol.accountId, peerLinkId: "pl_A_carol", peerDeviceId: c.deviceId, packetBytes: toA1.encryptedPacket.toBytes() });
  const gotA2 = await a2.svc.decryptFromDevice({ peerAccountId: carol.accountId, peerLinkId: "pl_A_carol", peerDeviceId: c.deviceId, packetBytes: toA2.encryptedPacket.toBytes() });
  assert.equal(dec(gotA1.plaintextBytes), "hi both devices", "device A1 decrypts");
  assert.equal(dec(gotA2.plaintextBytes), "hi both devices", "device A2 decrypts — the fan-out reached the second device");

  // A device can reply back over its established session.
  const reply = await a2.svc.encryptDirectMessageForDevice({ peerAccountId: carol.accountId, peerLinkId: "pl_A_carol", peerDeviceId: c.deviceId, plaintextBytes: enc("ack from A2") });
  const gotReply = await c.svc.decryptFromDevice({ peerAccountId: accountA.accountId, peerLinkId: "pl_carol_A", peerDeviceId: a2.deviceId, packetBytes: reply.encryptedPacket.toBytes() });
  assert.equal(dec(gotReply.plaintextBytes), "ack from A2");
});

test("aggregate build rejects a bundle that does not belong to the publishing account", async () => {
  const crypto = new BrowserCryptoProvider();
  const accountA = await makeAccount(crypto, { seedByte: 42, mailboxes: ["rez:inbox:a1"] });
  const other = await makeAccount(crypto, { seedByte: 9, mailboxes: ["rez:inbox:o1"] });
  const [a1] = accountA.devices;
  const [o1] = other.devices;
  await link(a1, "rez:acct:peer", "PEERPUB", "PEERDH", "pl_A_peer");

  const foreign = await o1.svc.buildAndRetainAccountDeviceBundle({});
  await assert.rejects(
    () => a1.svc.buildDeviceSetRecordForPeer({ peerAccountId: "rez:acct:peer", accountDeviceSet: [{ bundle: foreign.toJSON() }], revision: 1 }),
    /does not belong to the publishing account/,
  );
});
