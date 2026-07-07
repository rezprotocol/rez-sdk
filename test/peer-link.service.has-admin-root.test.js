import test from "node:test";
import assert from "node:assert/strict";
import {
  bytesToBase64,
  deriveAccountIdFromPublicKey,
  DeviceRegistrationV1,
  AccountDeviceCapabilityV1,
  ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
} from "@rezprotocol/core";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";
import { PeerLinkService } from "../src/peer-link/PeerLinkService.js";
import { BrowserCryptoProvider } from "../src/e2ee/BrowserCryptoProvider.js";

// S2.5 S9 K2 — the explicit signing-mode contract. `hasAdminRoot` has THREE
// outcomes: true = direct (account admin root signs through the authority),
// false = cert-mode (device key C signs under the capability chain), and a
// contradictory or incomplete configuration FAILS LOUD at construction.
// Omitted, the mode infers from chain presence — definitionally the pre-S9
// derivation, so every legacy call site is unchanged.

const NOW = 1_770_000_000_000;
const FAR = NOW + 7 * 24 * 60 * 60 * 1000;

function makeKvStore() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : undefined; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { return m.delete(k); },
    async keys(prefix) {
      const out = [];
      for (const k of m.keys()) if (!prefix || k.startsWith(prefix)) out.push(k);
      return out;
    },
  };
}

function makeStorageProvider() {
  const kv = makeKvStore();
  const peerLinkStorage = createKeyValueBackedPeerLinkStorage({ keyValueStore: kv });
  return {
    getPeerLinkStorage() { return peerLinkStorage; },
    getKeyValueStore() { return kv; },
    peerLinkStorage,
  };
}

async function buildLeafCert(c, { accountPubB64, accountPrivBytes, granteePubB64, capabilities }) {
  const fields = {
    v: 1,
    purpose: ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
    accountIdentityPublicKeyB64: accountPubB64,
    parentCertId: null,
    granteeDevicePublicKeyB64: granteePubB64,
    granteeDeviceId: DeviceRegistrationV1.deviceIdFor(granteePubB64),
    capabilities,
    maxDelegationDepth: 0,
    issuedAtMs: NOW - 1000,
    expiresAtMs: FAR,
    signerPublicKeyB64: accountPubB64,
  };
  const certId = AccountDeviceCapabilityV1.deriveCertId(fields);
  const sigBytes = await c.sign({ privateKey: accountPrivBytes, msg: AccountDeviceCapabilityV1.signableBytes({ ...fields, certId }) });
  return new AccountDeviceCapabilityV1({ ...fields, certId, sig: { alg: "ed25519", sigB64: bytesToBase64(sigBytes) } });
}

// Everything a construction needs; callers spread overrides on top.
async function makeParts(c) {
  const b = await c.generateSigningKeyPair();
  const accountPubB64 = bytesToBase64(b.publicKey);
  const accountId = deriveAccountIdFromPublicKey(b.publicKey);
  const deviceKp = await c.generateSigningKeyPair();
  const deviceKeyPair = { publicKeyB64: bytesToBase64(deviceKp.publicKey), privateKeyB64: bytesToBase64(deviceKp.privateKey) };
  const leafCert = await buildLeafCert(c, {
    accountPubB64,
    accountPrivBytes: b.privateKey,
    granteePubB64: deviceKeyPair.publicKeyB64,
    capabilities: ["peerLink.create"],
  });
  const authority = {
    signer: {
      getSignerRef() { return { accountId, keyId: "invite-ed25519-v1", alg: "ed25519", signerPublicKeyB64: accountPubB64 }; },
      async sign(bytes) { return c.sign({ privateKey: b.privateKey, msg: bytes }); },
    },
    verifier: { async verify() { return true; } },
  };
  return { accountId, deviceKeyPair, leafCert, authority };
}

function construct(c, parts, overrides = {}) {
  return new PeerLinkService({
    storageProvider: makeStorageProvider(),
    clock: () => NOW,
    ownerAccountId: parts.accountId,
    getInviteAuthority: () => parts.authority,
    inviteBinding: { mailboxId: "rez:inbox:x", capabilityId: "rez:inbox:x" },
    cryptoProvider: c,
    deviceKeyPair: parts.deviceKeyPair,
    deviceId: DeviceRegistrationV1.deviceIdFor(parts.deviceKeyPair.publicKeyB64),
    ...overrides,
  });
}

test("omitted hasAdminRoot infers the mode from chain presence (the pre-S9 derivation)", async () => {
  const c = new BrowserCryptoProvider();
  const parts = await makeParts(c);
  const direct = construct(c, parts);
  assert.equal(direct.hasAdminRoot, true);
  const delegated = construct(c, parts, { accountCapabilityCertChain: [parts.leafCert] });
  assert.equal(delegated.hasAdminRoot, false);
});

test("explicit hasAdminRoot that AGREES with the material constructs in that mode", async () => {
  const c = new BrowserCryptoProvider();
  const parts = await makeParts(c);
  const direct = construct(c, parts, { hasAdminRoot: true });
  assert.equal(direct.hasAdminRoot, true);
  const delegated = construct(c, parts, { hasAdminRoot: false, accountCapabilityCertChain: [parts.leafCert] });
  assert.equal(delegated.hasAdminRoot, false);
});

test("hasAdminRoot=true with a cert chain is a contradiction — fails loud", async () => {
  const c = new BrowserCryptoProvider();
  const parts = await makeParts(c);
  assert.throws(
    () => construct(c, parts, { hasAdminRoot: true, accountCapabilityCertChain: [parts.leafCert] }),
    /hasAdminRoot=true is incompatible with accountCapabilityCertChain/,
  );
});

test("hasAdminRoot=false without a cert chain is incomplete — fails loud", async () => {
  const c = new BrowserCryptoProvider();
  const parts = await makeParts(c);
  assert.throws(
    () => construct(c, parts, { hasAdminRoot: false }),
    /hasAdminRoot=false requires accountCapabilityCertChain/,
  );
});

test("a non-boolean hasAdminRoot is rejected", async () => {
  const c = new BrowserCryptoProvider();
  const parts = await makeParts(c);
  assert.throws(
    () => construct(c, parts, { hasAdminRoot: "yes" }),
    /hasAdminRoot must be true, false, or omitted/,
  );
});

test("a delegated service refuses the direct-only account-signer resolver and vice versa", async () => {
  const c = new BrowserCryptoProvider();
  const parts = await makeParts(c);
  const direct = construct(c, parts, { hasAdminRoot: true });
  await assert.rejects(
    () => direct._resolveDelegatedAccountIdentitySigner(parts.accountId),
    /requires a delegated PeerLinkService \(hasAdminRoot=false\)/,
  );
  const delegated = construct(c, parts, { hasAdminRoot: false, accountCapabilityCertChain: [parts.leafCert] });
  await assert.rejects(
    () => delegated.selfProvisionDelegatedAccountBinding({ ownerAccountId: "rez:acct:someoneelse" }),
    /chain anchor does not derive the owner accountId/,
  );
});
