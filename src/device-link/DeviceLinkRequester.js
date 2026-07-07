import {
  parseDeviceLinkCodeV1,
  buildCeremonyRequest,
  openCeremonyResponse,
  buildCeremonyConfirm,
  sealCeremonyRecord,
  verifyCeremonyRecord,
  DEVICE_LINK_RECORD_KIND,
  DEVICE_LINK_RECORD_ID_REQUEST,
  DEVICE_LINK_RECORD_ID_RESPONSE,
  DEVICE_LINK_RECORD_ID_CONFIRM,
  verifyAccountAuthority,
} from "@rezprotocol/core";
import { generateDeviceKeyPair } from "../device/deviceIdentity.js";
import { deriveRendezvousKeyPair } from "./rendezvous.js";
import { DEVICE_LINK_LEAF_CAPABILITIES } from "./capabilities.js";

function defaultSleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function emitStatus(onStatus, status) {
  if (typeof onStatus === "function") onStatus(status);
}

/**
 * The NEW-device half of the PSK device-link ceremony (S2.5 S10): takes the
 * link code read off the primary's screen, mints (or accepts) the device key
 * C, publishes the sealed request to the PSK-derived rendezvous slot, polls
 * for the primary's sealed response, VALIDATES the delegation (real
 * verifyAccountAuthority — the chain must anchor at the code's account key,
 * be granted to exactly this C, and carry every launch capability), publishes
 * the key-confirmation record, and returns the vault-ready delegation:
 * the EXACT createDelegatedKeystoreAccount shape (wire bundle + the
 * locally-minted deviceKeyPair — C's private key never rode the wire).
 *
 * Transport is injected as `records` ({put, get} — a DurableRecordsCapability
 * or a test double); crypto as an RCryptoProvider. Linear one-shot flow, so
 * the honest shape is an async function, not a state machine.
 */
export async function runDeviceLinkRequester({
  code,
  crypto,
  records,
  nowMs = () => Date.now(),
  sleep = defaultSleep,
  pollIntervalMs = 1000,
  pollMaxIntervalMs = 5000,
  pollBackoff = 1.5,
  deadlineMs = 10 * 60_000,
  deviceKeyPair = null,
  onStatus = null,
} = {}) {
  if (!crypto || typeof crypto !== "object") {
    throw new Error("runDeviceLinkRequester requires a crypto provider");
  }
  if (!records || typeof records.put !== "function" || typeof records.get !== "function") {
    throw new Error("runDeviceLinkRequester requires records {put, get}");
  }
  if (typeof nowMs !== "function") {
    throw new Error("runDeviceLinkRequester requires nowMs() (a clock function)");
  }

  const { psk, accountSignPublicKeyB64 } = parseDeviceLinkCodeV1(code);
  const rendezvousKeyPair = await deriveRendezvousKeyPair({ crypto, psk });
  const deviceKeys = deviceKeyPair || await generateDeviceKeyPair();
  const startedAtMs = nowMs();
  const deadlineAtMs = startedAtMs + deadlineMs;

  emitStatus(onStatus, "publishing-request");
  const request = await buildCeremonyRequest({
    crypto,
    nowMs: startedAtMs,
    psk,
    accountSignPublicKeyB64,
    rendezvousPublicKeyB64: rendezvousKeyPair.publicKeyB64,
    deviceKeyPair: deviceKeys,
    requestTtlMs: deadlineMs,
  });
  const requestRecord = await sealCeremonyRecord({
    crypto,
    nowMs: startedAtMs,
    rendezvousKeyPair,
    recordId: DEVICE_LINK_RECORD_ID_REQUEST,
    payloadB64: request.payloadB64,
    expiresAtMs: deadlineAtMs,
  });
  await records.put({ record: requestRecord });

  // Poll for the primary's response with backoff up to the ceremony deadline.
  emitStatus(onStatus, "waiting-approval");
  let responsePayload = null;
  let interval = pollIntervalMs;
  for (;;) {
    const at = nowMs();
    if (at >= deadlineAtMs) {
      const err = new Error("device link timed out waiting for the primary device's response");
      err.code = "DEVICE_LINK_TIMEOUT";
      throw err;
    }
    const record = await records.get({
      recordKind: DEVICE_LINK_RECORD_KIND,
      recordId: DEVICE_LINK_RECORD_ID_RESPONSE,
      publisherPublicKeyB64: rendezvousKeyPair.publicKeyB64,
    });
    if (record) {
      // The serving node is untrusted — re-verify before opening.
      responsePayload = await verifyCeremonyRecord({
        crypto,
        nowMs: at,
        record,
        rendezvousPublicKeyB64: rendezvousKeyPair.publicKeyB64,
        recordId: DEVICE_LINK_RECORD_ID_RESPONSE,
      });
      break;
    }
    await sleep(Math.min(interval, pollMaxIntervalMs));
    interval = Math.min(interval * pollBackoff, pollMaxIntervalMs);
  }

  emitStatus(onStatus, "validating");
  const opened = await openCeremonyResponse({
    crypto,
    psk,
    accountSignPublicKeyB64,
    rendezvousPublicKeyB64: rendezvousKeyPair.publicKeyB64,
    thRequestB64: request.thRequestB64,
    ephemeralKeyPair: request.ephemeralKeyPair,
    payload: responsePayload,
  });

  // The bundle's authority is verified HERE, before confirming — the AEAD
  // proves the psk+DH counterpart sealed it, but the chain inside must
  // independently anchor at the code's account key and grant exactly this
  // device key every launch capability.
  const authz = await verifyAccountAuthority({
    expectedAccountIdentityPublicKeyB64: accountSignPublicKeyB64,
    requiredCapability: DEVICE_LINK_LEAF_CAPABILITIES[0],
    opSignerPublicKeyB64: deviceKeys.publicKeyB64,
    certChain: opened.delegationBundle.certChain,
    crypto,
    nowMs: nowMs(),
  });
  if (authz.ok !== true) {
    throw new Error("runDeviceLinkRequester: delegation cert chain rejected: " + String(authz.reason || "unknown"));
  }
  const granted = Array.isArray(authz.grantedCapabilities) ? authz.grantedCapabilities : [];
  for (const capability of DEVICE_LINK_LEAF_CAPABILITIES) {
    if (!granted.includes(capability)) {
      throw new Error("runDeviceLinkRequester: delegation chain does not grant " + capability);
    }
  }

  emitStatus(onStatus, "confirming");
  const confirm = await buildCeremonyConfirm({
    crypto,
    masterSecret: opened.masterSecret,
    thResponseB64: opened.thResponseB64,
  });
  const confirmRecord = await sealCeremonyRecord({
    crypto,
    nowMs: nowMs(),
    rendezvousKeyPair,
    recordId: DEVICE_LINK_RECORD_ID_CONFIRM,
    payloadB64: confirm.payloadB64,
    expiresAtMs: deadlineAtMs,
  });
  await records.put({ record: confirmRecord });

  return {
    // The EXACT createDelegatedKeystoreAccount `delegation` shape.
    delegation: {
      accountSignPublicKeyB64: opened.delegationBundle.accountSignPublicKeyB64,
      accountDhKeyPair: opened.delegationBundle.accountDhKeyPair,
      deviceKeyPair: deviceKeys,
      certChain: opened.delegationBundle.certChain,
      cachedDeviceSet: opened.delegationBundle.cachedDeviceSet,
    },
    deviceId: request.linkRequest.newDeviceId,
    fingerprint: request.fingerprint,
  };
}
