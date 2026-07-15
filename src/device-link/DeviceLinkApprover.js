import {
  generateDeviceLinkPsk,
  encodeDeviceLinkCodeV1,
  openCeremonyRequest,
  buildCeremonyResponse,
  verifyCeremonyConfirm,
  sealCeremonyRecord,
  verifyCeremonyRecord,
  DEVICE_LINK_RECORD_KIND,
  DEVICE_LINK_RECORD_ID_REQUEST,
  DEVICE_LINK_RECORD_ID_RESPONSE,
  DEVICE_LINK_RECORD_ID_CONFIRM,
  AccountDeviceCapabilityV1,
  ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
  DeviceRegistrationV1,
  bytesToBase64,
  base64ToBytes,
} from "@rezprotocol/core";
import { deriveRendezvousKeyPair } from "./rendezvous.js";
import { DEVICE_LINK_LEAF_CAPABILITIES } from "./capabilities.js";

const DEFAULT_PSK_TTL_MS = 10 * 60_000;
const DEFAULT_CERT_TTL_MS = 365 * 24 * 60 * 60 * 1000;

function defaultSleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * The PRIMARY-device half of the PSK device-link ceremony (S2.5 S10).
 * Two-phase by design — the pause between `waitForRequest()` and `approve()`
 * is the HUMAN gate: the caller shows the pending request's fingerprint and
 * only calls approve() after the user cross-checks it against the new
 * device's screen (the defense against a photographed link code racing the
 * real device).
 *
 * Single-use: the PSK lives only in this instance; `waitForRequest` accepts
 * exactly ONE request ever (the first VALID one is pinned — later slot
 * roll-forwards are never re-read), and every terminal state drops the
 * secrets. No persistent replay store is needed: ceremony state is
 * coterminous with the 10-minute PSK inside one approver instance, unlike
 * the process-wide onion replay cache.
 *
 * The account root B enters ONLY as a sign callback (or a raw private key for
 * tests) — the approver never stores B, and B-dh rides in the bundle as the
 * keypair the delegated device is entitled to hold.
 */
export class DeviceLinkApprover {
  #crypto;
  #records;
  #accountSignPublicKeyB64;
  #accountSign;
  #accountDhKeyPair;
  #getCachedDeviceSet;
  #registerDevice;
  #nowMs;
  #sleep;
  #pollIntervalMs;
  #pollMaxIntervalMs;
  #pollBackoff;
  #pskTtlMs;
  #certTtlMs;
  #status;
  #psk;
  #rendezvousKeyPair;
  #expiresAtMs;
  #pinned; // { thRequestB64, ephemeralDhPublicKeyB64, linkRequest, newDeviceId, fingerprint }

  constructor({
    crypto,
    records,
    accountSignPublicKeyB64,
    accountSign = null,
    accountSignPrivateKey = null,
    accountDhKeyPair,
    getCachedDeviceSet = null,
    registerDevice = null,
    nowMs = () => Date.now(),
    sleep = defaultSleep,
    pollIntervalMs = 1000,
    pollMaxIntervalMs = 5000,
    pollBackoff = 1.5,
    pskTtlMs = DEFAULT_PSK_TTL_MS,
    certTtlMs = DEFAULT_CERT_TTL_MS,
  } = {}) {
    if (!crypto || typeof crypto !== "object") {
      throw new Error("DeviceLinkApprover requires a crypto provider");
    }
    if (!records || typeof records.put !== "function" || typeof records.get !== "function") {
      throw new Error("DeviceLinkApprover requires records {put, get}");
    }
    if (typeof accountSignPublicKeyB64 !== "string" || accountSignPublicKeyB64.length === 0) {
      throw new Error("DeviceLinkApprover requires accountSignPublicKeyB64 (the account root B)");
    }
    const hasCallback = typeof accountSign === "function";
    const hasPrivateKey = accountSignPrivateKey instanceof Uint8Array && accountSignPrivateKey.length > 0;
    if (hasCallback === hasPrivateKey) {
      throw new Error("DeviceLinkApprover requires exactly one of accountSign(bytes) or accountSignPrivateKey");
    }
    if (!accountDhKeyPair || !accountDhKeyPair.publicKeyB64 || !accountDhKeyPair.privateKeyB64) {
      throw new Error("DeviceLinkApprover requires accountDhKeyPair (B-dh — the bundle ships the PAIR)");
    }
    this.#crypto = crypto;
    this.#records = records;
    this.#accountSignPublicKeyB64 = accountSignPublicKeyB64;
    this.#accountSign = hasCallback
      ? accountSign
      : async (bytes) => crypto.sign({ privateKey: accountSignPrivateKey, msg: bytes });
    this.#accountDhKeyPair = {
      publicKeyB64: accountDhKeyPair.publicKeyB64,
      privateKeyB64: accountDhKeyPair.privateKeyB64,
    };
    this.#getCachedDeviceSet = typeof getCachedDeviceSet === "function" ? getCachedDeviceSet : null;
    // P1#2 registration-before-release: a REQUIRED async callback the approver runs — and
    // that MUST succeed — AFTER minting the leaf cert but BEFORE the response (the leaf) is
    // released. It submits device.add {deviceInboxBinding, deviceCapability} to the home so
    // the home binds the leaf's certId before the new device can use it. Required (not
    // optional) so no construction path can silently release an unregistered, off-home-
    // unrevocable leaf — the security invariant is intrinsic to the constructor. If it
    // throws, the ceremony fails and no leaf is released.
    if (typeof registerDevice !== "function") {
      throw new Error("DeviceLinkApprover requires registerDevice(...) — registration-before-release (P1#2): the home must bind the leaf's certId before the leaf is released");
    }
    this.#registerDevice = registerDevice;
    this.#nowMs = nowMs;
    this.#sleep = sleep;
    this.#pollIntervalMs = pollIntervalMs;
    this.#pollMaxIntervalMs = pollMaxIntervalMs;
    this.#pollBackoff = pollBackoff;
    this.#pskTtlMs = pskTtlMs;
    this.#certTtlMs = certTtlMs;
    this.#status = "idle";
    this.#psk = null;
    this.#rendezvousKeyPair = null;
    this.#expiresAtMs = 0;
    this.#pinned = null;
  }

  get status() {
    return this.#status;
  }

  get expiresAtMs() {
    return this.#expiresAtMs;
  }

  /** Mint the single-use PSK and derive the rendezvous key. → { code, expiresAtMs } */
  async start() {
    if (this.#status !== "idle") {
      throw new Error("DeviceLinkApprover.start: already started (one ceremony per instance)");
    }
    this.#psk = generateDeviceLinkPsk({ crypto: this.#crypto });
    this.#rendezvousKeyPair = await deriveRendezvousKeyPair({ crypto: this.#crypto, psk: this.#psk });
    this.#expiresAtMs = this.#nowMs() + this.#pskTtlMs;
    this.#status = "waiting-request";
    return {
      code: encodeDeviceLinkCodeV1({ psk: this.#psk, accountSignPublicKeyB64: this.#accountSignPublicKeyB64 }),
      expiresAtMs: this.#expiresAtMs,
    };
  }

  /**
   * Poll the request slot until the FIRST VALID request lands (pinned —
   * single-use), the PSK expires, or the ceremony is cancelled.
   * → { newDeviceId, fingerprint, linkRequest }
   */
  async waitForRequest() {
    if (this.#status !== "waiting-request") {
      throw new Error("DeviceLinkApprover.waitForRequest: not waiting (status " + this.#status + ")");
    }
    let interval = this.#pollIntervalMs;
    for (;;) {
      if (this.#status === "cancelled") {
        const err = new Error("device link cancelled");
        err.code = "DEVICE_LINK_CANCELLED";
        throw err;
      }
      const at = this.#nowMs();
      if (at >= this.#expiresAtMs) {
        this.#terminate("expired");
        const err = new Error("device link code expired before a request arrived");
        err.code = "DEVICE_LINK_TIMEOUT";
        throw err;
      }
      let record = null;
      try {
        record = await this.#records.get({
          recordKind: DEVICE_LINK_RECORD_KIND,
          recordId: DEVICE_LINK_RECORD_ID_REQUEST,
          publisherPublicKeyB64: this.#rendezvousKeyPair.publicKeyB64,
        });
      } catch (err) {
        // Transient transport failure — keep polling until the deadline; the
        // deadline is the loud failure path.
        record = null;
      }
      if (record) {
        try {
          const payload = await verifyCeremonyRecord({
            crypto: this.#crypto,
            nowMs: at,
            record,
            rendezvousPublicKeyB64: this.#rendezvousKeyPair.publicKeyB64,
            recordId: DEVICE_LINK_RECORD_ID_REQUEST,
          });
          const opened = await openCeremonyRequest({
            crypto: this.#crypto,
            nowMs: at,
            psk: this.#psk,
            accountSignPublicKeyB64: this.#accountSignPublicKeyB64,
            rendezvousPublicKeyB64: this.#rendezvousKeyPair.publicKeyB64,
            payload,
          });
          // FIRST valid request wins and is PINNED — approve() is bound to
          // this exact transcript; later slot roll-forwards are never read.
          this.#pinned = opened;
          this.#status = "awaiting-approval";
          return {
            newDeviceId: opened.newDeviceId,
            fingerprint: opened.fingerprint,
            linkRequest: opened.linkRequest,
          };
        } catch (err) {
          // An invalid record in the slot (an attacker without the psk cannot
          // even sign one, so this is corruption/staleness) — keep polling.
        }
      }
      await this.#sleep(Math.min(interval, this.#pollMaxIntervalMs));
      interval = Math.min(interval * this.#pollBackoff, this.#pollMaxIntervalMs);
    }
  }

  /**
   * The HUMAN-GATED step: mint the leaf cert for the pinned device key, seal
   * + publish the delegation bundle, and wait for the key-confirmation
   * record. → { newDeviceId, certId }
   */
  async approve() {
    if (this.#status !== "awaiting-approval" || !this.#pinned) {
      throw new Error("DeviceLinkApprover.approve: no pending request to approve");
    }
    this.#status = "responding";
    const pinned = this.#pinned;
    const at = this.#nowMs();

    const leafCert = await this.#mintLeafCert({
      granteePublicKeyB64: pinned.linkRequest.newDevicePublicKeyB64,
      nowMs: at,
    });

    // P1#2 registration-before-release: register the device at the home (device.add
    // carrying the new device's OWN inbox binding + this leaf cert) BEFORE building /
    // publishing the response that releases the leaf. If registration fails the ceremony
    // fails and the leaf is NEVER released — so a leaf that reaches the new device always
    // has its certId already bound at the home (and thus is revocable to off-home peers).
    // Ordered here, not in the caller, so no caller can accidentally release first.
    //
    // The callback MUST return its asserted COMMITTED registration ({ deviceId, inboxId,
    // certId }); we then validate it binds THIS exact device, inbox, and leaf cert. This is a
    // TRUSTED IN-PROCESS boundary (the production wiring is ServerDeviceLinkService submitting
    // device.add): the check catches wiring/consistency bugs — a no-op `async () => {}` or a
    // mismatched/stale commit can no longer release a leaf — but it is NOT cryptographic proof
    // the commit came from the home (a fabricated matching object would pass; provenance would
    // need a home-signed commit record). The END-TO-END guarantee that the home actually bound
    // the certId before release is proven by the real-Pg L6 test, not by this equality check.
    const bindingInboxId = pinned.linkRequest.deviceInboxBinding && typeof pinned.linkRequest.deviceInboxBinding === "object"
      ? pinned.linkRequest.deviceInboxBinding.inboxId
      : null;
    let commit;
    try {
      commit = await this.#registerDevice({
        newDeviceId: pinned.newDeviceId,
        deviceInboxBinding: pinned.linkRequest.deviceInboxBinding,
        deviceCapability: leafCert.toJSON(),
      });
    } catch (err) {
      this.#terminate("failed");
      const wrapped = new Error("device link registration (device.add) failed before release: " + (err && err.message ? err.message : String(err)));
      wrapped.code = "DEVICE_LINK_REGISTRATION_FAILED";
      throw wrapped;
    }
    if (!commit || typeof commit !== "object"
        || commit.certId !== leafCert.certId
        || commit.deviceId !== pinned.newDeviceId
        || commit.inboxId !== bindingInboxId) {
      this.#terminate("failed");
      const err = new Error(
        "device link registration returned an unverified commit (must bind this device, inbox, and leaf certId before release)",
      );
      err.code = "DEVICE_LINK_REGISTRATION_UNVERIFIED";
      throw err;
    }

    let cachedDeviceSet = null;
    if (this.#getCachedDeviceSet) {
      cachedDeviceSet = await this.#getCachedDeviceSet();
    }
    const response = await buildCeremonyResponse({
      crypto: this.#crypto,
      psk: this.#psk,
      accountSignPublicKeyB64: this.#accountSignPublicKeyB64,
      rendezvousPublicKeyB64: this.#rendezvousKeyPair.publicKeyB64,
      thRequestB64: pinned.thRequestB64,
      ephemeralDhPublicKeyB64: pinned.ephemeralDhPublicKeyB64,
      delegationBundle: {
        accountSignPublicKeyB64: this.#accountSignPublicKeyB64,
        accountDhKeyPair: this.#accountDhKeyPair,
        certChain: [leafCert.toJSON()],
        cachedDeviceSet: cachedDeviceSet === undefined ? null : cachedDeviceSet,
      },
    });
    const responseRecord = await sealCeremonyRecord({
      crypto: this.#crypto,
      nowMs: at,
      rendezvousKeyPair: this.#rendezvousKeyPair,
      recordId: DEVICE_LINK_RECORD_ID_RESPONSE,
      payloadB64: response.payloadB64,
      expiresAtMs: this.#expiresAtMs,
    });
    await this.#records.put({ record: responseRecord });

    // Explicit key confirmation: only the device that derived the SAME master
    // secret (psk + the pinned ephemeral DH) can produce the tag.
    this.#status = "waiting-confirm";
    let interval = this.#pollIntervalMs;
    for (;;) {
      if (this.#status === "cancelled") {
        const err = new Error("device link cancelled");
        err.code = "DEVICE_LINK_CANCELLED";
        throw err;
      }
      const now = this.#nowMs();
      if (now >= this.#expiresAtMs) {
        this.#terminate("failed");
        const err = new Error("device link timed out waiting for key confirmation");
        err.code = "DEVICE_LINK_TIMEOUT";
        throw err;
      }
      let record = null;
      try {
        record = await this.#records.get({
          recordKind: DEVICE_LINK_RECORD_KIND,
          recordId: DEVICE_LINK_RECORD_ID_CONFIRM,
          publisherPublicKeyB64: this.#rendezvousKeyPair.publicKeyB64,
        });
      } catch (err) {
        record = null;
      }
      if (record) {
        let confirmed = false;
        try {
          const payload = await verifyCeremonyRecord({
            crypto: this.#crypto,
            nowMs: now,
            record,
            rendezvousPublicKeyB64: this.#rendezvousKeyPair.publicKeyB64,
            recordId: DEVICE_LINK_RECORD_ID_CONFIRM,
          });
          confirmed = await verifyCeremonyConfirm({
            crypto: this.#crypto,
            masterSecret: response.masterSecret,
            thResponseB64: response.thResponseB64,
            payload,
          });
        } catch (err) {
          confirmed = false;
        }
        if (confirmed) {
          const result = { newDeviceId: pinned.newDeviceId, certId: leafCert.certId };
          this.#terminate("done");
          return result;
        }
        // A confirm record that does not verify is a hard failure — the slot
        // is single-writer (R-signed) and the tag is deterministic, so a bad
        // tag means the counterpart derived a DIFFERENT key.
        this.#terminate("failed");
        const err = new Error("device link key confirmation failed");
        err.code = "DEVICE_LINK_CONFIRM_FAILED";
        throw err;
      }
      await this.#sleep(Math.min(interval, this.#pollMaxIntervalMs));
      interval = Math.min(interval * this.#pollBackoff, this.#pollMaxIntervalMs);
    }
  }

  /** Terminal: drop the psk and every derived secret. */
  cancel() {
    this.#terminate("cancelled");
  }

  #terminate(status) {
    this.#status = status;
    if (this.#psk instanceof Uint8Array) this.#psk.fill(0);
    this.#psk = null;
    this.#pinned = null;
  }

  // Mint the single-hop (B→C) leaf capability cert. Capabilities are the
  // module constant — never widened per call (confused-deputy guard).
  async #mintLeafCert({ granteePublicKeyB64, nowMs }) {
    const fields = {
      v: 1,
      purpose: ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
      accountIdentityPublicKeyB64: this.#accountSignPublicKeyB64,
      parentCertId: null,
      granteeDevicePublicKeyB64: granteePublicKeyB64,
      granteeDeviceId: DeviceRegistrationV1.deviceIdFor(granteePublicKeyB64),
      capabilities: [...DEVICE_LINK_LEAF_CAPABILITIES],
      maxDelegationDepth: 0,
      issuedAtMs: nowMs,
      expiresAtMs: nowMs + this.#certTtlMs,
      signerPublicKeyB64: this.#accountSignPublicKeyB64,
    };
    const certId = AccountDeviceCapabilityV1.deriveCertId(fields);
    const sigBytes = await this.#accountSign(AccountDeviceCapabilityV1.signableBytes({ ...fields, certId }));
    if (!(sigBytes instanceof Uint8Array) || sigBytes.length === 0) {
      throw new Error("DeviceLinkApprover: accountSign returned no signature");
    }
    // Sanity: the mint must verify against B before it rides the wire.
    const ok = await this.#crypto.verify({
      publicKey: base64ToBytes(this.#accountSignPublicKeyB64),
      msg: AccountDeviceCapabilityV1.signableBytes({ ...fields, certId }),
      sig: sigBytes,
    });
    if (ok !== true) {
      throw new Error("DeviceLinkApprover: minted cert does not verify against the account key");
    }
    return new AccountDeviceCapabilityV1({ ...fields, certId, sig: { alg: "ed25519", sigB64: bytesToBase64(sigBytes) } });
  }
}
