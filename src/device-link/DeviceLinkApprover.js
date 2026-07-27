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
  #registrationJournal;
  #journalWarn;
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
    registrationJournal = null,
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
    // P1#2a persist-and-resume. Required for the same reason registerDevice is: a device.add is
    // authoritative the moment the leaf is released, and a fresh ceremony mints a DIFFERENT certId,
    // so a registration that is not durably recorded BEFORE the commit cannot be recovered — only
    // abandoned. Making the journal intrinsic to the constructor means no path exists that submits
    // device.add with nothing to resume from.
    const journal = registrationJournal && typeof registrationJournal === "object" ? registrationJournal : null;
    if (!journal
        || typeof journal.persistPending !== "function"
        || typeof journal.markPublished !== "function"
        || typeof journal.markConfirmed !== "function") {
      throw new Error(
        "DeviceLinkApprover requires registrationJournal { persistPending, markPublished, markConfirmed }"
          + " — persist-and-resume (P1#2a): the exact publication must be durable before device.add",
      );
    }
    this.#registrationJournal = journal;
    this.#journalWarn = typeof journal.warn === "function" ? (m) => journal.warn(m) : null;
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
          // A VERSION mismatch is terminal, not noise (audit #5). The device-link ceremony has no
          // handshake — the request arrives as a sealed record at a rendezvous coordinate, so
          // nothing negotiated schema support beforehand and this is the first and only place the
          // mismatch can be seen. Swallowing it here would leave the user watching a ceremony that
          // silently times out, when the actionable truth is "the other device is too old to link
          // safely". Surface it and stop.
          if (err && err.code === "DEVICE_LINK_UPGRADE_REQUIRED") {
            this.#terminate("failed");
            throw err;
          }
          // Anything else: an invalid record in the slot (an attacker without the psk cannot even
          // sign one, so this is corruption or staleness) — keep polling until the deadline.
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
  #onJournalWarning(op, err) {
    const message = "DeviceLinkApprover: registration journal " + op + " failed after the ceremony"
      + " already succeeded: " + (err && err.message ? err.message : String(err));
    if (typeof this.#journalWarn === "function") {
      this.#journalWarn(message);
      return;
    }
    console.warn(message);
  }

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

    // ORDER (P1#2 + P1#2a). Build and SEAL the response, PERSIST it, THEN register, THEN publish.
    //
    // P1#2 registration-before-release: the home must bind this leaf's certId before the leaf
    // reaches the new device, or an off-home peer has no way to learn it was revoked. So the
    // response is never PUBLISHED before the commit.
    //
    // P1#2a persist-and-resume: the response is nonetheless BUILT before the commit, because a
    // crash between "device.add committed" and "response published" must be recoverable — and it
    // can only be recovered by republishing these exact bytes. A fresh ceremony mints a different
    // certId (the id covers issuedAtMs/expiresAtMs), so retrying never converges on the
    // registration that already committed.
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

    const bindingInboxId = pinned.linkRequest.deviceInboxBinding && typeof pinned.linkRequest.deviceInboxBinding === "object"
      ? pinned.linkRequest.deviceInboxBinding.inboxId
      : null;

    // Durable BEFORE the commit. `confirmTagB64` is the expected confirmation tag rather than the
    // master secret: it is enough to recognise the new device's confirmation on resume, and unlike
    // the secret it cannot decrypt the sealed response at rest.
    try {
      await this.#registrationJournal.persistPending({
        deviceId: pinned.newDeviceId,
        inboxId: bindingInboxId,
        certId: leafCert.certId,
        leafCert: leafCert.toJSON(),
        sealedResponse: responseRecord,
        thRequestB64: pinned.thRequestB64,
        thResponseB64: response.thResponseB64,
        confirmTagB64: response.confirmTagB64,
        expiresAtMs: this.#expiresAtMs,
      });
    } catch (err) {
      this.#terminate("failed");
      const wrapped = new Error(
        "device link registration could not be made durable before device.add: "
          + (err && err.message ? err.message : String(err)),
      );
      wrapped.code = "DEVICE_LINK_REGISTRATION_NOT_DURABLE";
      throw wrapped;
    }

    // The callback MUST return its asserted COMMITTED registration ({ deviceId, inboxId,
    // certId }); we then validate it binds THIS exact device, inbox, and leaf cert. This is a
    // TRUSTED IN-PROCESS boundary (the production wiring is ServerDeviceLinkService submitting
    // device.add): the check catches wiring/consistency bugs — a no-op `async () => {}` or a
    // mismatched/stale commit can no longer release a leaf — but it is NOT cryptographic proof
    // the commit came from the home (a fabricated matching object would pass; provenance would
    // need a home-signed commit record). The END-TO-END guarantee that the home actually bound
    // the certId before release is proven by the real-Pg L6 test, not by this equality check.
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

    // Publish the EXACT record that was persisted, then record that it is out. Republishing the
    // same record is a no-op, which is what makes the resume path safe to run more than once.
    await this.#records.put({ record: responseRecord });
    await this.#registrationJournal.markPublished({ deviceId: pinned.newDeviceId });

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
          // ACKNOWLEDGMENT ONLY (P1#2a): the leaf has been live since it was released, so this
          // grants nothing — it closes out the resume obligation. A failure to record the
          // acknowledgment must not fail a ceremony that has already succeeded; the registration
          // simply stays `published` and the next sweep sees it as complete-but-unacknowledged.
          try {
            await this.#registrationJournal.markConfirmed({ deviceId: pinned.newDeviceId });
          } catch (err) {
            // Deliberately non-fatal, and deliberately not silent.
            this.#onJournalWarning("markConfirmed", err);
          }
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
