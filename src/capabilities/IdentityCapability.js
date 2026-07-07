import { SDK_EVENTS } from "../events/SdkEvents.js";
import {
  buildSignedDeviceRegistration,
  buildSignedDeviceInboxBinding,
  buildSignedDeviceRevoke,
  buildSignedAccountDeviceMutation,
  buildSignedAccountAuthorityState,
} from "../device/deviceIdentity.js";

/**
 * Identity capability — auth state, session info, and identity accessors.
 */
export class IdentityCapability {
  #pool;
  #eventBus;
  #identity;

  constructor({ pool, eventBus, identity }) {
    this.#pool = pool;
    this.#eventBus = eventBus;
    this.#identity = identity;
  }

  get authState() {
    return this.#pool.authState ?? "unknown";
  }

  getSessionInfo() {
    return this.#pool.getSessionInfo();
  }

  getAccountId() {
    return this.#identity && this.#identity.accountId != null ? this.#identity.accountId : null;
  }

  getDeviceId() {
    return this.#identity && this.#identity.deviceId != null ? this.#identity.deviceId : null;
  }

  #deviceKey() {
    const id = this.#identity;
    if (!id || typeof id !== "object") return null;
    const dk = id.deviceKey && typeof id.deviceKey === "object" ? id.deviceKey : null;
    return dk;
  }

  /**
   * The persisted device-local public key (canonical Ed25519 SPKI base64), or
   * null for a keystore that predates device-key persistence (v1). The matching
   * private key is never exposed — signing happens inside buildDeviceRegistration.
   */
  getDeviceKeyPublicKeyB64() {
    const dk = this.#deviceKey();
    return dk && typeof dk.publicKeyB64 === "string" && dk.publicKeyB64.length > 0 ? dk.publicKeyB64 : null;
  }

  /**
   * Produce a DeviceRegistrationV1 signed by THIS account's identity key that
   * vouches for THIS device's persisted key (the device->account trust chain the
   * multi-device slices verify). Fails loud if the device key or account keypair
   * is absent — never returns an unsigned/partial record.
   *
   * @param {object} [opts]
   * @param {number} [opts.nowMs] — issuedAtMs (defaults to Date.now())
   * @param {number} [opts.ttlMs] — lifetime; expiresAtMs = issuedAtMs + ttlMs
   * @returns {Promise<import("@rezprotocol/core").DeviceRegistrationV1>}
   */
  async buildDeviceRegistration({ nowMs, ttlMs } = {}) {
    const id = this.#identity;
    const dk = this.#deviceKey();
    if (!dk || typeof dk.publicKeyB64 !== "string" || dk.publicKeyB64.length === 0) {
      throw new Error("IdentityCapability.buildDeviceRegistration: identity has no device key (keystore predates device-key persistence)");
    }
    if (!id || typeof id.publicKeyB64 !== "string" || typeof id.privateKeyB64 !== "string" || id.publicKeyB64.length === 0 || id.privateKeyB64.length === 0) {
      throw new Error("IdentityCapability.buildDeviceRegistration: identity has no account keypair to sign with");
    }
    return buildSignedDeviceRegistration({
      account: { publicKeyB64: id.publicKeyB64, privateKeyB64: id.privateKeyB64 },
      devicePublicKeyB64: dk.publicKeyB64,
      nowMs,
      ttlMs,
    });
  }

  /**
   * Produce a DeviceInboxBindingV1 signed by THIS device's key (C), asserting it
   * receives at `inboxId`. Paired with buildDeviceRegistration() (account-signed),
   * this is the proof a `device.bind` presents to the home. Fails loud if the
   * device keypair is absent (legacy keystore) or inboxId is missing.
   *
   * @param {object} opts
   * @param {string} opts.inboxId — the inbox this device receives at (its claimed inbox)
   * @param {number} [opts.nowMs] — issuedAtMs (defaults to Date.now())
   * @param {number} [opts.ttlMs] — lifetime; expiresAtMs = issuedAtMs + ttlMs
   * @returns {Promise<import("@rezprotocol/core").DeviceInboxBindingV1>}
   */
  async buildDeviceInboxBinding({ inboxId, nowMs, ttlMs } = {}) {
    const dk = this.#deviceKey();
    if (!dk || typeof dk.publicKeyB64 !== "string" || dk.publicKeyB64.length === 0
        || typeof dk.privateKeyB64 !== "string" || dk.privateKeyB64.length === 0) {
      throw new Error("IdentityCapability.buildDeviceInboxBinding: identity has no device keypair (keystore predates device-key persistence)");
    }
    if (typeof inboxId !== "string" || inboxId.trim().length === 0) {
      throw new Error("IdentityCapability.buildDeviceInboxBinding: inboxId is required");
    }
    return buildSignedDeviceInboxBinding({
      device: { publicKeyB64: dk.publicKeyB64, privateKeyB64: dk.privateKeyB64 },
      inboxId,
      nowMs,
      ttlMs,
    });
  }

  /**
   * Produce a DeviceRevokeV1 signed by THIS account's identity key (B-sign) that
   * fail-closes another device of this account at the home (the proof a
   * `device.revoke` presents). Closes the builder gap so DevicesCapability.revoke
   * has a real record to send. Fails loud if the account keypair is absent or the
   * revoked device key is missing.
   *
   * @param {object} opts
   * @param {string} opts.revokedDevicePublicKeyB64 — the device public key to revoke
   * @param {number} [opts.nowMs] — issuedAtMs (defaults to Date.now())
   * @param {number} [opts.ttlMs] — lifetime; expiresAtMs = issuedAtMs + ttlMs
   * @returns {Promise<import("@rezprotocol/core").DeviceRevokeV1>}
   */
  async buildDeviceRevoke({ revokedDevicePublicKeyB64, nowMs, ttlMs } = {}) {
    const id = this.#identity;
    if (!id || typeof id.publicKeyB64 !== "string" || typeof id.privateKeyB64 !== "string" || id.publicKeyB64.length === 0 || id.privateKeyB64.length === 0) {
      throw new Error("IdentityCapability.buildDeviceRevoke: identity has no account keypair to sign with");
    }
    if (typeof revokedDevicePublicKeyB64 !== "string" || revokedDevicePublicKeyB64.length === 0) {
      throw new Error("IdentityCapability.buildDeviceRevoke: revokedDevicePublicKeyB64 is required");
    }
    return buildSignedDeviceRevoke({
      account: { publicKeyB64: id.publicKeyB64, privateKeyB64: id.privateKeyB64 },
      revokedDevicePublicKeyB64,
      nowMs,
      ttlMs,
    });
  }

  // Resolve the signing keypair for a device-authority action. "account" signs
  // with the account root B (a primary device); "device" signs with the local
  // device key C (a delegated / seedless device). Fails loud when the requested
  // key is absent — never returns a partial signer.
  #resolveSigner(signWith) {
    const id = this.#identity;
    if (signWith === "device") {
      const dk = this.#deviceKey();
      if (!dk || typeof dk.publicKeyB64 !== "string" || dk.publicKeyB64.length === 0
          || typeof dk.privateKeyB64 !== "string" || dk.privateKeyB64.length === 0) {
        throw new Error("IdentityCapability: identity has no device keypair to sign with (keystore predates device-key persistence)");
      }
      return { publicKeyB64: dk.publicKeyB64, privateKeyB64: dk.privateKeyB64 };
    }
    if (!id || typeof id.publicKeyB64 !== "string" || typeof id.privateKeyB64 !== "string"
        || id.publicKeyB64.length === 0 || id.privateKeyB64.length === 0) {
      throw new Error("IdentityCapability: identity has no account keypair to sign with");
    }
    return { publicKeyB64: id.publicKeyB64, privateKeyB64: id.privateKeyB64 };
  }

  #accountPublicKeyB64() {
    const id = this.#identity;
    if (!id || typeof id.publicKeyB64 !== "string" || id.publicKeyB64.length === 0) {
      throw new Error("IdentityCapability: identity has no account public key");
    }
    return id.publicKeyB64;
  }

  /**
   * Produce a signed AccountDeviceMutationV1 (S2.5 S11) to submit to the account's
   * authority home. Dual-mode: `signWith: "account"` (default) signs with the
   * account root B (a primary device); `signWith: "device"` signs with the local
   * device key C (a delegated device — the home checks its granted capability).
   *
   * @param {object} opts
   * @param {string} opts.opId — idempotency key
   * @param {number} opts.expectedRevision — optimistic concurrency (int ≥ 0)
   * @param {"device.add"|"device.revoke"} opts.action
   * @param {object} opts.target — action-tagged target
   * @param {"account"|"device"} [opts.signWith] — signing key (default "account")
   * @param {number} [opts.nowMs]
   * @param {number} [opts.ttlMs]
   * @returns {Promise<import("@rezprotocol/core").AccountDeviceMutationV1>}
   */
  async buildAccountDeviceMutation({ opId, expectedRevision, action, target, signWith = "account", nowMs, ttlMs } = {}) {
    const signer = this.#resolveSigner(signWith);
    return buildSignedAccountDeviceMutation({
      signer,
      accountIdentityPublicKeyB64: this.#accountPublicKeyB64(),
      opId,
      expectedRevision,
      action,
      target,
      nowMs,
      ttlMs,
    });
  }

  /**
   * Produce a signed AccountAuthorityStateV1 (S2.5 S11, F4) — the account's
   * monotonic revocation snapshot to publish for off-home peers. Same dual-mode
   * signing as buildAccountDeviceMutation (default: account root B).
   *
   * @param {object} opts
   * @param {number} opts.epoch — the authority epoch (int ≥ 0)
   * @param {string[]} [opts.revokedCertIds] — rez:cap: ids
   * @param {number} [opts.minValidIssuedAtMs] — issued-at cutoff
   * @param {"account"|"device"} [opts.signWith] — signing key (default "account")
   * @param {number} [opts.nowMs]
   * @returns {Promise<import("@rezprotocol/core").AccountAuthorityStateV1>}
   */
  async buildAccountAuthorityState({ epoch, revokedCertIds, minValidIssuedAtMs, signWith = "account", nowMs } = {}) {
    const signer = this.#resolveSigner(signWith);
    return buildSignedAccountAuthorityState({
      signer,
      accountIdentityPublicKeyB64: this.#accountPublicKeyB64(),
      epoch,
      revokedCertIds,
      minValidIssuedAtMs,
      nowMs,
    });
  }

  getLocalInboxId() {
    const session = this.#pool.getSessionInfo();
    return session && session.localInboxId != null ? session.localInboxId : null;
  }

  onAuthStateChanged(handler) {
    return this.#eventBus.on(SDK_EVENTS.AUTH_STATE_CHANGED, handler);
  }

  onAuthenticated(handler) {
    return this.#eventBus.on(SDK_EVENTS.AUTH_AUTHENTICATED, handler);
  }

  onReauthRequired(handler) {
    return this.#eventBus.on(SDK_EVENTS.AUTH_REAUTH_REQUIRED, handler);
  }
}
