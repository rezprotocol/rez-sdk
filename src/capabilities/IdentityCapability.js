import { SDK_EVENTS } from "../events/SdkEvents.js";
import { buildSignedDeviceRegistration } from "../device/deviceIdentity.js";

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
