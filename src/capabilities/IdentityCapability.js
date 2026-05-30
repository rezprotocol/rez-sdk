import { SDK_EVENTS } from "../events/SdkEvents.js";

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
    return this.#identity?.accountId ?? null;
  }

  getDeviceId() {
    return this.#identity?.deviceId ?? null;
  }

  getLocalInboxId() {
    const session = this.#pool.getSessionInfo();
    return session?.localInboxId ?? null;
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
