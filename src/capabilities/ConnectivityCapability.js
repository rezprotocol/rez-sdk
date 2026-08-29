import { SDK_EVENTS } from "../events/SdkEvents.js";

/**
 * Connectivity capability — connection state, uplink info, and connectivity events.
 */
export class ConnectivityCapability {
  #pool;
  #eventBus;

  constructor({ pool, eventBus }) {
    this.#pool = pool;
    this.#eventBus = eventBus;
  }

  get connectionState() {
    return this.#pool.connectionState ?? "unknown";
  }

  getActiveUplink() {
    return this.#pool.getActiveUplink();
  }

  getUplinkStates() {
    return this.#pool.getUplinkStates();
  }

  onConnectionStateChanged(handler) {
    return this.#eventBus.on(SDK_EVENTS.CONNECTION_STATE_CHANGED, handler);
  }

  onHealthChanged(handler) {
    return this.#eventBus.on(SDK_EVENTS.CONNECTION_HEALTH_CHANGED, handler);
  }

  onReconnecting(handler) {
    return this.#eventBus.on(SDK_EVENTS.TRANSPORT_RECONNECTING, handler);
  }

  onReconnected(handler) {
    if (this.#pool && typeof this.#pool.onReconnected === "function") {
      return this.#pool.onReconnected(handler);
    }
    return this.#eventBus.on(SDK_EVENTS.TRANSPORT_RECONNECTED, handler);
  }

  /**
   * M2 (mobile lifecycle): cancel any pending reconnect backoff wait and run
   * one serialized reconnect attempt NOW — the platform-wake liveness kick.
   * Resolves after the session-restoration hooks ran (same contract as a
   * scheduled reconnect); rejects when the attempt failed or the pool cannot
   * support the kick — never a silent no-op.
   */
  async connectNow() {
    if (this.#pool && typeof this.#pool.connectNow === "function") {
      return this.#pool.connectNow();
    }
    throw new Error("connectivity.connectNow unavailable: this pool does not implement connectNow");
  }

  onUplinkChanged(handler) {
    return this.#eventBus.on(SDK_EVENTS.TRANSPORT_UPLINK_CHANGED, handler);
  }
}
