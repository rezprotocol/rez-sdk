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
    return this.#eventBus.on(SDK_EVENTS.TRANSPORT_RECONNECTED, handler);
  }

  onUplinkChanged(handler) {
    return this.#eventBus.on(SDK_EVENTS.TRANSPORT_UPLINK_CHANGED, handler);
  }
}
