import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";
import { SDK_EVENTS } from "../events/SdkEvents.js";

const T = REZ_CONTRACT_TYPES;

/**
 * Subscription capability — server-push event subscriptions
 * with reconnect-aware resubscription.
 */
export class SubscriptionCapability {
  #pool;
  #eventBus;
  #subscriptions = new Map(); // key -> { eventType, handler }

  constructor({ pool, eventBus }) {
    this.#pool = pool;
    this.#eventBus = eventBus;

    // On reconnect, resubscribe all active subscriptions
    this.#eventBus.on(SDK_EVENTS.TRANSPORT_RECONNECTED, () => {
      this._resubscribeAll();
    });
  }

  onMailboxDeposited(handler) {
    return this.#subscribe(T.EVT_MAILBOX_DEPOSITED, handler);
  }

  onEvent(eventType, handler) {
    return this.#subscribe(String(eventType || ""), handler);
  }

  _resubscribeAll() {
    // Pool frame handlers persist across reconnects (they're registered on the pool, not the transport),
    // so no explicit resubscription is needed here. This hook exists for future use
    // (e.g., server-side subscription registration after reconnect).
  }

  #subscribe(eventType, handler) {
    if (typeof handler !== "function") throw new Error("handler required");
    const key = `${eventType}:${Date.now()}:${Math.random()}`;
    this.#subscriptions.set(key, { eventType, handler });
    const off = this.#pool.on(eventType, handler);
    return () => {
      this.#subscriptions.delete(key);
      off();
    };
  }
}
