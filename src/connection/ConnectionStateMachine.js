import { CONNECTION_STATES } from "./ConnectionState.js";
import { SDK_EVENTS } from "../events/SdkEvents.js";

/**
 * Connection state machine — manages the lifecycle of a single transport connection.
 * Composes a Transport + AuthStateMachine. Emits typed events on every transition.
 * Owns reconnect backoff (exponential with jitter).
 *
 * States: DISCONNECTED -> CONNECTING -> AUTHENTICATING -> CONNECTED -> RECONNECTING -> FAILED
 */
export class ConnectionStateMachine {
  #state = CONNECTION_STATES.DISCONNECTED;
  #transport;
  #eventBus;
  #authMachine;
  #reconnect;
  #reconnectTimer = null;
  #reconnectAttempts = 0;
  #closed = false;
  #offTransportState = null;

  constructor({ transport, eventBus, authMachine, reconnect = {} } = {}) {
    if (!transport) throw new Error("ConnectionStateMachine requires transport");
    if (!eventBus) throw new Error("ConnectionStateMachine requires eventBus");
    if (!authMachine) throw new Error("ConnectionStateMachine requires authMachine");
    this.#transport = transport;
    this.#eventBus = eventBus;
    this.#authMachine = authMachine;
    this.#reconnect = {
      enabled: reconnect.enabled !== false,
      backoffMs: Math.max(1000, Number(reconnect.backoffMs) || 2000),
      backoffCapMs: Math.max(5000, Number(reconnect.backoffCapMs) || 60_000),
      maxAttempts: Number.isFinite(Number(reconnect.maxAttempts)) ? Number(reconnect.maxAttempts) : Infinity,
    };
  }

  get state() {
    return this.#state;
  }

  get transport() {
    return this.#transport;
  }

  async connect() {
    this.#closed = false;
    this.#stopReconnectTimer();

    try {
      // CONNECTING
      this.#transition(CONNECTION_STATES.CONNECTING);
      await this.#transport.close().catch(() => {});
      this.#offTransportState?.();
      this.#offTransportState = this.#transport.onState((state) => {
        if (state?.phase === "disconnected" || state?.phase === "error") {
          this.#onTransportDisconnect(state?.reason || "transport disconnected");
        }
      });

      await this.#transport.connect();

      // AUTHENTICATING
      this.#transition(CONNECTION_STATES.AUTHENTICATING);
      await this.#authMachine.authenticate(this.#transport);

      // CONNECTED
      this.#reconnectAttempts = 0;
      this.#transition(CONNECTION_STATES.CONNECTED);
    } catch (err) {
      if (this.#closed) return;
      this.#transition(CONNECTION_STATES.FAILED, { error: err?.message });
      throw err;
    }
  }

  async disconnect() {
    this.#closed = true;
    this.#stopReconnectTimer();
    this.#reconnectAttempts = 0;
    this.#offTransportState?.();
    this.#offTransportState = null;
    await this.#transport.close().catch(() => {});
    this.#authMachine.reset();
    this.#transition(CONNECTION_STATES.DISCONNECTED);
  }

  #onTransportDisconnect(reason) {
    if (this.#closed) return;
    if (this.#state === CONNECTION_STATES.DISCONNECTED) return;
    if (this.#state === CONNECTION_STATES.RECONNECTING) return;

    this.#authMachine.reset();

    if (!this.#reconnect.enabled) {
      this.#transition(CONNECTION_STATES.FAILED, { reason });
      return;
    }

    this.#transition(CONNECTION_STATES.RECONNECTING, { reason });
    this.#scheduleReconnect();
  }

  #scheduleReconnect() {
    if (this.#closed || this.#reconnectTimer) return;
    this.#reconnectAttempts += 1;

    if (this.#reconnectAttempts > this.#reconnect.maxAttempts) {
      this.#transition(CONNECTION_STATES.FAILED, { reason: "max reconnect attempts" });
      return;
    }

    const jitter = 0.5 + Math.random();
    const delayMs = Math.min(
      this.#reconnect.backoffCapMs,
      this.#reconnect.backoffMs * Math.pow(2, this.#reconnectAttempts - 1) * jitter,
    );

    this.#eventBus.emit(SDK_EVENTS.TRANSPORT_RECONNECTING, {
      attempt: this.#reconnectAttempts,
      delayMs: Math.round(delayMs),
    });

    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = null;
      if (this.#closed) return;
      this.connect().then(
        () => {
          this.#reconnectAttempts = 0;
          this.#eventBus.emit(SDK_EVENTS.TRANSPORT_RECONNECTED, {});
        },
        () => {
          if (this.#closed) return;
          this.#scheduleReconnect();
        },
      );
    }, delayMs);

    if (this.#reconnectTimer.unref) this.#reconnectTimer.unref();
  }

  #stopReconnectTimer() {
    if (this.#reconnectTimer) {
      clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
  }

  #transition(newState, detail = {}) {
    const prev = this.#state;
    if (prev === newState) return;
    this.#state = newState;
    this.#eventBus.emit(SDK_EVENTS.CONNECTION_STATE_CHANGED, { prev, state: newState, ...detail });
  }
}
