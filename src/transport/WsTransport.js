import { CONTRACT_VERSION } from "@rezprotocol/core";
import { Transport } from "./Transport.js";
import { createFrameCodec } from "./FrameCodec.js";

function makeId(prefix, seq) {
  return `${prefix}:${Date.now()}:${seq}`;
}

function asError(code, message, retryable = false) {
  const err = new Error(message || code || "TRANSPORT_ERR");
  err.code = code || "TRANSPORT_ERR";
  err.retryable = retryable;
  return err;
}

/**
 * WebSocket transport — raw frame send/receive with request-response correlation.
 * Auth logic is NOT included here; that is handled by AuthStateMachine.
 */
export class WsTransport extends Transport {
  #wsUrl;
  #wsFactory;
  #codec;
  #timeouts;
  #maxFrameBytes;
  #ws = null;
  #seq = 0;
  #pending = new Map();
  #frameListeners = new Set();
  #stateListeners = new Set();
  #heartbeatTimer = null;
  #lastPongAtMs = 0;
  #missedPongs = 0;
  #badFrameCount = 0;
  #badFrameWindowStart = 0;

  constructor({
    url,
    wsFactory = null,
    frameCodec = null,
    timeouts = {},
    maxFrameBytes = 1_000_000,
  } = {}) {
    super();
    if (typeof url !== "string" || url.trim().length === 0) {
      throw new Error("WsTransport requires url");
    }
    this.#wsUrl = url;
    this.#wsFactory = wsFactory || ((u) => new WebSocket(u));
    this.#codec = frameCodec || createFrameCodec();
    this.#timeouts = {
      connectMs: Number.isFinite(Number(timeouts.connectMs)) ? Number(timeouts.connectMs) : 5000,
      requestMs: Number.isFinite(Number(timeouts.requestMs)) ? Number(timeouts.requestMs) : 8000,
      heartbeatIntervalMs: Number.isFinite(Number(timeouts.heartbeatIntervalMs))
        ? Number(timeouts.heartbeatIntervalMs)
        : 30_000,
    };
    this.#maxFrameBytes = Math.max(1024, Number(maxFrameBytes) || 1_000_000);
  }

  get url() {
    return this.#wsUrl;
  }

  async connect() {
    if (this.#ws && this.#ws.readyState === 1) return;
    if (typeof this.#wsFactory !== "function") {
      throw new Error("WsTransport requires wsFactory");
    }
    const ws = this.#wsFactory(this.#wsUrl);
    if (!ws || typeof ws.addEventListener !== "function") {
      throw new Error("wsFactory must return ws-compatible object");
    }
    this.#ws = ws;

    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        cleanup();
        reject(asError("CONNECT_TIMEOUT", "connect timeout", true));
      }, this.#timeouts.connectMs);

      const cleanup = () => {
        clearTimeout(timeout);
        ws.removeEventListener("open", onOpen);
        ws.removeEventListener("error", onErr);
      };
      const onOpen = () => {
        cleanup();
        this.#emitState({ phase: "connected", url: this.#wsUrl });
        resolve();
      };
      const onErr = (evt) => {
        cleanup();
        reject(asError("CONNECT_FAILED", evt && evt.message || "connect failed", true));
      };
      ws.addEventListener("open", onOpen);
      ws.addEventListener("error", onErr);
    });

    ws.addEventListener("message", (evt) => this.#onRawFrame(evt ? evt.data : undefined));
    ws.addEventListener("close", (evt) => this.#onClosed(evt));
    ws.addEventListener("error", (evt) => {
      this.#emitState({ phase: "error", url: this.#wsUrl, reason: evt && evt.message || "socket error" });
    });

    this.#startHeartbeat();
  }

  async close() {
    this.#stopHeartbeat();
    for (const [, entry] of this.#pending) {
      clearTimeout(entry.timer);
      entry.reject(asError("DISCONNECTED", "socket closed", true));
    }
    this.#pending.clear();
    if (this.#ws) {
      try {
        this.#ws.close();
      } catch {
        // ignore close errors
      }
      this.#ws = null;
    }
  }

  isConnected() {
    return !!(this.#ws && this.#ws.readyState === 1);
  }

  async sendFrame(frame) {
    if (!this.#ws || this.#ws.readyState !== 1) {
      throw asError("DISCONNECTED", "socket not connected", true);
    }
    const raw = this.#codec.encodeFrame(frame);
    this.#ws.send(raw);
  }

  async sendRequest({
    type,
    body = {},
    expectedResponseType = null,
    timeoutMs = null,
  } = {}) {
    if (!this.#ws || this.#ws.readyState !== 1) {
      throw asError("DISCONNECTED", "socket not connected", true);
    }
    const frameType = String(type || "").trim();
    if (!frameType) {
      throw asError("BAD_REQUEST", "type required", false);
    }
    const id = makeId(frameType, ++this.#seq);
    const requestTimeoutMs =
      timeoutMs != null && Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0
        ? Number(timeoutMs)
        : this.#timeouts.requestMs;
    const frameRaw = this.#codec.encodeFrame({ id, type: frameType, body, version: CONTRACT_VERSION });

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (!this.#pending.has(id)) return;
        this.#pending.delete(id);
        reject(asError("TIMEOUT", `${frameType} timeout`, true));
      }, requestTimeoutMs);

      this.#pending.set(id, {
        resolve,
        reject,
        timer,
        expectedResponseType: expectedResponseType ? String(expectedResponseType) : null,
      });

      try {
        this.#ws.send(frameRaw);
      } catch (err) {
        clearTimeout(timer);
        this.#pending.delete(id);
        reject(asError("SEND_FAILED", err && err.message || "send failed", true));
      }
    });
  }

  onFrame(handler) {
    if (typeof handler !== "function") throw new Error("onFrame requires handler");
    this.#frameListeners.add(handler);
    return () => this.#frameListeners.delete(handler);
  }

  onState(handler) {
    if (typeof handler !== "function") throw new Error("onState requires handler");
    this.#stateListeners.add(handler);
    return () => this.#stateListeners.delete(handler);
  }

  #startHeartbeat() {
    const intervalMs = this.#timeouts.heartbeatIntervalMs;
    if (!intervalMs || intervalMs <= 0) return;
    this.#stopHeartbeat();
    this.#lastPongAtMs = 0;
    this.#missedPongs = 0;
    this.#heartbeatTimer = setInterval(() => this.#sendHeartbeat(), intervalMs);
    if (this.#heartbeatTimer.unref) this.#heartbeatTimer.unref();
  }

  #stopHeartbeat() {
    if (this.#heartbeatTimer) {
      clearInterval(this.#heartbeatTimer);
      this.#heartbeatTimer = null;
    }
  }

  #sendHeartbeat() {
    if (!this.#ws || this.#ws.readyState !== 1) return;
    // If we've sent heartbeats but never received a pong back, the connection
    // is likely dead (e.g. cable pull where no TCP FIN/RST arrives).
    if (this.#lastPongAtMs > 0) {
      this.#missedPongs = 0;
    } else if (this.#missedPongs >= 2) {
      this.#onClosed({ reason: "heartbeat pong timeout" });
      try { this.#ws.close(); } catch {}
      return;
    }
    this.#missedPongs += 1;
    this.#lastPongAtMs = 0;
    try {
      const frame = this.#codec.encodeFrame({
        id: `ping:${Date.now()}`,
        type: "ping",
        body: {},
        version: CONTRACT_VERSION,
      });
      this.#ws.send(frame);
    } catch {
      this.#onClosed({ reason: "heartbeat send failed" });
    }
  }

  #onClosed(evt) {
    this.#stopHeartbeat();
    const err = asError("DISCONNECTED", evt && evt.reason || "socket closed", true);
    for (const [, entry] of this.#pending) {
      clearTimeout(entry.timer);
      entry.reject(err);
    }
    this.#pending.clear();
    this.#emitState({ phase: "disconnected", url: this.#wsUrl, reason: evt && evt.reason || null });
  }

  #onRawFrame(rawData) {
    const raw = typeof rawData === "string" ? rawData : String(rawData || "");
    const bytes = new TextEncoder().encode(raw);
    if (bytes.length > this.#maxFrameBytes) {
      this.#emitState({ phase: "warn", url: this.#wsUrl, reason: "frame too large" });
      return;
    }

    let frame;
    try {
      frame = this.#codec.decodeFrame(raw);
    } catch (err) {
      const errReason = err && err.message ? err.message : "bad frame";
      this.#emitState({ phase: "warn", url: this.#wsUrl, reason: errReason });
      // Rate-limit malformed frames: disconnect if >10 bad frames in 5 seconds
      const now = Date.now();
      if (now - this.#badFrameWindowStart > 5000) {
        this.#badFrameCount = 0;
        this.#badFrameWindowStart = now;
      }
      this.#badFrameCount++;
      if (this.#badFrameCount > 10) {
        this.#emitState({ phase: "error", url: this.#wsUrl, reason: "too many bad frames — disconnecting" });
        this.close();
      }
      return;
    }

    // Heartbeat pong — record receipt so #sendHeartbeat knows the server is alive.
    if (frame && frame.type === "pong") {
      this.#lastPongAtMs = Date.now();
      return;
    }

    // Request-response correlation
    if (frame && typeof frame.id === "string" && this.#pending.has(frame.id)) {
      const pending = this.#pending.get(frame.id);
      this.#pending.delete(frame.id);
      clearTimeout(pending.timer);

      if (frame.type === "error" || frame.type === "chat.error") {
        const frameBody = frame.body && typeof frame.body === "object" ? frame.body : {};
        const retryable =
          frameBody.retryable === true ||
          !!(frameBody.detail && typeof frameBody.detail === "object" && frameBody.detail.retryable === true);
        pending.reject(asError(
          String(frameBody.code || "REMOTE_ERR"),
          frameBody.message || "remote error",
          retryable,
        ));
        return;
      }

      if (pending.expectedResponseType && String(frame.type || "") !== pending.expectedResponseType) {
        pending.reject(asError(
          "BAD_RESPONSE",
          `unexpected response type: ${String(frame.type || "")}`,
          false,
        ));
        return;
      }

      pending.resolve({
        id: frame.id,
        t: String(frame.type || ""),
        v: frame.version,
        body: frame.body && typeof frame.body === "object" ? frame.body : {},
      });
      return;
    }

    // Unsolicited frame — emit to frame listeners
    const framePayload = {
      id: typeof (frame && frame.id) === "string" ? frame.id : null,
      t: String(frame && frame.type || ""),
      v: frame ? frame.version : undefined,
      body: frame && frame.body && typeof frame.body === "object" ? frame.body : {},
    };
    for (const listener of [...this.#frameListeners]) {
      try {
        listener(framePayload);
      } catch {
        // listener errors should not break socket handling
      }
    }
  }

  #emitState(payload) {
    for (const listener of [...this.#stateListeners]) {
      try {
        listener(payload);
      } catch {
        // ignore listener errors
      }
    }
  }
}
