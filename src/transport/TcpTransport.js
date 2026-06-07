import { Transport } from "./Transport.js";
import { createFrameCodec } from "./FrameCodec.js";

function asError(code, message, retryable = false) {
  const err = new Error(message || code || "TRANSPORT_ERR");
  err.code = code || "TRANSPORT_ERR";
  err.retryable = retryable;
  return err;
}

function makeId(prefix, seq) {
  return `${prefix}:${Date.now()}:${seq}`;
}

const HEADER_SIZE = 4;
const MAX_FRAME_BYTES_DEFAULT = 8 * 1024 * 1024; // 8MB, matching rez-node TcpTransport

/**
 * TCP transport — length-prefixed framing (4-byte big-endian) with JSON codec.
 * Wire-compatible with rez-node's TcpTransport.
 * Server-side (Node.js) only — uses node:net / node:tls.
 */
export class TcpTransport extends Transport {
  #host;
  #port;
  #tls;
  #codec;
  #timeouts;
  #maxFrameBytes;
  #socket = null;
  #seq = 0;
  #pending = new Map();
  #frameListeners = new Set();
  #stateListeners = new Set();
  #keepAliveTimer = null;
  #readBuffer = Buffer.alloc(0);
  #connected = false;

  constructor({
    host,
    port,
    tls = false,
    frameCodec = null,
    timeouts = {},
    maxFrameBytes = MAX_FRAME_BYTES_DEFAULT,
  } = {}) {
    super();
    if (!host) throw new Error("TcpTransport requires host");
    if (!port) throw new Error("TcpTransport requires port");
    this.#host = host;
    this.#port = Number(port);
    this.#tls = !!tls;
    this.#codec = frameCodec || createFrameCodec();
    this.#timeouts = {
      connectMs: Number.isFinite(Number(timeouts.connectMs)) ? Number(timeouts.connectMs) : 5000,
      requestMs: Number.isFinite(Number(timeouts.requestMs)) ? Number(timeouts.requestMs) : 8000,
      keepAliveMs: Number.isFinite(Number(timeouts.keepAliveMs)) ? Number(timeouts.keepAliveMs) : 30_000,
    };
    this.#maxFrameBytes = Math.max(1024, Number(maxFrameBytes) || MAX_FRAME_BYTES_DEFAULT);
  }

  get url() {
    return `${this.#tls ? "tls" : "tcp"}://${this.#host}:${this.#port}`;
  }

  async connect() {
    if (this.#connected && this.#socket && !this.#socket.destroyed) return;

    const connectFn = this.#tls
      ? (await import("node:tls")).connect
      : (await import("node:net")).createConnection;

    const connectOpts = { host: this.#host, port: this.#port };

    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        cleanup();
        socket.destroy();
        reject(asError("CONNECT_TIMEOUT", "tcp connect timeout", true));
      }, this.#timeouts.connectMs);

      const socket = this.#tls
        ? connectFn(connectOpts, () => {
            cleanup();
            onConnect();
          })
        : connectFn(connectOpts, () => {
            cleanup();
            onConnect();
          });

      this.#socket = socket;

      const cleanup = () => {
        clearTimeout(timeout);
        socket.removeListener("error", onErr);
      };

      const onConnect = () => {
        this.#connected = true;
        this.#readBuffer = Buffer.alloc(0);
        this.#emitState({ phase: "connected", url: this.url });
        resolve();
      };

      const onErr = (err) => {
        cleanup();
        reject(asError("CONNECT_FAILED", err && err.message || "tcp connect failed", true));
      };

      socket.once("error", onErr);
    });

    this.#socket.on("data", (chunk) => this.#onData(chunk));
    this.#socket.on("close", () => this.#onClosed({ reason: "socket closed" }));
    this.#socket.on("error", (err) => {
      this.#emitState({ phase: "error", url: this.url, reason: err && err.message || "socket error" });
    });

    this.#startKeepAlive();
  }

  async close() {
    this.#stopKeepAlive();
    this.#connected = false;
    for (const [, entry] of this.#pending) {
      clearTimeout(entry.timer);
      entry.reject(asError("DISCONNECTED", "socket closed", true));
    }
    this.#pending.clear();
    if (this.#socket) {
      try {
        this.#socket.destroy();
      } catch {
        // ignore
      }
      this.#socket = null;
    }
    this.#readBuffer = Buffer.alloc(0);
  }

  isConnected() {
    return this.#connected && !!this.#socket && !this.#socket.destroyed;
  }

  async sendFrame(frame) {
    if (!this.isConnected()) {
      throw asError("DISCONNECTED", "socket not connected", true);
    }
    const raw = this.#codec.encodeFrame(frame);
    this.#writeFrame(raw);
  }

  async sendRequest({
    type,
    body = {},
    expectedResponseType = null,
    timeoutMs = null,
  } = {}) {
    if (!this.isConnected()) {
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
    const frameRaw = this.#codec.encodeFrame({ id, type: frameType, body, version: 1 });

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
        this.#writeFrame(frameRaw);
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

  // --- Length-prefixed framing (4-byte big-endian) ---

  #writeFrame(jsonStr) {
    const payload = Buffer.from(jsonStr, "utf8");
    const header = Buffer.alloc(HEADER_SIZE);
    header.writeUInt32BE(payload.length, 0);
    this.#socket.write(Buffer.concat([header, payload]));
  }

  #onData(chunk) {
    this.#readBuffer = Buffer.concat([this.#readBuffer, chunk]);
    while (this.#readBuffer.length >= HEADER_SIZE) {
      const frameLen = this.#readBuffer.readUInt32BE(0);
      if (frameLen > this.#maxFrameBytes) {
        this.#emitState({ phase: "warn", url: this.url, reason: "frame too large" });
        this.#readBuffer = Buffer.alloc(0);
        return;
      }
      if (this.#readBuffer.length < HEADER_SIZE + frameLen) break;
      const payload = this.#readBuffer.subarray(HEADER_SIZE, HEADER_SIZE + frameLen);
      this.#readBuffer = this.#readBuffer.subarray(HEADER_SIZE + frameLen);
      this.#processFrame(payload.toString("utf8"));
    }
  }

  #processFrame(raw) {
    let frame;
    try {
      frame = this.#codec.decodeFrame(raw);
    } catch (err) {
      this.#emitState({ phase: "warn", url: this.url, reason: err && err.message || "bad frame" });
      return;
    }

    // Request-response correlation
    if (typeof (frame && frame.id) === "string" && this.#pending.has(frame.id)) {
      const pending = this.#pending.get(frame.id);
      this.#pending.delete(frame.id);
      clearTimeout(pending.timer);

      if (frame.type === "error") {
        pending.reject(asError(
          String(frame.body && frame.body.code || "REMOTE_ERR"),
          frame.body && frame.body.message || "remote error",
          (frame.body && frame.body.retryable) === true,
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

    // Unsolicited frame
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
        // listener errors non-fatal
      }
    }
  }

  // --- Keep-alive ---

  #startKeepAlive() {
    const intervalMs = this.#timeouts.keepAliveMs;
    if (!intervalMs || intervalMs <= 0) return;
    this.#stopKeepAlive();
    this.#keepAliveTimer = setInterval(() => this.#sendKeepAlive(), intervalMs);
    if (this.#keepAliveTimer.unref) this.#keepAliveTimer.unref();
  }

  #stopKeepAlive() {
    if (this.#keepAliveTimer) {
      clearInterval(this.#keepAliveTimer);
      this.#keepAliveTimer = null;
    }
  }

  #sendKeepAlive() {
    if (!this.isConnected()) return;
    try {
      const raw = this.#codec.encodeFrame({
        id: `ping:${Date.now()}`,
        type: "ping",
        body: {},
        version: 1,
      });
      this.#writeFrame(raw);
    } catch {
      this.#onClosed({ reason: "keep-alive send failed" });
    }
  }

  #onClosed(evt) {
    this.#stopKeepAlive();
    this.#connected = false;
    const err = asError("DISCONNECTED", evt && evt.reason || "socket closed", true);
    for (const [, entry] of this.#pending) {
      clearTimeout(entry.timer);
      entry.reject(err);
    }
    this.#pending.clear();
    this.#emitState({ phase: "disconnected", url: this.url, reason: evt && evt.reason || null });
  }

  #emitState(payload) {
    for (const listener of [...this.#stateListeners]) {
      try {
        listener(payload);
      } catch {
        // ignore
      }
    }
  }
}
