import { base64ToBytes, fnv1a64Hex, stableJson } from "@rezprotocol/core";
import { SDK_EVENTS } from "../events/SdkEvents.js";
import { DeduperLRU } from "./DeduperLRU.js";
import { FloodGate } from "./FloodGate.js";
import { WARN_CODES } from "./WarnCodes.js";

const MAX_DEDUPE_HASH_BYTES = 64 * 1024;
const LARGE_FRAME_WARN_WINDOW_MS = 1000;
const RETRYABLE_FAILOVER_CODES = Object.freeze([
  "RATE_LIMITED",
  "TIMEOUT",
  "DISCONNECTED",
  "UNREACHABLE",
  "CONNECT_FAILED",
  "CONNECT_TIMEOUT",
  "SEND_FAILED",
]);

function errObj({ code, message, retryable }) {
  const err = new Error(message || code || "UPLINK_ERR");
  err.code = code || "UPLINK_ERR";
  err.retryable = retryable === true;
  return err;
}

/**
 * Transport-agnostic uplink connection pool.
 * Adapted from rez-node/src/network/ws/UplinkPoolClient.js.
 *
 * Manages multiple uplink transports with warm spares, failover,
 * dedupe, and flood gating. No rez-node imports.
 */
export class UplinkPool {
  #uplinks;
  #transportFactory;
  #authMachine;
  #eventBus;
  #warmSpareCount;
  #timeouts;
  #maxRequestAttempts;
  #dedupe;
  #flood;

  #conns = new Map(); // url -> { transport, ready, healthy, offFrame, offState }
  #activeUrl = null;
  #sessionInfo = null;
  #events = new Map(); // frameType -> handlers
  #stateHandlers = new Set();
  #ready = false;
  #promotePromise = null;
  #spareEnsurePromise = null;
  #spareEnsureQueued = false;
  #largeUnidentifiableDrops = 0;
  #largeWarnSinceMs = 0;
  #largeWarnDroppedCount = 0;
  #largeWarnLastMeta = null;
  #reconnectTimer = null;
  #reconnectAttempts = 0;
  #reconnectBackoffMs;
  #reconnectBackoffCapMs;
  #closed = false;

  constructor({
    uplinks,
    transportFactory,
    authMachine,
    eventBus,
    warmSpareCount = 2,
    timeouts = {},
    maxRequestAttempts = 3,
    dedupe = {},
    flood = {},
  } = {}) {
    if (!Array.isArray(uplinks) || uplinks.length === 0) {
      throw new Error("UplinkPool requires uplinks[]");
    }
    if (typeof transportFactory !== "function") {
      throw new Error("UplinkPool requires transportFactory");
    }
    if (!authMachine) throw new Error("UplinkPool requires authMachine");
    if (!eventBus) throw new Error("UplinkPool requires eventBus");

    this.#uplinks = uplinks.map((u) => String(typeof u === "string" ? u : u && u.url || "").trim()).filter(Boolean);
    this.#transportFactory = transportFactory;
    this.#authMachine = authMachine;
    this.#eventBus = eventBus;
    this.#warmSpareCount = Math.max(0, Number(warmSpareCount) || 0);
    this.#timeouts = {
      connectHelloMs: Number.isFinite(Number(timeouts.connectHelloMs)) ? Number(timeouts.connectHelloMs) : 5000,
      requestMs: Number.isFinite(Number(timeouts.requestMs)) ? Number(timeouts.requestMs) : 8000,
    };
    this.#maxRequestAttempts = Math.max(1, Math.min(3, Number(maxRequestAttempts) || 3));
    this.#dedupe = new DeduperLRU(dedupe);
    this.#flood = new FloodGate(flood);
    this.#reconnectBackoffMs = Math.max(1000, Number(timeouts.reconnectBackoffMs) || 2000);
    this.#reconnectBackoffCapMs = Math.max(5000, Number(timeouts.reconnectBackoffCapMs) || 60_000);
  }

  async connect() {
    this.#closed = false;
    this.#stopReconnectTimer();
    await this.#closeConnections();

    let firstErr = null;
    for (const url of this.#uplinks) {
      try {
        await this.#ensureConnected(url);
        this.#setActive(url);
        this.#ready = true;
        this.#emitState({ phase: "connected", activeUplink: url });
        break;
      } catch (err) {
        if (!firstErr) firstErr = err;
      }
    }

    if (!this.#ready || !this.#activeUrl) {
      this.#emitState({ phase: "offline", reason: firstErr && firstErr.message || "no uplinks available" });
      this.#scheduleReconnect();
      throw errObj({ code: "UNREACHABLE", message: firstErr && firstErr.message || "no uplinks available", retryable: true });
    }
    await this.#ensureWarmSpareTarget();
  }

  async close() {
    this.#closed = true;
    this.#stopReconnectTimer();
    this.#reconnectAttempts = 0;
    await this.#closeConnections();
  }

  getActiveUplink() {
    return this.#activeUrl;
  }

  getUplinkStates() {
    return this.#uplinks.map((url) => {
      const state = this.#conns.get(url);
      return {
        url,
        active: url === this.#activeUrl,
        ready: (state && state.ready) === true,
        healthy: (state && state.healthy) === true,
      };
    });
  }

  getSessionInfo() {
    return this.#sessionInfo ? { ...this.#sessionInfo } : null;
  }

  on(type, handler) {
    if (typeof type !== "string" || type.length === 0) throw new Error("on(type, handler) requires type");
    if (typeof handler !== "function") throw new Error("on(type, handler) requires handler");
    const set = this.#events.get(type) || new Set();
    set.add(handler);
    this.#events.set(type, set);
    return () => {
      const current = this.#events.get(type);
      if (!current) return;
      current.delete(handler);
      if (current.size === 0) this.#events.delete(type);
    };
  }

  onState(handler) {
    if (typeof handler !== "function") throw new Error("onState(handler) requires handler");
    this.#stateHandlers.add(handler);
    return () => this.#stateHandlers.delete(handler);
  }

  async sendRequest({
    type,
    body = {},
    expectedResponseType = null,
    timeoutMs = null,
    tryAllUplinks = false,
    continueOnCodes = null,
    adoptSuccessfulUplink = false,
    adoptReason = null,
    skipActiveUplink = false,
  } = {}) {
    const frameType = String(type || "").trim();
    if (!frameType) {
      throw errObj({ code: "BAD_REQUEST", message: "type required", retryable: false });
    }
    const allowedCodes = continueOnCodes instanceof Set
      ? continueOnCodes
      : new Set(Array.isArray(continueOnCodes) ? continueOnCodes.map((v) => String(v || "").trim()) : []);

    if (!tryAllUplinks) {
      if (!this.#ready || !this.#activeUrl) {
        throw errObj({ code: "NOT_READY", message: "uplink pool not ready", retryable: true });
      }
      const active = this.#conns.get(this.#activeUrl);
      if (!(active && active.ready)) {
        throw errObj({ code: "UNREACHABLE", message: "no ready uplink", retryable: true });
      }
      return active.transport.sendRequest({ type: frameType, body, expectedResponseType, timeoutMs });
    }

    const activeUrl = this.getActiveUplink();
    const ordered = skipActiveUplink
      ? [...this.#uplinks.filter((u) => u !== activeUrl), ...(activeUrl ? [activeUrl] : [])]
      : [...(activeUrl ? [activeUrl] : []), ...this.#uplinks.filter((u) => u !== activeUrl)];

    let attempted = 0;
    let lastErr = null;
    for (const url of ordered) {
      attempted += 1;
      try {
        await this.#ensureConnected(url);
      } catch (err) {
        lastErr = err;
        continue;
      }

      const state = this.#conns.get(url);
      if (!(state && state.ready)) continue;
      try {
        const frame = await state.transport.sendRequest({ type: frameType, body, expectedResponseType, timeoutMs });
        if (adoptSuccessfulUplink && url !== this.#activeUrl) {
          this.#setActive(url);
          this.#emitState({ phase: "failover", from: activeUrl, to: url, reason: String(adoptReason || "request_success_adopt"), activeUplink: url });
          this.#emitState({ phase: "connected", activeUplink: url });
        }
        return frame;
      } catch (err) {
        lastErr = err;
        const code = String(err && err.code || "").trim();
        if (!allowedCodes.has(code)) throw err;
      }
    }

    if (attempted === 0) {
      throw errObj({ code: "UNREACHABLE", message: "no uplinks configured", retryable: true });
    }
    throw lastErr || errObj({ code: "UNREACHABLE", message: `${frameType} failed across uplinks`, retryable: true });
  }

  // --- Internal ---

  async #ensureConnected(url) {
    const existing = this.#conns.get(url);
    if (existing && existing.ready) return existing;

    const transport = existing && existing.transport || this.#transportFactory(url);
    if (!existing) {
      const offFrame = transport.onFrame((frame) => {
        this.#onInboundFrame(url, frame).catch(() => {});
      });
      const offState = transport.onState((state) => {
        this.#onConnState(url, state).catch(() => {});
      });
      this.#conns.set(url, { transport, ready: false, healthy: false, offFrame, offState });
    }

    await transport.connect();
    await this.#authMachine.authenticate(transport);
    this.#mark(url, { ready: true, healthy: true });
    return this.#conns.get(url);
  }

  async #closeConnections() {
    const entries = [...this.#conns.entries()];
    this.#conns.clear();
    this.#activeUrl = null;
    this.#sessionInfo = null;
    this.#ready = false;
    this.#promotePromise = null;
    this.#spareEnsurePromise = null;
    this.#spareEnsureQueued = false;
    this.#largeUnidentifiableDrops = 0;
    this.#largeWarnSinceMs = 0;
    this.#largeWarnDroppedCount = 0;
    this.#largeWarnLastMeta = null;
    for (const [, state] of entries) {
      try {
        if (state.offFrame) state.offFrame();
        if (state.offState) state.offState();
        await state.transport.close();
      } catch {
        // ignore close failures
      }
    }
    this.#dedupe.clear();
    this.#flood.clear();
  }

  async #promoteNextConnectedSpare(reason = "failover") {
    return this.#runPromotion(async () => {
      const from = this.#activeUrl;
      let candidate = this.#findConnectedSpare();
      if (!candidate) {
        await this.#ensureWarmSpareTarget();
        candidate = this.#findConnectedSpare();
      }
      if (!candidate) return false;

      this.#setActive(candidate);
      this.#ready = true;
      this.#emitState({ phase: "failover", from, to: candidate, reason, activeUplink: candidate });
      this.#emitState({ phase: "connected", activeUplink: candidate });
      await this.#ensureWarmSpareTarget();
      return true;
    });
  }

  async #onConnState(url, state) {
    if (state && state.phase === "warn") {
      this.#emit("warn", { code: "FRAME_WARN", uplink: url, reason: state && state.reason || "warn" });
    }
    if (state && state.phase === "disconnected" || state && state.phase === "error") {
      this.#mark(url, { ready: false, healthy: false });
      if (url === this.#activeUrl) {
        const promoted = await this.#promoteNextConnectedSpare("active_disconnect");
        if (!promoted) {
          this.#ready = false;
          this.#activeUrl = null;
          this.#sessionInfo = null;
          this.#emitState({ phase: "offline", activeUplink: url, reason: state && state.reason || null });
          this.#scheduleReconnect();
        }
      } else {
        if (this.#spareEnsurePromise) this.#spareEnsureQueued = true;
        await this.#ensureWarmSpareTarget();
      }
    }
  }

  async #onInboundFrame(url, frame) {
    if (!frame || typeof frame.t !== "string") return;
    const nowMs = Date.now();
    if (!this.#flood.allow(url, nowMs)) {
      const warn = this.#flood.consumeWarn(nowMs);
      if (warn) this.#emit("warn", warn);
      return;
    }

    const decision = await dedupeDecision(frame);
    if (decision.dropLargeUnidentifiable) {
      this.#recordLargeUnidentifiableDrop({ nowMs, approxBytes: decision.approxBytes, frameType: frame.t });
      return;
    }

    const key = decision.key;
    if (key && this.#dedupe.seen(key, nowMs)) return;
    if (key) this.#dedupe.mark(key, nowMs);

    this.#emit(frame.t, frame);
  }

  #recordLargeUnidentifiableDrop({ nowMs, approxBytes, frameType }) {
    this.#largeUnidentifiableDrops += 1;
    this.#largeWarnDroppedCount += 1;
    this.#largeWarnLastMeta = { approxBytes, frameType };
    if (this.#largeWarnSinceMs === 0) this.#largeWarnSinceMs = nowMs;
    const elapsed = nowMs - this.#largeWarnSinceMs;
    if (elapsed < LARGE_FRAME_WARN_WINDOW_MS && this.#largeWarnDroppedCount > 1) return;

    this.#emit("warn", {
      code: WARN_CODES.UNIDENTIFIABLE_LARGE_FRAME,
      droppedCount: this.#largeWarnDroppedCount,
      approxBytes: this.#largeWarnLastMeta.approxBytes,
      t: this.#largeWarnLastMeta.frameType,
      totalDropped: this.#largeUnidentifiableDrops,
    });
    this.#largeWarnSinceMs = nowMs;
    this.#largeWarnDroppedCount = 0;
    this.#largeWarnLastMeta = null;
  }

  #stopReconnectTimer() {
    if (this.#reconnectTimer) {
      clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
  }

  #scheduleReconnect() {
    if (this.#closed || this.#reconnectTimer) return;
    this.#reconnectAttempts += 1;
    const delayMs = Math.min(
      this.#reconnectBackoffCapMs,
      this.#reconnectBackoffMs * Math.pow(2, this.#reconnectAttempts - 1),
    );
    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = null;
      if (this.#closed) return;
      this.connect().then(
        () => { this.#reconnectAttempts = 0; },
        () => {
          this.#emitState({ phase: "offline", reason: "reconnect failed" });
          this.#scheduleReconnect();
        },
      );
    }, delayMs);
    if (this.#reconnectTimer.unref) this.#reconnectTimer.unref();
  }

  async #ensureWarmSpareTarget() {
    if (this.#spareEnsurePromise) return this.#spareEnsurePromise;
    this.#spareEnsurePromise = (async () => {
      if (!this.#activeUrl) return;
      const target = this.#warmSpareCount;
      if (target <= 0) return;
      const connectedSpares = () => this.#uplinks.filter((url) => {
        if (url === this.#activeUrl) return false;
        const st = this.#conns.get(url);
        return !!(st && st.ready && st && st.healthy);
      }).length;

      if (connectedSpares() >= target) return;
      for (const url of this.#uplinks) {
        if (url === this.#activeUrl) continue;
        if (connectedSpares() >= target) break;
        const st = this.#conns.get(url);
        if (st && st.ready && st && st.healthy) continue;
        try { await this.#ensureConnected(url); } catch { this.#mark(url, { ready: false, healthy: false }); }
      }
    })();
    try {
      await this.#spareEnsurePromise;
    } finally {
      this.#spareEnsurePromise = null;
    }
    if (this.#spareEnsureQueued && !this.#closed) {
      this.#spareEnsureQueued = false;
      return this.#ensureWarmSpareTarget();
    }
  }

  #findConnectedSpare() {
    for (const url of this.#uplinks) {
      if (url === this.#activeUrl) continue;
      const st = this.#conns.get(url);
      if (st && st.ready && st && st.healthy) return url;
    }
    return null;
  }

  #setActive(url) {
    this.#activeUrl = url;
    this.#sessionInfo = this.#authMachine.sessionInfo;
    if (this.#activeUrl) {
      this.#eventBus.emit(SDK_EVENTS.TRANSPORT_UPLINK_CHANGED, { url });
    }
  }

  #mark(url, patch) {
    const state = this.#conns.get(url);
    if (!state) return;
    this.#conns.set(url, { ...state, ...patch });
  }

  #emit(type, payload) {
    const handlers = this.#events.get(type);
    if (!handlers || handlers.size === 0) return;
    for (const handler of [...handlers]) {
      try { handler(payload); } catch { /* ignore */ }
    }
  }

  #emitState(payload) {
    for (const handler of [...this.#stateHandlers]) {
      try { handler(payload); } catch { /* ignore */ }
    }
  }

  async #runPromotion(fn) {
    if (this.#promotePromise) return this.#promotePromise;
    this.#promotePromise = (async () => {
      try { return await fn(); } finally { this.#promotePromise = null; }
    })();
    return this.#promotePromise;
  }
}

// --- Dedupe helpers ---

async function dedupeDecision(frame) {
  const body = frame && frame.body && typeof frame.body === "object" ? frame.body : {};
  const serverMsgId = firstNonEmptyString(body.serverMsgId, body && body.message && body.message.serverMsgId, body && body.message && body.message.id);
  if (serverMsgId) return { key: `s:${serverMsgId}`, dropLargeUnidentifiable: false };

  const packetId = firstNonEmptyString(body.packetId, body && body.message && body.message.packetId);
  if (packetId) return { key: `p:${packetId}`, dropLargeUnidentifiable: false };

  const b64 = extractBase64Payload(body);
  if (b64) {
    const approxBytes = estimateBase64Bytes(b64);
    if (approxBytes > MAX_DEDUPE_HASH_BYTES) {
      return { key: null, dropLargeUnidentifiable: true, approxBytes };
    }
    const bytes = safeBase64ToBytes(b64);
    if (bytes.length > 0) {
      return { key: `h:${await sha256Hex(bytes)}`, dropLargeUnidentifiable: false };
    }
  }

  const stable = stableJson(body);
  return { key: `j:${await sha256Hex(new TextEncoder().encode(stable))}`, dropLargeUnidentifiable: false };
}

function firstNonEmptyString(...values) {
  for (const v of values) {
    if (typeof v === "string" && v.length > 0) return v;
  }
  return null;
}

function extractBase64Payload(body) {
  const candidates = [body && body.payload && body.payload.ciphertextB64, body && body.payload && body.payload.packetB64, body && body.packetB64, body && body.message && body.message.packetB64];
  for (const c of candidates) {
    if (typeof c === "string" && c.length > 0) return c;
  }
  return null;
}

function safeBase64ToBytes(value) {
  if (typeof value !== "string") return new Uint8Array();
  try { return base64ToBytes(value); } catch { return new Uint8Array(); }
}

function estimateBase64Bytes(value) {
  const cleaned = String(value || "").replace(/\s+/g, "");
  if (cleaned.length === 0) return 0;
  const padding = cleaned.endsWith("==") ? 2 : cleaned.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((cleaned.length * 3) / 4) - padding);
}

async function sha256Hex(bytes) {
  if (globalThis.crypto && globalThis.crypto.subtle) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
    return toHex(new Uint8Array(digest));
  }
  return fnv1a64Hex(bytes);
}

function toHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}
