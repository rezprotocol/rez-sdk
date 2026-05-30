import { CONTRACT_VERSION, REZ_CONTRACT_TYPES } from "@rezprotocol/core";
import { TypedEventBus } from "../events/TypedEventBus.js";
import { AuthStateMachine } from "../auth/AuthStateMachine.js";
import { UplinkPool } from "../pool/UplinkPool.js";
import { WsTransport } from "../transport/WsTransport.js";
import { createFrameCodec } from "../transport/FrameCodec.js";

const RETRYABLE_FAILOVER_CODES = Object.freeze([
  "RATE_LIMITED",
  "TIMEOUT",
  "DISCONNECTED",
  "UNREACHABLE",
  "CONNECT_FAILED",
  "CONNECT_TIMEOUT",
  "SEND_FAILED",
]);

function createError({ code, message, retryable }) {
  const err = new Error(message || code || "UPLINK_ERR");
  err.code = code || "UPLINK_ERR";
  err.retryable = retryable === true;
  return err;
}

function makeDeviceId() {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === "function") {
    return `rez-sdk:${globalThis.crypto.randomUUID()}`;
  }
  return `rez-sdk:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeSessionHello(sessionHello) {
  if (!sessionHello || typeof sessionHello !== "object") {
    return {
      requestType: REZ_CONTRACT_TYPES.SESSION_HELLO,
      responseType: REZ_CONTRACT_TYPES.SESSION_READY,
      body: { contractVersion: CONTRACT_VERSION },
    };
  }
  const body = sessionHello.body && typeof sessionHello.body === "object"
    ? sessionHello.body
    : { contractVersion: CONTRACT_VERSION };
  return {
    requestType: String(sessionHello.requestType || REZ_CONTRACT_TYPES.SESSION_HELLO),
    responseType: String(sessionHello.responseType || REZ_CONTRACT_TYPES.SESSION_READY),
    body,
  };
}

function resolveType(typeOrRecord) {
  if (typeof typeOrRecord === "string") return typeOrRecord;
  if (!typeOrRecord || typeof typeOrRecord !== "object") return "";
  if (typeof typeOrRecord.type === "string" && typeOrRecord.type.length > 0) return typeOrRecord.type;
  const ctor = typeOrRecord.constructor;
  if (ctor && typeof ctor.type === "string" && ctor.type.length > 0) return ctor.type;
  return "";
}

function resolveBody(typeOrRecord, body) {
  if (typeof typeOrRecord === "string") {
    return body && typeof body === "object" ? body : {};
  }
  if (!typeOrRecord || typeof typeOrRecord !== "object") return {};
  if (typeof typeOrRecord.toJSON === "function") {
    return typeOrRecord.toJSON();
  }
  return typeOrRecord;
}

export class UplinkPoolClient {
  #pool;

  constructor({
    uplinks,
    warmSpareCount = 2,
    clientVersion = "rez-sdk/1.0",
    deviceId = null,
    accountId = null,
    timeouts = {},
    limits = {},
    dedupe = {},
    flood = {},
    wsFactory = null,
    frameCodec = null,
    sessionHello = null,
    accountIdentityPublicKeyB64 = null,
    accountIdentityPrivateKeyB64 = null,
    maxRequestAttempts = 3,
  } = {}) {
    if (!Array.isArray(uplinks) || uplinks.length === 0) {
      throw new Error("UplinkPoolClient requires uplinks[]");
    }

    const eventBus = new TypedEventBus();
    const normalizedDeviceId = deviceId == null ? "" : String(deviceId).trim();
    const authMachine = new AuthStateMachine({
      identity: {
        accountId: accountId == null ? "" : String(accountId),
        deviceId: normalizedDeviceId || makeDeviceId(),
        publicKeyB64: typeof accountIdentityPublicKeyB64 === "string" ? accountIdentityPublicKeyB64.trim() : "",
        privateKeyB64: typeof accountIdentityPrivateKeyB64 === "string" ? accountIdentityPrivateKeyB64.trim() : "",
      },
      eventBus,
      sessionHello: normalizeSessionHello(sessionHello),
      clientVersion,
    });

    const codec = frameCodec || createFrameCodec();
    const maxFrameBytes = Number.isFinite(Number(limits.maxFrameBytes))
      ? Number(limits.maxFrameBytes)
      : 1_000_000;
    const normalizedUplinks = uplinks.map((value) => String(value || "").trim()).filter(Boolean);
    const transportFactory = (url) => new WsTransport({
      url,
      wsFactory,
      frameCodec: codec,
      timeouts,
      maxFrameBytes,
    });

    this.#pool = new UplinkPool({
      uplinks: normalizedUplinks,
      transportFactory,
      authMachine,
      eventBus,
      warmSpareCount,
      timeouts,
      maxRequestAttempts,
      dedupe,
      flood,
    });
  }

  async connect() {
    await this.#pool.connect();
  }

  async close() {
    await this.#pool.close();
  }

  getActiveUplink() {
    return this.#pool.getActiveUplink();
  }

  getUplinkStates() {
    return this.#pool.getUplinkStates();
  }

  getHelloInfo() {
    return this.#pool.getSessionInfo();
  }

  on(type, handler) {
    return this.#pool.on(type, handler);
  }

  onState(handler) {
    return this.#pool.onState(handler);
  }

  async request(typeOrRecord, body = {}) {
    const type = resolveType(typeOrRecord);
    if (!type) {
      throw createError({ code: "BAD_REQUEST", message: "request requires type", retryable: false });
    }
    const requestBody = resolveBody(typeOrRecord, body);
    try {
      const frame = await this.sendRequest({ type, body: requestBody, expectedResponseType: null });
      return frame && frame.body ? frame.body : null;
    } catch (err) {
      if (!err || err.retryable !== true) throw err;
      const code = typeof err.code === "string" ? err.code.trim() : "";
      if (code === "NOT_READY") throw err;
      const continueOnCodes = new Set(RETRYABLE_FAILOVER_CODES);
      if (code) continueOnCodes.add(code);
      const frame = await this.sendRequest({
        type,
        body: requestBody,
        expectedResponseType: null,
        tryAllUplinks: true,
        continueOnCodes,
        adoptSuccessfulUplink: true,
        adoptReason: "request_retryable_error",
        skipActiveUplink: true,
      });
      return frame && frame.body ? frame.body : null;
    }
  }

  async sendRequest(args = {}) {
    return this.#pool.sendRequest(args);
  }
}
