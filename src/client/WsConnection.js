import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";
import { TypedEventBus } from "../events/TypedEventBus.js";
import { AuthStateMachine } from "../auth/AuthStateMachine.js";
import { WsTransport } from "../transport/WsTransport.js";
import { createFrameCodec } from "../transport/FrameCodec.js";

function createError(code, message, retryable) {
  const err = new Error(message || code || "WS_ERR");
  err.code = code || "WS_ERR";
  err.retryable = retryable === true;
  return err;
}

export class WsConnection {
  #wsUrl;
  #transport;
  #sessionHello;
  #accountIdentityPublicKeyB64;
  #accountIdentityPrivateKeyB64;
  #clientVersion;
  #expectedNodePublicKeyB64;
  #sessionInfo = null;
  #stateHandlers = new Map();

  constructor({
    wsUrl,
    timeouts = {},
    maxFrameBytes = 1_000_000,
    wsFactory = null,
    frameCodec = null,
    sessionHello = null,
    accountIdentityPublicKeyB64 = null,
    accountIdentityPrivateKeyB64 = null,
    clientVersion = "rez-sdk/1.0",
    expectedNodePublicKeyB64 = "",
  } = {}) {
    if (typeof wsUrl !== "string" || wsUrl.trim().length === 0) {
      throw new Error("WsConnection requires wsUrl");
    }
    this.#wsUrl = wsUrl;
    this.#sessionHello = sessionHello && typeof sessionHello === "object" ? sessionHello : {};
    this.#accountIdentityPublicKeyB64 =
      typeof accountIdentityPublicKeyB64 === "string" ? accountIdentityPublicKeyB64.trim() : "";
    this.#accountIdentityPrivateKeyB64 =
      typeof accountIdentityPrivateKeyB64 === "string" ? accountIdentityPrivateKeyB64.trim() : "";
    this.#clientVersion = String(clientVersion || "rez-sdk/1.0");
    this.#expectedNodePublicKeyB64 =
      typeof expectedNodePublicKeyB64 === "string" ? expectedNodePublicKeyB64.trim() : "";
    this.#transport = new WsTransport({
      url: wsUrl,
      wsFactory,
      frameCodec: frameCodec || createFrameCodec(),
      timeouts,
      maxFrameBytes,
    });
  }

  async connectAndHello({ deviceId = null, accountId = null } = {}) {
    const authMachine = new AuthStateMachine({
      identity: {
        accountId: accountId == null ? "" : String(accountId),
        deviceId: deviceId == null ? "" : String(deviceId),
        publicKeyB64: this.#accountIdentityPublicKeyB64,
        privateKeyB64: this.#accountIdentityPrivateKeyB64,
      },
      eventBus: new TypedEventBus(),
      sessionHello: this.#sessionHello,
      clientVersion: this.#clientVersion,
      expectedNodePublicKeyB64: this.#expectedNodePublicKeyB64,
    });
    await this.#transport.connect();
    this.#sessionInfo = await authMachine.authenticate(this.#transport);
    return this.getHelloOk();
  }

  async close() {
    this.#sessionInfo = null;
    await this.#transport.close();
  }

  onFrame(handler) {
    return this.#transport.onFrame(handler);
  }

  onState(handler) {
    if (typeof handler !== "function") throw new Error("onState requires handler");
    const wrapped = (state) => {
      if (!state || typeof state !== "object") {
        handler(state);
        return;
      }
      const payload = { ...state };
      if (Object.prototype.hasOwnProperty.call(payload, "url")) {
        payload.wsUrl = payload.url;
        delete payload.url;
      }
      handler(payload);
    };
    const off = this.#transport.onState(wrapped);
    this.#stateHandlers.set(handler, off);
    return () => {
      const cleanup = this.#stateHandlers.get(handler);
      if (cleanup) cleanup();
      this.#stateHandlers.delete(handler);
    };
  }

  isReady() {
    return this.#transport.isConnected() && !!this.#sessionInfo;
  }

  getHelloOk() {
    return this.#sessionInfo ? { ...this.#sessionInfo } : null;
  }

  async sendRequest({
    type,
    body = {},
    expectedResponseType = null,
    timeoutMs = null,
    allowBeforeHello = false,
  } = {}) {
    const helloType = String(this.#sessionHello.requestType || REZ_CONTRACT_TYPES.SESSION_HELLO);
    const frameType = String(type || "").trim();
    if (!frameType) {
      throw createError("BAD_REQUEST", "type required", false);
    }
    if (!allowBeforeHello && !this.#sessionInfo && frameType !== helloType) {
      throw createError("NOT_READY", "session hello required", true);
    }
    return this.#transport.sendRequest({
      type: frameType,
      body,
      expectedResponseType,
      timeoutMs,
    });
  }
}
