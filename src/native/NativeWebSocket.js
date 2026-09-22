import { RRecord } from "@rezprotocol/core";
import { NativePrimitiveRequestV1 } from "./NativePrimitiveRecords.js";

class NativeSocketEventV1 extends RRecord {
  static type = "sdk.native.socket.event.v1";
  constructor(event, data, code) { super(); this.event = event; this.data = data; this.code = code; this.message = event === "error" ? data : ""; this._seal(); }
  validate() { this.assert(["open", "message", "error", "close"].includes(this.event), "invalid socket event"); }
}

export class NativeSocketFactory {
  #client;
  #sockets = new Map();
  constructor(client) { this.#client = client; }
  create(url) {
    const id = this.#client.call(new NativePrimitiveRequestV1("network.open", [url]))[0];
    const socket = new NativeWebSocket(this.#client, id);
    this.#sockets.set(id, socket);
    return socket;
  }
  dispatch(id, kind, data, code) {
    const socket = this.#sockets.get(id);
    if (!socket) return;
    if (kind === "binary") {
      const raw = this.#client.call(new NativePrimitiveRequestV1("bytes.base64Decode", [data]))[0];
      data = Uint8Array.from(JSON.parse(raw)).buffer;
      kind = "message";
    }
    socket.dispatch(new NativeSocketEventV1(kind, data, code));
    if (kind === "close") this.#sockets.delete(id);
  }
}

class NativeWebSocket {
  #client;
  #id;
  #state = 0;
  #handlers = new Map();
  constructor(client, id) { this.#client = client; this.#id = id; }
  get readyState() { return this.#state; }
  addEventListener(event, handler) {
    if (!this.#handlers.has(event)) this.#handlers.set(event, new Set());
    this.#handlers.get(event).add(handler);
  }
  removeEventListener(event, handler) { const handlers = this.#handlers.get(event); if (handlers) handlers.delete(handler); }
  dispatch(event) {
    if (!(event instanceof NativeSocketEventV1)) throw new Error("Socket event record required");
    if (event.event === "open") this.#state = 1;
    if (event.event === "close") this.#state = 3;
    const handlers = this.#handlers.get(event.event);
    if (handlers) for (const handler of Array.from(handlers)) handler(event);
  }
  send(text) {
    if (this.#state !== 1) throw new Error("Native socket is not open");
    if (typeof text !== "string") throw new Error("Rez native transport requires text frames");
    this.#client.call(new NativePrimitiveRequestV1("network.send", [this.#id, text]));
  }
  close() {
    if (this.#state >= 2) return;
    this.#client.call(new NativePrimitiveRequestV1("network.close", [this.#id]));
    this.#state = 2;
  }
}
