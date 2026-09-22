import { NativePrimitiveClient, NativePrimitiveRequestV1 } from "./NativePrimitiveRecords.js";
import { NativeWebCrypto } from "./NativeWebCrypto.js";
import { NativeSocketFactory } from "./NativeWebSocket.js";

// Install only the platform API subset consumed by the SDK. Unsupported
// operations fail explicitly instead of imitating a complete browser.
export function installNativePlatform(invoke) {
  const client = new NativePrimitiveClient(invoke);
  const subtle = new NativeWebCrypto(client);
  const sockets = new NativeSocketFactory(client);
  globalThis.crypto = new NativeCryptoPlatform(subtle);
  globalThis.btoa = (value) => {
    const bytes = Array.from(String(value), (char) => char.charCodeAt(0));
    if (bytes.some((byte) => byte > 255)) throw new Error("btoa requires Latin-1 input");
    return client.call(new NativePrimitiveRequestV1("bytes.base64Encode", [JSON.stringify(bytes)]))[0];
  };
  globalThis.atob = (value) => {
    const bytes = JSON.parse(client.call(new NativePrimitiveRequestV1("bytes.base64Decode", [String(value)]))[0]);
    return bytes.map((byte) => String.fromCharCode(byte)).join("");
  };
  globalThis.__rezNetworkEvent = (id, event, data, code) => sockets.dispatch(id, event, data, code);
  globalThis.WebSocket = class { constructor(url) { return sockets.create(url); } };
  globalThis.URL = class {
    #parts;
    constructor(input, base = "") {
      this.#parts = client.call(new NativePrimitiveRequestV1("url.parse", [String(input), String(base)]));
    }
    get href() { return this.#parts[0]; }
    get protocol() { return this.#parts[1]; }
    get hostname() { return this.#parts[2]; }
    get port() { return this.#parts[3]; }
    get pathname() { return this.#parts[4]; }
    get search() { return this.#parts[5]; }
    get hash() { return this.#parts[6]; }
    get username() { return this.#parts[7]; }
    get password() { return this.#parts[8]; }
    get host() { return this.hostname + (this.port ? ":" + this.port : ""); }
    get origin() { return this.protocol + "//" + this.host; }
    toString() { return this.href; }
  };
  return client;
}

class NativeCryptoPlatform {
  #subtle;
  constructor(subtle) { this.#subtle = subtle; }
  get subtle() { return this.#subtle; }
  getRandomValues(array) { return this.#subtle.getRandomValues(array); }
  randomUUID() {
    const bytes = this.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    const hex = Array.from(bytes, (v) => v.toString(16).padStart(2, "0")).join("");
    return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join("-");
  }
}
