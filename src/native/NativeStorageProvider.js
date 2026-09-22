import { KeyValueStore, KeyValueUnreadableError, RRecord } from "@rezprotocol/core";
import { createKeyValueBackedPeerLinkStorage } from "../peer-link/createKeyValueBackedPeerLinkStorage.js";
import { NativePrimitiveClient, NativePrimitiveRequestV1 } from "./NativePrimitiveRecords.js";

class NativeOwnershipGrant extends RRecord {
  static type = "sdk.native.ownershipGrant.v1";
  #client;
  #token;
  #released = false;
  constructor(client, epoch, token) {
    super();
    this.#client = client;
    this.#token = token;
    this.runtimeEpoch = epoch;
    this._seal();
  }
  validate() { this.assert(Number.isSafeInteger(this.runtimeEpoch) && this.runtimeEpoch > 0, "invalid runtime epoch"); }
  assertActive() {
    if (this.#released) {
      const err = new Error("native delivery ownership released");
      err.code = "DELIVERY_RUNTIME_FENCED";
      throw err;
    }
    this.#client.call(new NativePrimitiveRequestV1("storage.assertOwner", [this.#token]));
  }
  async release() {
    if (this.#released) return;
    this.#client.call(new NativePrimitiveRequestV1("storage.releaseOwner", [this.#token]));
    this.#released = true;
  }
}

class NativeKeyValueStore extends KeyValueStore {
  #client;
  #scope;
  constructor(client, scope) { super(); this.#client = client; this.#scope = scope; }
  #call(method, ...args) { return this.#client.call(new NativePrimitiveRequestV1("storage." + method, [this.#scope, ...args])); }
  async get(key) { return this.getStrict(key); }
  async getStrict(key) {
    try {
      const result = this.#call("get", key);
      if (result.length !== 2 || typeof result[0] !== "boolean" || typeof result[1] !== "string") {
        throw new Error("Invalid native storage read result");
      }
      return result[0] ? JSON.parse(result[1]) : undefined;
    } catch (cause) {
      throw new KeyValueUnreadableError({ key, cause });
    }
  }
  async set(key, value) {
    const json = JSON.stringify(value);
    if (json === undefined) throw new Error("native storage requires a serializable value");
    this.#call("set", key, json);
  }
  async delete(key) { return this.#call("delete", key)[0]; }
  async keys(prefix = "") { return this.#call("keys", prefix); }
}

// Native owns encrypted SQLite transactions and a process-wide OS lock. The
// SDK owns peer-link records, commit replay, and all owner partition semantics.
export class NativeStorageProvider {
  #client;
  #stores = new Map();
  #peers = new Map();
  constructor(client) {
    if (!(client instanceof NativePrimitiveClient)) throw new Error("NativeStorageProvider requires NativePrimitiveClient");
    this.#client = client;
  }
  async get(key) {
    const value = await this.getKeyValueStore().getStrict(key);
    return value === undefined ? null : value;
  }
  async put(key, value) {
    await this.getKeyValueStore().set(key, value);
    return value;
  }
  async del(key) {
    return this.getKeyValueStore().delete(key);
  }
  async listKeys() {
    return this.getKeyValueStore().keys();
  }
  getKeyValueStore(ownerAccountId = null) {
    const scope = ownerAccountId === null ? "" : ownerAccountId;
    if (typeof scope !== "string") throw new TypeError("native storage owner must be a string");
    if (!this.#stores.has(scope)) this.#stores.set(scope, new NativeKeyValueStore(this.#client, scope));
    return this.#stores.get(scope);
  }
  getPeerLinkStorage(ownerAccountId = null) {
    if (!this.#peers.has(ownerAccountId)) this.#peers.set(ownerAccountId, createKeyValueBackedPeerLinkStorage({ keyValueStore: this.getKeyValueStore(ownerAccountId) }));
    return this.#peers.get(ownerAccountId);
  }
  async acquireRuntimeOwnership({ namespace = "sdk-delivery" } = {}) {
    const result = this.#client.call(new NativePrimitiveRequestV1("storage.acquireOwner", [namespace]));
    return new NativeOwnershipGrant(this.#client, result[0], result[1]);
  }
  partition(...scopeParts) {
    if (scopeParts.length === 0 || !scopeParts.every((part) => typeof part === "string" && part.length > 0)) {
      throw new TypeError("native storage partition requires non-empty string parts");
    }
    return new NativeStoragePartition(this, scopeParts);
  }
}

class NativeStoragePartition {
  #provider;
  #scopeParts;
  #peers = new Map();
  constructor(provider, scopeParts) {
    this.#provider = provider;
    this.#scopeParts = scopeParts.slice();
  }
  getKeyValueStore(ownerAccountId = null) {
    return this.#provider.getKeyValueStore(JSON.stringify([...this.#scopeParts, ownerAccountId]));
  }
  getPeerLinkStorage(ownerAccountId = null) {
    if (!this.#peers.has(ownerAccountId)) {
      this.#peers.set(ownerAccountId, createKeyValueBackedPeerLinkStorage({
        keyValueStore: this.getKeyValueStore(ownerAccountId),
      }));
    }
    return this.#peers.get(ownerAccountId);
  }
  acquireRuntimeOwnership(options) {
    return this.#provider.acquireRuntimeOwnership(options);
  }
}
