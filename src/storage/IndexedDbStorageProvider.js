import { KeyValueStore, RRecord, base64ToBytes, bytesToBase64 } from "@rezprotocol/core";
import { createKeyValueBackedPeerLinkStorage } from "../peer-link/createKeyValueBackedPeerLinkStorage.js";

const DEFAULT_DB_NAME = "rez";
const DEFAULT_STORE_NAME = "keystore";
const ENCRYPTED_VALUE_VERSION = 1;

class IndexedDbEncryptedValueV1 extends RRecord {
  static type = "sdk.storage.indexeddb.encryptedValue.v1";

  constructor({ nonceB64 = "", ciphertextB64 = "" } = {}) {
    super();
    this.version = ENCRYPTED_VALUE_VERSION;
    this.nonceB64 = String(nonceB64 || "");
    this.ciphertextB64 = String(ciphertextB64 || "");
    this._seal();
  }

  validate() {
    this.assert(this.version === ENCRYPTED_VALUE_VERSION, "version must be 1");
    this.assert(this.nonceB64.length > 0, "nonceB64 is required");
    this.assert(this.ciphertextB64.length > 0, "ciphertextB64 is required");
  }
}

function cloneJson(value) {
  if (value == null) return null;
  return JSON.parse(JSON.stringify(value));
}

function resolveIndexedDb() {
  const idb = globalThis.indexedDB;
  if (!idb || typeof idb.open !== "function") {
    throw new Error("IndexedDB is not available in this runtime");
  }
  return idb;
}

export class IndexedDbStorageProvider {
  constructor({
    dbName = DEFAULT_DB_NAME,
    storeName = DEFAULT_STORE_NAME,
    encryptionKey = null,
    cryptoProvider = null,
  } = {}) {
    this._dbName = String(dbName || DEFAULT_DB_NAME);
    this._storeName = String(storeName || DEFAULT_STORE_NAME);
    this._dbPromise = null;
    this._encryptionKey = encryptionKey instanceof Uint8Array ? new Uint8Array(encryptionKey) : null;
    this._cryptoProvider = cryptoProvider;
    this._keyValueStores = new Map();
    this._peerLinkStores = new Map();
    if ((this._encryptionKey && !this._cryptoProvider) || (!this._encryptionKey && this._cryptoProvider)) {
      throw new Error("IndexedDbStorageProvider encryptionKey and cryptoProvider must be provided together");
    }
    if (this._encryptionKey && this._encryptionKey.length !== 32) {
      throw new Error("IndexedDbStorageProvider encryptionKey must be 32 bytes");
    }
  }

  getDbName() {
    return this._dbName;
  }

  getStoreName() {
    return this._storeName;
  }

  async _openDb() {
    if (this._dbPromise) return this._dbPromise;

    this._dbPromise = new Promise((resolve, reject) => {
      const indexedDB = resolveIndexedDb();
      const request = indexedDB.open(this._dbName, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(this._storeName)) {
          db.createObjectStore(this._storeName);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("IndexedDB open failed"));
    });

    return this._dbPromise;
  }

  async get(key) {
    const db = await this._openDb();
    const normalizedKey = String(key || "");
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this._storeName, "readonly");
      const store = tx.objectStore(this._storeName);
      const request = store.get(normalizedKey);
      request.onsuccess = () => resolve(cloneJson(request.result ?? null));
      request.onerror = () => reject(request.error || new Error("IndexedDB get failed"));
      tx.onabort = () => reject(tx.error || new Error("IndexedDB get transaction aborted"));
      tx.onerror = () => reject(tx.error || new Error("IndexedDB get transaction failed"));
    });
  }

  async put(key, value) {
    const db = await this._openDb();
    const normalizedKey = String(key || "");
    const payload = cloneJson(value);
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this._storeName, "readwrite");
      const store = tx.objectStore(this._storeName);
      const request = store.put(payload, normalizedKey);
      request.onsuccess = () => resolve(payload);
      request.onerror = () => reject(request.error || new Error("IndexedDB put failed"));
      tx.onabort = () => reject(tx.error || new Error("IndexedDB put transaction aborted"));
      tx.onerror = () => reject(tx.error || new Error("IndexedDB put transaction failed"));
    });
  }

  async del(key) {
    const db = await this._openDb();
    const normalizedKey = String(key || "");
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this._storeName, "readwrite");
      const store = tx.objectStore(this._storeName);
      const request = store.delete(normalizedKey);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error || new Error("IndexedDB delete failed"));
      tx.onabort = () => reject(tx.error || new Error("IndexedDB delete transaction aborted"));
      tx.onerror = () => reject(tx.error || new Error("IndexedDB delete transaction failed"));
    });
  }

  async listKeys() {
    const db = await this._openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this._storeName, "readonly");
      const store = tx.objectStore(this._storeName);
      const request = store.getAllKeys();
      request.onsuccess = () => {
        const rows = Array.isArray(request.result) ? request.result : [];
        resolve(rows.map((value) => String(value || "")).filter((value) => value.length > 0).sort());
      };
      request.onerror = () => reject(request.error || new Error("IndexedDB listKeys failed"));
      tx.onabort = () => reject(tx.error || new Error("IndexedDB listKeys transaction aborted"));
      tx.onerror = () => reject(tx.error || new Error("IndexedDB listKeys transaction failed"));
    });
  }

  async clear() {
    const db = await this._openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this._storeName, "readwrite");
      const store = tx.objectStore(this._storeName);
      const request = store.clear();
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error || new Error("IndexedDB clear failed"));
      tx.onabort = () => reject(tx.error || new Error("IndexedDB clear transaction aborted"));
      tx.onerror = () => reject(tx.error || new Error("IndexedDB clear transaction failed"));
    });
  }

  getKeyValueStore(ownerAccountId = null) {
    const owner = ownerAccountId === null ? "" : String(ownerAccountId || "").trim();
    const cacheKey = owner || "<root>";
    let store = this._keyValueStores.get(cacheKey);
    if (!store) {
      store = new IndexedDbKeyValueStore({
        provider: this,
        ownerAccountId: owner,
        encryptionKey: this._encryptionKey,
        cryptoProvider: this._cryptoProvider,
      });
      this._keyValueStores.set(cacheKey, store);
    }
    return store;
  }

  getPeerLinkStorage(ownerAccountId = null) {
    const owner = ownerAccountId === null ? "" : String(ownerAccountId || "").trim();
    const cacheKey = owner || "<root>";
    let storage = this._peerLinkStores.get(cacheKey);
    if (!storage) {
      storage = createKeyValueBackedPeerLinkStorage({
        keyValueStore: this.getKeyValueStore(owner),
      });
      this._peerLinkStores.set(cacheKey, storage);
    }
    return storage;
  }
}

class IndexedDbKeyValueStore extends KeyValueStore {
  #provider;
  #prefix;
  #encryptionKey;
  #cryptoProvider;

  constructor({ provider, ownerAccountId, encryptionKey, cryptoProvider } = {}) {
    super();
    this.#provider = provider;
    const partition = ownerAccountId ? encodeURIComponent(ownerAccountId) : "root";
    this.#prefix = "kv/" + partition + "/";
    this.#encryptionKey = encryptionKey;
    this.#cryptoProvider = cryptoProvider;
  }

  async set(key, value) {
    const physicalKey = this.#physicalKey(key);
    const stored = this.#encryptionKey
      ? await this.#encrypt(physicalKey, value)
      : value;
    await this.#provider.put(physicalKey, stored);
  }

  async get(key) {
    const physicalKey = this.#physicalKey(key);
    const stored = await this.#provider.get(physicalKey);
    if (stored === null) return undefined;
    if (!this.#encryptionKey) return stored;
    return this.#decrypt(physicalKey, stored);
  }

  async delete(key) {
    const physicalKey = this.#physicalKey(key);
    const existed = await this.#provider.get(physicalKey) !== null;
    await this.#provider.del(physicalKey);
    return existed;
  }

  async keys(prefix = "") {
    const physicalPrefix = this.#prefix + String(prefix || "");
    const keys = await this.#provider.listKeys();
    return keys
      .filter((key) => key.startsWith(physicalPrefix))
      .map((key) => key.slice(this.#prefix.length));
  }

  #physicalKey(key) {
    return this.#prefix + String(key || "");
  }

  async #encrypt(physicalKey, value) {
    const plaintext = new TextEncoder().encode(JSON.stringify(value));
    const nonce = this.#cryptoProvider.randomBytes(12);
    const ciphertext = await this.#cryptoProvider.aeadEncrypt({
      key: this.#encryptionKey,
      nonce,
      plaintext,
      aad: new TextEncoder().encode(physicalKey),
    });
    const record = new IndexedDbEncryptedValueV1({
      nonceB64: bytesToBase64(nonce),
      ciphertextB64: bytesToBase64(ciphertext),
    });
    record.validate();
    return record.toJSON();
  }

  async #decrypt(physicalKey, stored) {
    let record;
    try {
      record = new IndexedDbEncryptedValueV1({
        nonceB64: stored && stored.nonceB64,
        ciphertextB64: stored && stored.ciphertextB64,
      });
      record.validate();
    } catch (err) {
      throw new Error("IndexedDbStorageProvider encrypted value is malformed: " + (err && err.message ? err.message : err));
    }
    const plaintext = await this.#cryptoProvider.aeadDecrypt({
      key: this.#encryptionKey,
      nonce: base64ToBytes(record.nonceB64),
      ciphertext: base64ToBytes(record.ciphertextB64),
      aad: new TextEncoder().encode(physicalKey),
    });
    return JSON.parse(new TextDecoder().decode(plaintext));
  }
}
