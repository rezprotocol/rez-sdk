const DEFAULT_DB_NAME = "rez";
const DEFAULT_STORE_NAME = "keystore";

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
  constructor({ dbName = DEFAULT_DB_NAME, storeName = DEFAULT_STORE_NAME } = {}) {
    this._dbName = String(dbName || DEFAULT_DB_NAME);
    this._storeName = String(storeName || DEFAULT_STORE_NAME);
    this._dbPromise = null;
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
}
