import test from "node:test";
import assert from "node:assert/strict";

import { IndexedDbStorageProvider } from "../src/storage/IndexedDbStorageProvider.js";
import { KeystoreStore } from "../src/keystore/KeystoreStore.js";
import { createKeystoreEnvelope, randomBytes, toBase64 } from "../src/keystore/index.js";

function createRequest(resultFn, tx = null) {
  const request = {
    result: undefined,
    error: null,
    onsuccess: null,
    onerror: null,
  };
  queueMicrotask(() => {
    try {
      request.result = resultFn();
      if (typeof request.onsuccess === "function") request.onsuccess({ target: request });
      if (tx && typeof tx.oncomplete === "function") {
        queueMicrotask(() => tx.oncomplete({ target: tx }));
      }
    } catch (err) {
      request.error = err;
      if (typeof request.onerror === "function") request.onerror({ target: request });
      if (tx) {
        tx.error = err;
        if (typeof tx.onerror === "function") tx.onerror({ target: tx });
      }
    }
  });
  return request;
}

function createFakeIndexedDb() {
  const dbMap = new Map();

  function createDbRecord(name) {
    if (!dbMap.has(name)) {
      dbMap.set(name, {
        stores: new Map(),
      });
    }
    return dbMap.get(name);
  }

  return {
    open(name) {
      const dbRecord = createDbRecord(String(name || ""));
      const request = {
        result: null,
        error: null,
        onsuccess: null,
        onerror: null,
        onupgradeneeded: null,
      };

      queueMicrotask(() => {
        const db = {
          objectStoreNames: {
            contains(storeName) {
              return dbRecord.stores.has(String(storeName || ""));
            },
          },
          createObjectStore(storeName) {
            const normalized = String(storeName || "");
            if (!dbRecord.stores.has(normalized)) dbRecord.stores.set(normalized, new Map());
            return {};
          },
          transaction(storeName) {
            const normalized = String(storeName || "");
            if (!dbRecord.stores.has(normalized)) dbRecord.stores.set(normalized, new Map());
            const store = dbRecord.stores.get(normalized);
            const tx = {
              error: null,
              oncomplete: null,
              onerror: null,
              onabort: null,
              objectStore() {
                return {
                  get(key) {
                    const normalizedKey = String(key || "");
                    return createRequest(() => (
                      store.has(normalizedKey)
                        ? JSON.parse(JSON.stringify(store.get(normalizedKey)))
                        : undefined
                    ), tx);
                  },
                  put(value, key) {
                    const normalizedKey = String(key || "");
                    return createRequest(() => {
                      store.set(normalizedKey, JSON.parse(JSON.stringify(value)));
                      return normalizedKey;
                    }, tx);
                  },
                  delete(key) {
                    const normalizedKey = String(key || "");
                    return createRequest(() => {
                      store.delete(normalizedKey);
                      return undefined;
                    }, tx);
                  },
                };
              },
            };
            return tx;
          },
        };

        request.result = db;
        if (typeof request.onupgradeneeded === "function") request.onupgradeneeded({ target: request });
        if (typeof request.onsuccess === "function") request.onsuccess({ target: request });
      });

      return request;
    },
  };
}

test("IndexedDbStorageProvider put/get round-trip and del removes key", async () => {
  const prev = globalThis.indexedDB;
  globalThis.indexedDB = createFakeIndexedDb();
  try {
    const provider = new IndexedDbStorageProvider();
    await provider.put("default", { ok: true, value: 42 });
    const found = await provider.get("default");
    assert.deepEqual(found, { ok: true, value: 42 });
    await provider.del("default");
    const missing = await provider.get("default");
    assert.equal(missing, null);
  } finally {
    globalThis.indexedDB = prev;
  }
});

test("KeystoreStore default uses IndexedDB provider and persists envelope shape", async () => {
  const prev = globalThis.indexedDB;
  globalThis.indexedDB = createFakeIndexedDb();
  try {
    const store = new KeystoreStore();
    const now = Date.now();
    const envelope = createKeystoreEnvelope({
      kdfParams: { type: "pbkdf2-sha256", iterations: 210000, keyLength: 32 },
      saltB64: toBase64(randomBytes(16, globalThis.crypto)),
      ciphertextB64: toBase64(randomBytes(64, globalThis.crypto)),
      createdAtMs: now,
      updatedAtMs: now,
    });
    await store.putKeystoreEnvelope(envelope);
    const saved = await store.getKeystoreEnvelope();
    assert.deepEqual(saved, envelope);
  } finally {
    globalThis.indexedDB = prev;
  }
});
