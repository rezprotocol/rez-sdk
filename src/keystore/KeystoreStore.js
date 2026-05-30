import { KeystoreStore as CoreKeystoreStore } from "@rezprotocol/core";
import { IndexedDbStorageProvider } from "../storage/IndexedDbStorageProvider.js";

const DEFAULT_KEY = "default";

function hasIndexedDb() {
  return !!(globalThis.indexedDB && typeof globalThis.indexedDB.open === "function");
}

function resolveStorageProvider(storageProvider) {
  if (storageProvider && typeof storageProvider === "object") return storageProvider;
  if (hasIndexedDb()) return new IndexedDbStorageProvider();
  throw new Error("KeystoreStore requires storageProvider when IndexedDB is unavailable");
}

/**
 * SDK KeystoreStore: uses core store with optional default to IndexedDB when no storage provided.
 */
export class KeystoreStore extends CoreKeystoreStore {
  constructor({ storageProvider = null, storage = null, key = DEFAULT_KEY } = {}) {
    const provider = resolveStorageProvider(storageProvider || storage);
    super({ storageProvider: provider, key });
  }
}
