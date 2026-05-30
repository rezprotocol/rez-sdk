import { MemoryStorageProvider } from "@rezprotocol/core";

export function createDefaultStorageProvider() {
  return new MemoryStorageProvider();
}
