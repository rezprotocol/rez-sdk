import { RezRuntime } from "@rezprotocol/core";
import { createDefaultCodecChain } from "../defaults/createDefaultCodecChain.js";
import { createDefaultLogger } from "../defaults/createDefaultLogger.js";
import { createDefaultStorageProvider } from "../defaults/createDefaultStorageProvider.js";

export class RezRuntimeBuilder {
  constructor() {
    this.codecChain = null;
    this.logger = null;
    this.storageProvider = null;
  }

  withCodecChain(chain) {
    this.codecChain = chain;
    return this;
  }

  withLogger(logger) {
    this.logger = logger;
    return this;
  }

  withStorageProvider(storageProvider) {
    this.storageProvider = storageProvider;
    return this;
  }

  build() {
    const codecChain = this.codecChain || createDefaultCodecChain();
    const logger = this.logger || createDefaultLogger();
    const storageProvider = this.storageProvider || createDefaultStorageProvider();

    return new RezRuntime({ codecChain, logger, storageProvider });
  }
}
