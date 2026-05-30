import {
  RService,
  Hash,
  FileChunker,
  FileManifestV1,
  FileChunkV1,
  FileTransferSessionV1,
  bytesToBase64,
  base64ToBytes,
  bytesToHex,
} from "@rezprotocol/core";

export class FileTransferService extends RService {
  static type = "FileTransferService";

  #kvStore;
  #onSendDeposit;
  #onProgress;
  #onFileReceived;
  #sessions = new Map();
  #chunkBuffers = new Map();

  constructor({ log, kvStore, onSendDeposit, onProgress, onFileReceived } = {}) {
    super({ log });
    this.assert(kvStore && typeof kvStore.get === "function", "FileTransferService requires kvStore");
    this.assert(typeof onSendDeposit === "function", "FileTransferService requires onSendDeposit function");
    this.assert(typeof onFileReceived === "function", "FileTransferService requires onFileReceived function");

    this.#kvStore = kvStore;
    this.#onSendDeposit = onSendDeposit;
    this.#onProgress = onProgress || null;
    this.#onFileReceived = onFileReceived;
  }

  async sendFile({ fileBytes, fileName, mimeType, peerAccountId, contextId, text }) {
    this.assert(fileBytes instanceof Uint8Array && fileBytes.length > 0, "sendFile requires non-empty fileBytes");
    this.assert(typeof peerAccountId === "string" && peerAccountId.length > 0, "sendFile requires peerAccountId");
    this.assert(typeof contextId === "string" && contextId.length > 0, "sendFile requires contextId");

    const { manifest, chunks } = FileChunker.chunk(fileBytes, { fileName, mimeType, text: typeof text === "string" ? text : "" });

    // Send manifest first
    await this.#onSendDeposit({
      peerAccountId,
      contextId,
      plaintextBodyBytes: manifest.toBytes(),
    });

    // Send each chunk sequentially
    for (let i = 0; i < chunks.length; i++) {
      await this.#onSendDeposit({
        peerAccountId,
        contextId,
        plaintextBodyBytes: chunks[i].toBytes(),
      });

      if (this.#onProgress) {
        this.#onProgress({
          transferId: manifest.transferId,
          progress: (i + 1) / chunks.length,
          state: i + 1 === chunks.length ? "complete" : "sending",
        });
      }
    }

    // Store completed file content-addressed
    await this.#kvStore.set("file:" + manifest.fileHashHex, bytesToBase64(fileBytes));

    return { transferId: manifest.transferId, manifest };
  }

  async handleIncomingPayload(payload, { senderAccountId, contextId } = {}) {
    // Accept either an already-constructed record OR a raw decoded object
    // (for callers that haven't been migrated to construct-at-boundary).
    if (payload instanceof FileManifestV1) {
      return this.#handleManifest(payload, { senderAccountId, contextId });
    }
    if (payload instanceof FileChunkV1) {
      return this.#handleChunk(payload, { senderAccountId, contextId });
    }
    if (!payload || typeof payload !== "object" || typeof payload.kind !== "string") {
      return false;
    }
    if (payload.kind === "rez.file.manifest.v1") {
      return this.#handleManifest(FileManifestV1.fromJSON(payload), { senderAccountId, contextId });
    }
    if (payload.kind === "rez.file.chunk.v1") {
      return this.#handleChunk(FileChunkV1.fromJSON(payload), { senderAccountId, contextId });
    }
    return false;
  }

  async #handleManifest(manifest, { senderAccountId, contextId }) {
    const now = Date.now();
    const session = new FileTransferSessionV1({
      transferId: manifest.transferId,
      manifest,
      receivedChunks: new Array(manifest.chunkCount).fill(false),
      state: "pending",
      createdAtMs: now,
      updatedAtMs: now,
    });

    this.#sessions.set(manifest.transferId, session);
    this.#chunkBuffers.set(manifest.transferId, new Array(manifest.chunkCount));

    // Persist session for crash recovery
    await this.#kvStore.set("xfer:" + manifest.transferId, JSON.stringify(session.toJSON()));

    if (this.#onProgress) {
      this.#onProgress({
        transferId: manifest.transferId,
        progress: 0,
        state: "pending",
      });
    }

    return true;
  }

  async #handleChunk(chunk, { senderAccountId, contextId }) {
    const session = this.#sessions.get(chunk.transferId);
    if (!session) {
      this.log.error("FileTransferService: chunk for unknown transfer " + chunk.transferId);
      return true; // consumed but orphaned
    }

    // Verify chunk hash
    const rawBytes = base64ToBytes(chunk.dataB64);
    const actualHash = bytesToHex(Hash.sha256(rawBytes));
    if (actualHash !== session.manifest.chunkHashesHex[chunk.chunkIndex]) {
      this.log.error("FileTransferService: chunk " + chunk.chunkIndex + " hash mismatch for " + chunk.transferId);
      return true;
    }

    // Buffer chunk and update session
    const buffer = this.#chunkBuffers.get(chunk.transferId);
    buffer[chunk.chunkIndex] = chunk;

    const updated = session.markChunkReceived(chunk.chunkIndex);
    this.#sessions.set(chunk.transferId, updated);
    await this.#kvStore.set("xfer:" + chunk.transferId, JSON.stringify(updated.toJSON()));

    if (this.#onProgress) {
      this.#onProgress({
        transferId: chunk.transferId,
        progress: updated.progress,
        state: updated.state,
      });
    }

    // Check if complete
    if (updated.isComplete) {
      await this.#completeTransfer(chunk.transferId, updated, { senderAccountId, contextId });
    }

    return true;
  }

  async #completeTransfer(transferId, session, { senderAccountId, contextId }) {
    const buffer = this.#chunkBuffers.get(transferId);
    let fileBytes;
    try {
      fileBytes = FileChunker.reassemble(session.manifest, buffer);
    } catch (err) {
      this.log.error("FileTransferService: reassembly failed for " + transferId, { err });
      const failed = new FileTransferSessionV1({
        transferId: session.transferId,
        manifest: session.manifest,
        receivedChunks: session.receivedChunks,
        state: "failed",
        createdAtMs: session.createdAtMs,
        updatedAtMs: Date.now(),
      });
      this.#sessions.set(transferId, failed);
      await this.#kvStore.set("xfer:" + transferId, JSON.stringify(failed.toJSON()));
      return;
    }

    // Store file content-addressed
    await this.#kvStore.set("file:" + session.manifest.fileHashHex, bytesToBase64(fileBytes));

    // Clean up session
    this.#chunkBuffers.delete(transferId);
    await this.#kvStore.delete("xfer:" + transferId);

    this.#onFileReceived({
      transferId,
      manifest: session.manifest,
      fileBytes,
      senderAccountId,
      contextId,
    });
  }

  async getFile(fileHashHex) {
    const b64 = await this.#kvStore.get("file:" + fileHashHex);
    if (b64 === undefined || b64 === null) return null;
    return base64ToBytes(b64);
  }

  getTransferSession(transferId) {
    return this.#sessions.get(transferId) || null;
  }
}
