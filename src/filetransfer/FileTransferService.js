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
  // Local eager-transfer budget, separate from transport frame sizes. One
  // owner protects sender chunking and receiver allocation until streaming.
  static MAX_FILE_SIZE_BYTES = 64 * 1024 * 1024;
  static MAX_CHUNK_COUNT = 1024;

  #kvStore;
  #onSendDeposit;
  #onProgress;
  #onFileReceived;
  #sessions = new Map();
  #receiveTails = new Map();

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
    this.assert(fileBytes.length <= FileTransferService.MAX_FILE_SIZE_BYTES, "File exceeds the 64 MiB eager-transfer limit");
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
    let record = payload;
    if (!(record instanceof FileManifestV1) && !(record instanceof FileChunkV1)) {
      if (!record || typeof record !== "object") return false;
      if (record.kind === "rez.file.manifest.v1") record = FileManifestV1.fromJSON(record);
      else if (record.kind === "rez.file.chunk.v1") record = FileChunkV1.fromJSON(record);
      else return false;
    }
    this.assert(typeof senderAccountId === "string" && senderAccountId.trim(), "File transfer requires authenticated sender");
    this.assert(typeof contextId === "string" && contextId.trim(), "File transfer requires contextId");
    const id = record.transferId;
    const prior = this.#receiveTails.get(id) || Promise.resolve();
    const pending = prior.then(() => record instanceof FileManifestV1
      ? this.#handleManifest(record, senderAccountId, contextId)
      : this.#handleChunk(record, senderAccountId, contextId));
    // Keep the returned failure visible; only the sequencing tail recovers.
    const tail = pending.then(() => undefined, () => undefined);
    this.#receiveTails.set(id, tail);
    tail.then(() => { if (this.#receiveTails.get(id) === tail) this.#receiveTails.delete(id); });
    return pending;
  }

  #recoveryRequired() {
    const error = new Error("Incomplete file cannot be resumed from this client version; ask the sender to resend it");
    error.code = "FILE_TRANSFER_RECOVERY_REQUIRED";
    return error;
  }

  #assertContext(session, senderAccountId, contextId) {
    if (!session.senderAccountId || !session.contextId) throw this.#recoveryRequired();
    this.assert(session.senderAccountId === senderAccountId && session.contextId === contextId,
      "File transfer sender/context mismatch");
  }

  #chunkKey(transferId, index) {
    return "xfer-chunk:" + transferId + ":" + index;
  }

  #assertBudget(manifest) {
    this.assert(manifest.fileSizeBytes <= FileTransferService.MAX_FILE_SIZE_BYTES
      && manifest.chunkCount <= FileTransferService.MAX_CHUNK_COUNT,
    "File exceeds the eager-transfer byte/chunk limit");
  }

  #validateChunk(chunk, manifest, index) {
    this.assert(chunk instanceof FileChunkV1 && chunk.transferId === manifest.transferId
      && chunk.chunkIndex === index && index >= 0 && index < manifest.chunkCount,
    "File chunk identity/index mismatch");
    const bytes = base64ToBytes(chunk.dataB64);
    const expectedSize = Math.min(manifest.chunkSizeBytes, manifest.fileSizeBytes - index * manifest.chunkSizeBytes);
    this.assert(bytes.length === expectedSize && chunk.hashHex === manifest.chunkHashesHex[index]
      && bytesToHex(Hash.sha256(bytes)) === chunk.hashHex, "File chunk hash/size mismatch");
  }

  async #loadSession(transferId) {
    const cached = this.#sessions.get(transferId);
    if (cached) return cached;
    const raw = await this.#kvStore.get("xfer:" + transferId);
    if (raw === undefined || raw === null) return null;
    let session = FileTransferSessionV1.fromJSON(typeof raw === "string" ? JSON.parse(raw) : raw);
    this.#assertBudget(session.manifest);
    this.assert(session.transferId === transferId, "File transfer storage identity mismatch");
    if (!session.senderAccountId || !session.contextId) throw this.#recoveryRequired();
    const fileBytes = await this.getFile(session.manifest.fileHashHex);
    if (!fileBytes || !session.isComplete) {
      const received = new Array(session.manifest.chunkCount).fill(false);
      for (let index = 0; index < received.length; index++) {
        const stored = await this.#kvStore.get(this.#chunkKey(transferId, index));
        if (stored === undefined || stored === null) {
          if (session.receivedChunks[index]) throw this.#recoveryRequired();
          continue;
        }
        const chunk = FileChunkV1.fromJSON(typeof stored === "string" ? JSON.parse(stored) : stored);
        this.#validateChunk(chunk, session.manifest, index);
        received[index] = true;
      }
      session = new FileTransferSessionV1({
        ...session.toJSON(), manifest: session.manifest, receivedChunks: received,
        // Chunk recovery proves bytes, not that application projection ran.
        state: received.some(Boolean) ? "receiving" : "pending",
      });
      await this.#kvStore.set("xfer:" + transferId, JSON.stringify(session.toJSON()));
    }
    this.#sessions.set(transferId, session);
    return session;
  }

  async #handleManifest(manifest, senderAccountId, contextId) {
    this.#assertBudget(manifest);
    let session = await this.#loadSession(manifest.transferId);
    if (session) {
      this.#assertContext(session, senderAccountId, contextId);
      this.assert(JSON.stringify(session.manifest.toJSON()) === JSON.stringify(manifest.toJSON()),
        "File transfer manifest changed for an existing transfer");
      if (session.state === "complete") {
        const bytes = await this.getFile(session.manifest.fileHashHex);
        if (!bytes || bytes.length !== manifest.fileSizeBytes) throw this.#recoveryRequired();
        await this.#deleteChunks(session);
        return true;
      }
      if (session.isComplete) await this.#completeTransfer(session);
      return true;
    }
    const now = Date.now();
    session = new FileTransferSessionV1({
      transferId: manifest.transferId, manifest,
      receivedChunks: new Array(manifest.chunkCount).fill(false), state: "pending",
      createdAtMs: now, updatedAtMs: now, senderAccountId, contextId,
    });
    await this.#kvStore.set("xfer:" + manifest.transferId, JSON.stringify(session.toJSON()));
    this.#sessions.set(manifest.transferId, session);
    if (this.#onProgress) this.#onProgress({ transferId: manifest.transferId, progress: 0, state: "pending" });
    return true;
  }

  async #handleChunk(chunk, senderAccountId, contextId) {
    const session = await this.#loadSession(chunk.transferId);
    if (!session) throw this.#recoveryRequired();
    this.#assertContext(session, senderAccountId, contextId);
    this.#validateChunk(chunk, session.manifest, chunk.chunkIndex);
    if (session.state === "complete") {
      const bytes = await this.getFile(session.manifest.fileHashHex);
      if (!bytes || bytes.length !== session.manifest.fileSizeBytes) throw this.#recoveryRequired();
      await this.#deleteChunks(session);
      return true;
    }
    // Persist bytes BEFORE the receipt bitmap or application acknowledgement.
    // If the bitmap write fails, reload reconciles from verified chunk records.
    try {
      await this.#kvStore.set(this.#chunkKey(chunk.transferId, chunk.chunkIndex), JSON.stringify(chunk.toJSON()));
      const received = session.markChunkReceived(chunk.chunkIndex);
      // All bytes may exist before the application projection commits. Keep
      // this retryable until the awaited completion callback succeeds.
      const updated = received.isComplete
        ? new FileTransferSessionV1({ ...received.toJSON(), manifest: received.manifest, state: "receiving" })
        : received;
      await this.#kvStore.set("xfer:" + chunk.transferId, JSON.stringify(updated.toJSON()));
      this.#sessions.set(chunk.transferId, updated);
      if (this.#onProgress) this.#onProgress({ transferId: chunk.transferId, progress: updated.progress, state: updated.state });
      if (updated.isComplete) await this.#completeTransfer(updated);
    } catch (error) {
      this.#sessions.delete(chunk.transferId);
      throw error;
    }
    return true;
  }

  async #completeTransfer(session) {
    let fileBytes = await this.getFile(session.manifest.fileHashHex);
    if (fileBytes) this.assert(fileBytes.length === session.manifest.fileSizeBytes, "Stored file size mismatch");
    if (!fileBytes) {
      const chunks = [];
      for (let index = 0; index < session.manifest.chunkCount; index++) {
        const raw = await this.#kvStore.get(this.#chunkKey(session.transferId, index));
        if (raw === undefined || raw === null) throw this.#recoveryRequired();
        const chunk = FileChunkV1.fromJSON(typeof raw === "string" ? JSON.parse(raw) : raw);
        this.#validateChunk(chunk, session.manifest, index);
        chunks.push(chunk);
      }
      fileBytes = FileChunker.reassemble(session.manifest, chunks);
      await this.#kvStore.set("file:" + session.manifest.fileHashHex, bytesToBase64(fileBytes));
    }
    // Projection is part of apply, not a fire-and-forget notification. Keep
    // recovery records if it fails; replay uses the verified complete file.
    await this.#onFileReceived({
      transferId: session.transferId, manifest: session.manifest, fileBytes,
      senderAccountId: session.senderAccountId, contextId: session.contextId,
    });
    const completed = new FileTransferSessionV1({ ...session.toJSON(), manifest: session.manifest, state: "complete", updatedAtMs: Date.now() });
    await this.#kvStore.set("xfer:" + session.transferId, JSON.stringify(completed.toJSON()));
    this.#sessions.set(session.transferId, completed);
    await this.#deleteChunks(session);
    // Retain the small bound session for authenticated, idempotent replay.
  }

  async #deleteChunks(session) {
    for (let index = 0; index < session.manifest.chunkCount; index++) {
      await this.#kvStore.delete(this.#chunkKey(session.transferId, index));
    }
  }

  async getFile(fileHashHex) {
    const b64 = await this.#kvStore.get("file:" + fileHashHex);
    if (b64 === undefined || b64 === null) return null;
    const bytes = base64ToBytes(b64);
    this.assert(bytesToHex(Hash.sha256(bytes)) === fileHashHex, "Stored file hash mismatch");
    return bytes;
  }

  getTransferSession(transferId) {
    return this.#sessions.get(transferId) || null;
  }
}
