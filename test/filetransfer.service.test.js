import test from "node:test";
import assert from "node:assert/strict";

import {
  MemoryKeyValueStore,
  FileChunker,
  FileManifestV1,
  FileChunkV1,
  bytesToHex,
  Hash,
} from "@rezprotocol/core";
import { FileTransferService } from "../src/filetransfer/FileTransferService.js";

function makeBytes(len) {
  const b = new Uint8Array(len);
  for (let i = 0; i < len; i++) b[i] = i % 256;
  return b;
}

function createService({ onSendDeposit, onProgress, onFileReceived } = {}) {
  const kvStore = new MemoryKeyValueStore();
  const deposits = [];
  const progressEvents = [];
  const receivedFiles = [];

  const svc = new FileTransferService({
    kvStore,
    onSendDeposit: onSendDeposit || (async (msg) => { deposits.push(msg); }),
    onProgress: onProgress || ((evt) => { progressEvents.push(evt); }),
    onFileReceived: onFileReceived || ((evt) => { receivedFiles.push(evt); }),
  });

  return { svc, kvStore, deposits, progressEvents, receivedFiles };
}

// --- sendFile ---

test("sendFile — sends manifest then chunks in order", async () => {
  const { svc, deposits } = createService();
  const data = makeBytes(3000);
  const result = await svc.sendFile({
    fileBytes: data,
    fileName: "test.bin",
    peerAccountId: "acct:bob",
    contextId: "ctx-1",
  });

  assert.ok(result.manifest instanceof FileManifestV1);
  assert.equal(result.manifest.transferId, result.transferId);

  // First deposit is manifest
  const manifestPayload = JSON.parse(new TextDecoder().decode(deposits[0].plaintextBodyBytes));
  assert.equal(manifestPayload.kind, "rez.file.manifest.v1");

  // Remaining deposits are chunks, in order
  for (let i = 1; i < deposits.length; i++) {
    const chunkPayload = JSON.parse(new TextDecoder().decode(deposits[i].plaintextBodyBytes));
    assert.equal(chunkPayload.kind, "rez.file.chunk.v1");
    assert.equal(chunkPayload.chunkIndex, i - 1);
  }

  // Total: 1 manifest + chunkCount chunks
  assert.equal(deposits.length, 1 + result.manifest.chunkCount);
});

test("sendFile — stores file in kvStore", async () => {
  const { svc, kvStore } = createService();
  const data = makeBytes(1024);
  const result = await svc.sendFile({
    fileBytes: data,
    fileName: "store.bin",
    peerAccountId: "acct:bob",
    contextId: "ctx-1",
  });

  const stored = await svc.getFile(result.manifest.fileHashHex);
  assert.ok(stored instanceof Uint8Array);
  assert.deepEqual(stored, data);
});

test("sendFile — fires onProgress for each chunk", async () => {
  const { svc, progressEvents } = createService();
  const data = makeBytes(3000);
  await svc.sendFile({
    fileBytes: data,
    fileName: "prog.bin",
    peerAccountId: "acct:bob",
    contextId: "ctx-1",
    chunkSizeBytes: 1024,
  });

  // FileChunker default chunk size applies, but we get progress for each chunk
  assert.ok(progressEvents.length > 0);
  const last = progressEvents[progressEvents.length - 1];
  assert.equal(last.progress, 1);
  assert.equal(last.state, "complete");
});

// --- handleIncomingPayload ---

test("handleIncomingPayload — returns false for non-file payloads", async () => {
  const { svc } = createService();
  assert.equal(await svc.handleIncomingPayload({ kind: "rez.message.v1", text: "hi" }, {}), false);
  assert.equal(await svc.handleIncomingPayload(null, {}), false);
  assert.equal(await svc.handleIncomingPayload({ noKind: true }, {}), false);
});

test("handleIncomingPayload — manifest creates session", async () => {
  const { svc } = createService();
  const data = makeBytes(2048);
  const { manifest } = FileChunker.chunk(data, { fileName: "in.bin", chunkSizeBytes: 1024 });

  const consumed = await svc.handleIncomingPayload(manifest.toJSON(), {
    senderAccountId: "acct:alice",
    contextId: "ctx-1",
  });
  assert.equal(consumed, true);

  const session = svc.getTransferSession(manifest.transferId);
  assert.ok(session);
  assert.equal(session.state, "pending");
  assert.equal(session.progress, 0);
});

test("handleIncomingPayload — chunks update progress", async () => {
  const { svc, progressEvents } = createService();
  const data = makeBytes(2048);
  const { manifest, chunks } = FileChunker.chunk(data, { fileName: "prog.bin", chunkSizeBytes: 1024 });

  await svc.handleIncomingPayload(manifest.toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });

  await svc.handleIncomingPayload(chunks[0].toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });
  const session = svc.getTransferSession(manifest.transferId);
  assert.equal(session.receivedCount, 1);
  assert.equal(session.state, "receiving");
});

test("handleIncomingPayload — final chunk triggers reassembly + onFileReceived", async () => {
  const { svc, receivedFiles } = createService();
  const data = makeBytes(2048);
  const { manifest, chunks } = FileChunker.chunk(data, { fileName: "done.bin", chunkSizeBytes: 1024 });

  await svc.handleIncomingPayload(manifest.toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });
  await svc.handleIncomingPayload(chunks[0].toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });
  await svc.handleIncomingPayload(chunks[1].toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });

  assert.equal(receivedFiles.length, 1);
  assert.equal(receivedFiles[0].transferId, manifest.transferId);
  assert.deepEqual(receivedFiles[0].fileBytes, data);
  assert.ok(receivedFiles[0].manifest instanceof FileManifestV1);
});

test("handleIncomingPayload — out-of-order chunks work", async () => {
  const { svc, receivedFiles } = createService();
  const data = makeBytes(3072);
  const { manifest, chunks } = FileChunker.chunk(data, { fileName: "ooo.bin", chunkSizeBytes: 1024 });

  await svc.handleIncomingPayload(manifest.toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });
  // Send in reverse order
  await svc.handleIncomingPayload(chunks[2].toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });
  await svc.handleIncomingPayload(chunks[0].toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });
  await svc.handleIncomingPayload(chunks[1].toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });

  assert.equal(receivedFiles.length, 1);
  assert.deepEqual(receivedFiles[0].fileBytes, data);
});

test("handleIncomingPayload — bad chunk hash is rejected (logged, not thrown)", async () => {
  const logs = [];
  const { svc } = createService();
  // Override log to capture errors
  svc.log = { error: (...args) => logs.push(args) };

  const data = makeBytes(1024);
  const { manifest } = FileChunker.chunk(data, { fileName: "bad.bin", chunkSizeBytes: 1024 });

  await svc.handleIncomingPayload(manifest.toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });

  // Send chunk with tampered data but matching transfer ID
  const badChunk = new FileChunkV1({
    transferId: manifest.transferId,
    chunkIndex: 0,
    dataB64: "AAAA", // wrong data
    hashHex: bytesToHex(Hash.sha256(new Uint8Array([0, 0, 0]))),
  });

  const consumed = await svc.handleIncomingPayload(badChunk.toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });
  assert.equal(consumed, true);
  assert.ok(logs.length > 0, "should have logged a hash mismatch error");

  // Session should NOT have marked chunk as received
  const session = svc.getTransferSession(manifest.transferId);
  assert.equal(session.receivedCount, 0);
});

test("getFile — returns null for unknown hash", async () => {
  const { svc } = createService();
  const result = await svc.getFile("0".repeat(64));
  assert.equal(result, null);
});

test("getFile — retrieves stored file by hash", async () => {
  const { svc } = createService();
  const data = makeBytes(2048);
  const { manifest, chunks } = FileChunker.chunk(data, { fileName: "get.bin", chunkSizeBytes: 1024 });

  await svc.handleIncomingPayload(manifest.toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });
  for (const chunk of chunks) {
    await svc.handleIncomingPayload(chunk.toJSON(), { senderAccountId: "acct:alice", contextId: "ctx-1" });
  }

  const retrieved = await svc.getFile(manifest.fileHashHex);
  assert.ok(retrieved instanceof Uint8Array);
  assert.deepEqual(retrieved, data);
});
