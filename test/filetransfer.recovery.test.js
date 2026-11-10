import test from "node:test";
import assert from "node:assert/strict";
import { FileChunker, FileManifestV1, FileTransferSessionV1, MemoryKeyValueStore, bytesToBase64 } from "@rezprotocol/core";
import { FileTransferService } from "../src/filetransfer/FileTransferService.js";

const context = { senderAccountId: "acct:alice", contextId: "thread:one" };

class FaultStore extends MemoryKeyValueStore {
  #failKey = null;
  failNextSet(key) { this.#failKey = key; }
  async set(key, value) {
    if (key === this.#failKey) { this.#failKey = null; throw new Error("injected storage failure"); }
    return super.set(key, value);
  }
}

function fixture() {
  const bytes = Uint8Array.from({ length: 3072 }, (_, i) => (i * 17 + Math.floor(i / 1024) * 31) % 256);
  return { bytes, ...FileChunker.chunk(bytes, { fileName: "resume.bin", chunkSizeBytes: 1024 }) };
}

function receiver(kvStore, received, callback = null) {
  return new FileTransferService({
    kvStore,
    onSendDeposit: async () => { throw new Error("receive-only fixture"); },
    onFileReceived: callback || (async (event) => { received.push(event); }),
  });
}

test("restart resumes verified chunks without replaying the manifest", async () => {
  const kv = new FaultStore(); const received = []; const { bytes, manifest, chunks } = fixture();
  const first = receiver(kv, received);
  await first.handleIncomingPayload(manifest, context);
  await first.handleIncomingPayload(chunks[0], context);
  const restarted = receiver(kv, received);
  await assert.rejects(restarted.handleIncomingPayload(chunks[1], { ...context, senderAccountId: "acct:mallory" }), /sender\/context mismatch/);
  await assert.rejects(restarted.handleIncomingPayload(chunks[1], { ...context, contextId: "thread:other" }), /sender\/context mismatch/);
  await Promise.all(chunks.slice(1).map((chunk) => restarted.handleIncomingPayload(chunk, context)));
  assert.equal(received.length, 1);
  assert.deepEqual(received[0].fileBytes, bytes);
  assert.equal(received[0].senderAccountId, context.senderAccountId);
  assert.equal(received[0].contextId, context.contextId);
  assert.deepEqual(await restarted.getFile(manifest.fileHashHex), bytes);
  for (const chunk of chunks) assert.equal(await kv.get("xfer-chunk:" + manifest.transferId + ":" + chunk.chunkIndex), undefined);
});

test("manifest replay cannot reset progress or change authenticated metadata", async () => {
  const kv = new FaultStore(); const received = []; const { bytes, manifest, chunks } = fixture();
  const service = receiver(kv, received);
  await service.handleIncomingPayload(manifest, context);
  await service.handleIncomingPayload(chunks[0], context);
  await service.handleIncomingPayload(manifest, context);
  assert.equal(service.getTransferSession(manifest.transferId).receivedCount, 1);
  const changed = new FileManifestV1({ ...manifest.toJSON(), fileName: "different.bin" });
  await assert.rejects(service.handleIncomingPayload(changed, context), /manifest changed/);
  for (const chunk of chunks.slice(1)) await service.handleIncomingPayload(chunk, context);
  const restarted = receiver(kv, received);
  await restarted.handleIncomingPayload(manifest, context);
  for (const chunk of chunks) await restarted.handleIncomingPayload(chunk, context);
  assert.equal(received.length, 1, "a durably completed projection is not repeated by manifest/chunk replay");
  assert.deepEqual(received[0].fileBytes, bytes);
});

test("failed chunk storage leaves its receipt unset and permits retry", async () => {
  const kv = new FaultStore(); const received = []; const { bytes, manifest, chunks } = fixture();
  const service = receiver(kv, received);
  await service.handleIncomingPayload(manifest, context);
  kv.failNextSet("xfer-chunk:" + manifest.transferId + ":0");
  await assert.rejects(service.handleIncomingPayload(chunks[0], context), /injected storage failure/);
  const stored = FileTransferSessionV1.fromJSON(JSON.parse(await kv.get("xfer:" + manifest.transferId)));
  assert.equal(stored.receivedCount, 0);
  for (const chunk of chunks) await service.handleIncomingPayload(chunk, context);
  assert.deepEqual(received[0].fileBytes, bytes);
});

for (const failureIndex of [0, 2]) test("restart repairs a chunk write before its receipt bitmap at index " + failureIndex, async () => {
  const kv = new FaultStore(); const received = []; const { bytes, manifest, chunks } = fixture();
  const first = receiver(kv, received);
  await first.handleIncomingPayload(manifest, context);
  for (const chunk of chunks.slice(0, failureIndex)) await first.handleIncomingPayload(chunk, context);
  kv.failNextSet("xfer:" + manifest.transferId);
  await assert.rejects(first.handleIncomingPayload(chunks[failureIndex], context), /injected storage failure/);
  const restarted = receiver(kv, received);
  const remaining = chunks.slice(failureIndex + 1);
  if (remaining.length === 0) remaining.push(chunks[failureIndex]);
  for (const chunk of remaining) await restarted.handleIncomingPayload(chunk, context);
  assert.deepEqual(received[0].fileBytes, bytes);
});

test("application failure retains complete bytes and retries projection after restart", async () => {
  const kv = new FaultStore(); const received = []; const { bytes, manifest, chunks } = fixture();
  const first = receiver(kv, received, async () => { throw new Error("projection unavailable"); });
  await first.handleIncomingPayload(manifest, context);
  for (const chunk of chunks.slice(0, -1)) await first.handleIncomingPayload(chunk, context);
  await assert.rejects(first.handleIncomingPayload(chunks[chunks.length - 1], context), /projection unavailable/);
  const stored = FileTransferSessionV1.fromJSON(JSON.parse(await kv.get("xfer:" + manifest.transferId)));
  assert.equal(stored.state, "receiving", "byte completion alone is not application completion");
  const restarted = receiver(kv, received);
  await restarted.handleIncomingPayload(chunks[chunks.length - 1], context);
  assert.deepEqual(received[0].fileBytes, bytes);
  assert.equal(restarted.getTransferSession(manifest.transferId).state, "complete");
});

test("chunk consumption waits for the asynchronous completion projection", async () => {
  const kv = new FaultStore(); const { manifest, chunks } = fixture();
  let release; let began;
  const gate = new Promise((resolve) => { release = resolve; });
  const started = new Promise((resolve) => { began = resolve; });
  const service = receiver(kv, [], async () => { began(); await gate; });
  await service.handleIncomingPayload(manifest, context);
  for (const chunk of chunks.slice(0, -1)) await service.handleIncomingPayload(chunk, context);
  let consumed = false;
  const pending = service.handleIncomingPayload(chunks[chunks.length - 1], context).then(() => { consumed = true; });
  await started;
  assert.equal(consumed, false);
  release(); await pending;
  assert.equal(consumed, true);
});

test("legacy partial state and unknown chunks fail explicitly without deleting recovery evidence", async () => {
  const kv = new FaultStore(); const { manifest, chunks } = fixture(); const service = receiver(kv, []);
  await assert.rejects(service.handleIncomingPayload(chunks[0], context), { code: "FILE_TRANSFER_RECOVERY_REQUIRED" });
  const legacy = new FileTransferSessionV1({ transferId: manifest.transferId, manifest, receivedChunks: [true, false, false], state: "receiving", createdAtMs: 1, updatedAtMs: 1 });
  const raw = JSON.stringify(legacy.toJSON());
  await kv.set("xfer:" + manifest.transferId, raw);
  await assert.rejects(service.handleIncomingPayload(chunks[1], context), { code: "FILE_TRANSFER_RECOVERY_REQUIRED" });
  assert.equal(await kv.get("xfer:" + manifest.transferId), raw);
});

test("receiver budget rejects excessive chunk counts before persisting a session", async () => {
  const kv = new FaultStore(); const { manifest } = fixture(); const service = receiver(kv, []);
  const count = FileTransferService.MAX_CHUNK_COUNT + 1;
  const oversized = new FileManifestV1({ ...manifest.toJSON(), chunkCount: count, fileSizeBytes: count * 1024, chunkHashesHex: new Array(count).fill(manifest.chunkHashesHex[0]) });
  await assert.rejects(service.handleIncomingPayload(oversized, context), /byte\/chunk limit/);
  assert.equal(await kv.get("xfer:" + manifest.transferId), undefined);
});

test("a corrupted completed file is never served or projected as valid", async () => {
  const kv = new FaultStore(); const received = []; const { manifest, chunks } = fixture();
  const service = receiver(kv, received);
  await service.handleIncomingPayload(manifest, context);
  for (const chunk of chunks) await service.handleIncomingPayload(chunk, context);
  await kv.set("file:" + manifest.fileHashHex, bytesToBase64(new Uint8Array([1, 2, 3])));
  const restarted = receiver(kv, received);
  await assert.rejects(restarted.handleIncomingPayload(manifest, context), /Stored file hash mismatch/);
  assert.equal(received.length, 1);
});
