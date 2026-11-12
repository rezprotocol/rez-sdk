import test from "node:test";
import assert from "node:assert/strict";
import { MemoryStorageProvider } from "@rezprotocol/core";
import { PeerLinkService } from "../src/peer-link/PeerLinkService.js";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";

const signer = { sign: async () => new Uint8Array([1]), getSignerRef: () => ({ kind: "test" }) };
const verifier = { verify: async () => true };

function makeService(storageProvider) {
  return new PeerLinkService({
    storageProvider,
    ownerAccountId: "rez:acct:owner",
    signer,
    verifier,
  });
}

test("a provider without exclusive runtime ownership fails closed", async () => {
  const memory = new MemoryStorageProvider();
  const provider = {
    getKeyValueStore: () => memory.getKeyValueStore(),
    getPeerLinkStorage: () => memory.getPeerLinkStorage(),
  };
  const service = makeService(provider);
  await assert.rejects(
    () => service.listPendingDeliveryWork(),
    (err) => err.code === "DELIVERY_RUNTIME_OWNERSHIP_UNSUPPORTED",
  );
});

test("one memory provider admits one runtime until its owner releases", async () => {
  const provider = new MemoryStorageProvider();
  const first = makeService(provider);
  const second = makeService(provider);
  await first.listPendingDeliveryWork();
  await assert.rejects(
    () => second.listPendingDeliveryWork(),
    (err) => err.code === "DELIVERY_RUNTIME_ALREADY_ACTIVE",
  );
  await first.close();
  assert.deepEqual(await second.listPendingDeliveryWork(), [], "a refused runtime can retry after the owner releases");
  await second.close();
});

test("runtime admission rejects and releases grants without an active-owner assertion", async () => {
  const provider = new MemoryStorageProvider();
  const acquire = provider.acquireRuntimeOwnership.bind(provider);
  let releases = 0;
  provider.acquireRuntimeOwnership = async () => {
    const grant = await acquire();
    return {
      runtimeEpoch: grant.runtimeEpoch,
      release: async () => { releases += 1; await grant.release(); },
    };
  };
  const service = makeService(provider);
  await assert.rejects(() => service.listPendingDeliveryWork(), /invalid delivery runtime grant/);
  assert.equal(releases, 1);
  provider.acquireRuntimeOwnership = acquire;
  assert.deepEqual(await service.listPendingDeliveryWork(), []);
  await service.close();
});

test("close before first use is terminal", async () => {
  const service = makeService(new MemoryStorageProvider());
  await service.close();
  await assert.rejects(() => service.listPendingDeliveryWork(), /PeerLinkService is closed/);
});

test("key-value backed peer-link storage requires corruption-distinguishing reads", () => {
  assert.throws(
    () => createKeyValueBackedPeerLinkStorage({
      keyValueStore: { get() {}, set() {}, delete() {}, keys() {} },
    }),
    /strict reads/,
  );
});
