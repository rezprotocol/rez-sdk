import test from "node:test";
import assert from "node:assert/strict";
import { IndexedDbStorageProvider } from "../src/storage/IndexedDbStorageProvider.js";

function fixture(operation) {
  const request = {};
  const transaction = { objectStore: () => ({ put: () => request, delete: () => request, clear: () => request }) };
  const provider = new IndexedDbStorageProvider();
  provider._openDb = async () => ({ transaction: () => transaction });
  const invoke = operation === "put" ? () => provider.put("key", "payload")
    : operation === "del" ? () => provider.del("key") : () => provider.clear();
  return { request, transaction, invoke };
}

for (const operation of ["put", "del", "clear"]) {
  test(operation + " waits for transaction commit after request success", async () => {
    const { request, transaction, invoke } = fixture(operation);
    let resolved = false;
    const pending = invoke().then((value) => { resolved = true; return value; });
    await new Promise((resolve) => setImmediate(resolve));
    if (typeof request.onsuccess === "function") request.onsuccess();
    await Promise.resolve();
    assert.equal(resolved, false, "request success alone is not a durable acknowledgement");
    transaction.oncomplete();
    assert.equal(await pending, operation === "put" ? "payload" : undefined);
  });

  test(operation + " rejects an abort after request success", async () => {
    const { request, transaction, invoke } = fixture(operation);
    const pending = invoke();
    await new Promise((resolve) => setImmediate(resolve));
    if (typeof request.onsuccess === "function") request.onsuccess();
    const rejection = assert.rejects(pending, /transaction aborted/);
    transaction.onabort();
    await rejection;
  });
}
