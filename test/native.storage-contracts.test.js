import test from "node:test";
import assert from "node:assert/strict";
import { NativePrimitiveClient } from "../src/native/NativePrimitiveRecords.js";
import { NativeStorageProvider } from "../src/native/NativeStorageProvider.js";

test("malformed native reads and corrupted JSON are unreadable, never missing keys", async () => {
  for (const values of [[], [false], ["false", ""], [true, "broken JSON"]]) {
    const client = new NativePrimitiveClient(() => JSON.stringify({ ok: true, values }));
    const store = new NativeStorageProvider(client).getKeyValueStore("test");
    await assert.rejects(store.getStrict("critical"), (error) => error.name === "KeyValueUnreadableError");
  }
});

test("only an explicit native missing-key result becomes undefined", async () => {
  const client = new NativePrimitiveClient(() => JSON.stringify({ ok: true, values: [false, ""] }));
  assert.equal(await new NativeStorageProvider(client).getKeyValueStore("test").getStrict("missing"), undefined);
});

test("native provider satisfies the canonical flat storage contract", async () => {
  const calls = [];
  const client = new NativePrimitiveClient((requestJson) => {
    const request = JSON.parse(requestJson);
    calls.push(request);
    if (request.method === "storage.get") return JSON.stringify({ ok: true, values: [false, ""] });
    if (request.method === "storage.keys") return JSON.stringify({ ok: true, values: ["one", "two"] });
    if (request.method === "storage.delete") return JSON.stringify({ ok: true, values: [true] });
    return JSON.stringify({ ok: true, values: [] });
  });
  const provider = new NativeStorageProvider(client);
  assert.equal(await provider.get("missing"), null);
  assert.equal(await provider.put("one", { value: 1 }).then((value) => value.value), 1);
  assert.equal(await provider.del("one"), true);
  assert.deepEqual(await provider.listKeys(), ["one", "two"]);
  assert.deepEqual(calls.map((call) => call.args[0]), ["", "", "", ""]);
});

test("native storage partitions owner scopes without changing the storage contract", async () => {
  const calls = [];
  const client = new NativePrimitiveClient((requestJson) => {
    const request = JSON.parse(requestJson);
    calls.push(request);
    return JSON.stringify({ ok: true, values: request.method === "storage.get" ? [false, ""] : [] });
  });
  const partition = new NativeStorageProvider(client).partition("mobile:account", "rez:acct:one");
  await partition.getKeyValueStore().get("root");
  await partition.getKeyValueStore("rez:acct:one").get("owned");
  assert.deepEqual(calls.map((call) => call.args[0]), [
    JSON.stringify(["mobile:account", "rez:acct:one", null]),
    JSON.stringify(["mobile:account", "rez:acct:one", "rez:acct:one"]),
  ]);
});
