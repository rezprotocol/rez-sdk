import test from "node:test";
import assert from "node:assert/strict";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";

function makeKv(seed = []) {
  const rows = new Map(seed);
  return {
    rows,
    async get(key) { return rows.get(key); },
    async getStrict(key) { return rows.get(key); },
    async set(key, value) { rows.set(key, JSON.parse(JSON.stringify(value))); },
    async delete(key) { return rows.delete(key); },
    async keys(prefix = "") { return [...rows.keys()].filter((key) => key.startsWith(prefix)).reverse(); },
  };
}

const OWNER = "rez:acct:event-owner";
const LINK = "pl_event_link";

function event(eventId, atMs) {
  return { ownerAccountId: OWNER, peerLinkId: LINK, eventId, type: "test", atMs, summary: null, details: {} };
}

test("legacy event array migrates crash-safely while preserving event-id cursors", async () => {
  const legacyKey = "peer-link:events:index:" + OWNER + "::" + LINK;
  const kv = makeKv([
    [legacyKey, ["pev_a", "pev_b", "pev_c"]],
    ["peer-link:events:" + OWNER + "::pev_a", event("pev_a", 30)],
    ["peer-link:events:" + OWNER + "::pev_b", event("pev_b", 10)],
    ["peer-link:events:" + OWNER + "::pev_c", event("pev_c", 20)],
  ]);
  const { events } = createKeyValueBackedPeerLinkStorage({ keyValueStore: kv });
  const page = await events.listByPeerLinkId(OWNER, LINK, { limit: 2, cursor: "pev_a" });
  assert.deepEqual(page.items.map((row) => row.eventId), ["pev_b", "pev_c"]);
  assert.equal(page.nextCursor, null);
  assert.equal(kv.rows.has(legacyKey), false);
  assert.equal(kv.rows.get("peer-link:events-index-migrated:v1:" + OWNER + "::" + LINK), "v1");
  assert.equal(kv.rows.get("peer-link:events-index:" + OWNER + "::" + LINK + "::pev_b").seq, 1);
});

test("partial migration is idempotently repaired before the marker and ignores the array after it", async () => {
  const legacyKey = "peer-link:events:index:" + OWNER + "::" + LINK;
  const entryKey = "peer-link:events-index:" + OWNER + "::" + LINK + "::pev_a";
  const markerKey = "peer-link:events-index-migrated:v1:" + OWNER + "::" + LINK;
  const kv = makeKv([
    [legacyKey, ["pev_a", "pev_b"]],
    ["peer-link:events:" + OWNER + "::pev_a", event("pev_a", 1)],
    ["peer-link:events:" + OWNER + "::pev_b", event("pev_b", 2)],
    [entryKey, { recordVersion: 1, ownerAccountId: OWNER, peerLinkId: LINK, eventId: "pev_a", atMs: 999, seq: 99 }],
  ]);
  const { events } = createKeyValueBackedPeerLinkStorage({ keyValueStore: kv });
  await events.migrateLegacyIndex(OWNER, LINK);
  assert.equal(kv.rows.get(entryKey).seq, 0);
  assert.equal(kv.rows.get(entryKey).atMs, 1);

  kv.rows.set(legacyKey, ["pev_b"]);
  kv.rows.set(markerKey, "v1");
  const page = await events.listByPeerLinkId(OWNER, LINK);
  assert.deepEqual(page.items.map((row) => row.eventId), ["pev_a", "pev_b"]);
  assert.equal(kv.rows.has(legacyKey), false);
});

test("keyed append assigns max seq plus one independent of enumeration order", async () => {
  const kv = makeKv();
  const { events } = createKeyValueBackedPeerLinkStorage({ keyValueStore: kv });
  await events.append(event("pev_a", 30));
  await events.append(event("pev_b", 10));
  await events.append(event("pev_c", 20));
  const page = await events.listByPeerLinkId(OWNER, LINK);
  assert.deepEqual(page.items.map((row) => row.eventId), ["pev_a", "pev_b", "pev_c"]);
  assert.equal(kv.rows.get("peer-link:events-index:" + OWNER + "::" + LINK + "::pev_c").seq, 2);
});
