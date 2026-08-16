import test from "node:test";
import assert from "node:assert/strict";

import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";

// DT-002 characterization: the peer-link event listing/cursor contract
// (KeyValuePeerLinkEventStore.listByPeerLinkId). This is the PUBLIC contract
// DT-302's keyed-entry migration must preserve unchanged (DT-006 Freeze
// Addendum A3): the public cursor is the existing EVENT-ID STRING; ordering
// is append order; pagination is exclusive-of-cursor. These tests pin what
// IS, defects included — they must pass byte-for-byte against the keyed
// implementation later.

function makeKvStore() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : undefined; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { return m.delete(k); },
    async keys(prefix) {
      const out = [];
      for (const k of m.keys()) if (!prefix || k.startsWith(prefix)) out.push(k);
      return out;
    },
  };
}

const OWNER = "rez:acct:cursor-pin-owner";
const LINK = "pl_cursor_pin";

async function makeStoreWithEvents(count) {
  const storage = createKeyValueBackedPeerLinkStorage({ keyValueStore: makeKvStore() });
  const ids = [];
  for (let i = 1; i <= count; i++) {
    const eventId = "pev_pin_" + String(i).padStart(2, "0");
    await storage.events.append({
      ownerAccountId: OWNER,
      eventId,
      peerLinkId: LINK,
      type: "pin_event",
      summary: "event " + i,
      details: { i },
      atMs: 1000, // deliberately identical: ordering must be append order, not atMs
    });
    ids.push(eventId);
  }
  return { events: storage.events, ids };
}

function itemIds(page) {
  return page.items.map((e) => e.eventId);
}

test("events cursor pin: no options returns everything in APPEND order with nextCursor null", async () => {
  const { events, ids } = await makeStoreWithEvents(5);
  const page = await events.listByPeerLinkId(OWNER, LINK);
  assert.deepEqual(itemIds(page), ids, "append order, not atMs order (all atMs identical)");
  assert.equal(page.nextCursor, null);
});

test("events cursor pin: limit pages forward; nextCursor is the last ITEM's eventId; cursor is EXCLUSIVE", async () => {
  const { events, ids } = await makeStoreWithEvents(5);

  const p1 = await events.listByPeerLinkId(OWNER, LINK, { limit: 2 });
  assert.deepEqual(itemIds(p1), [ids[0], ids[1]]);
  assert.equal(p1.nextCursor, ids[1], "public cursor is the event-id string");

  const p2 = await events.listByPeerLinkId(OWNER, LINK, { limit: 2, cursor: p1.nextCursor });
  assert.deepEqual(itemIds(p2), [ids[2], ids[3]], "cursor event itself is excluded");
  assert.equal(p2.nextCursor, ids[3]);

  const p3 = await events.listByPeerLinkId(OWNER, LINK, { limit: 2, cursor: p2.nextCursor });
  assert.deepEqual(itemIds(p3), [ids[4]]);
  assert.equal(p3.nextCursor, null, "final page has no nextCursor");
});

test("events cursor pin (defect): an UNKNOWN cursor silently replays from the beginning — no error, no empty page", async () => {
  const { events, ids } = await makeStoreWithEvents(3);
  const page = await events.listByPeerLinkId(OWNER, LINK, { limit: 2, cursor: "pev_never_existed" });
  assert.deepEqual(itemIds(page), [ids[0], ids[1]], "garbage cursor restarts at page 1");
});

test("events cursor pin: invalid limits mean UNBOUNDED (no clamp, no error)", async () => {
  const { events, ids } = await makeStoreWithEvents(4);
  for (const limit of [0, -1, 10.5, "2", Infinity]) {
    const page = await events.listByPeerLinkId(OWNER, LINK, { limit });
    assert.deepEqual(itemIds(page), ids, "limit " + String(limit) + " is ignored -> full tail");
    assert.equal(page.nextCursor, null, "without a valid limit, nextCursor is always null");
  }
});

test("events cursor pin: non-string cursor is ignored; missing index yields an empty page", async () => {
  const { events, ids } = await makeStoreWithEvents(2);
  const page = await events.listByPeerLinkId(OWNER, LINK, { cursor: 42 });
  assert.deepEqual(itemIds(page), ids);

  const empty = await events.listByPeerLinkId(OWNER, "pl_no_such_link");
  assert.deepEqual(empty.items, []);
  assert.equal(empty.nextCursor, null);
});
