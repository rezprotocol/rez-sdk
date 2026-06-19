import test from "node:test";
import assert from "node:assert/strict";
import { createKeyValueBackedPeerLinkStorage } from "../src/peer-link/createKeyValueBackedPeerLinkStorage.js";

// Minimal in-memory KV store matching the interface the storage layer uses:
// get / set / delete(boolean) / keys(prefix).
function makeKvStore() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : undefined; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { return m.delete(k); },
    async keys(prefix) {
      const out = [];
      for (const k of m.keys()) {
        if (!prefix || k.startsWith(prefix)) out.push(k);
      }
      return out;
    },
  };
}

const OWNER = "rez:acct:owner";
const PEER_LINK = "pl_abc";

function sessionRecord({ sessionId, peerDeviceId, peerAccountId = "rez:acct:peer" }) {
  const rec = {
    sessionId,
    peerLinkId: PEER_LINK,
    localAccountId: OWNER,
    peerAccountId,
    status: "active",
    ratchetSnapshot: { v: 1, marker: sessionId },
    createdAtMs: 1,
    updatedAtMs: 1,
  };
  if (peerDeviceId) rec.peerDeviceId = peerDeviceId;
  return rec;
}

test("legacy session (no peerDeviceId) stays on the by-peer-link index", async () => {
  const { sessions } = createKeyValueBackedPeerLinkStorage({ keyValueStore: makeKvStore() });
  await sessions.put(sessionRecord({ sessionId: "s_legacy" }));

  const byLink = await sessions.getByPeerLinkId(OWNER, PEER_LINK);
  assert.equal(byLink.sessionId, "s_legacy");
  // The legacy session is NOT addressable by device and not in the device list.
  assert.equal(await sessions.getByPeerLinkAndDevice(OWNER, PEER_LINK, "rez:dev:x"), undefined);
  assert.deepEqual(await sessions.listByPeerLink(OWNER, PEER_LINK), []);
});

test("two per-device sessions under one peer-link coexist without clobbering", async () => {
  const { sessions } = createKeyValueBackedPeerLinkStorage({ keyValueStore: makeKvStore() });
  await sessions.put(sessionRecord({ sessionId: "s_dev1", peerDeviceId: "rez:dev:1" }));
  await sessions.put(sessionRecord({ sessionId: "s_dev2", peerDeviceId: "rez:dev:2" }));

  const d1 = await sessions.getByPeerLinkAndDevice(OWNER, PEER_LINK, "rez:dev:1");
  const d2 = await sessions.getByPeerLinkAndDevice(OWNER, PEER_LINK, "rez:dev:2");
  assert.equal(d1.sessionId, "s_dev1", "device 1 resolves independently");
  assert.equal(d2.sessionId, "s_dev2", "device 2 resolves independently (no clobber)");

  // Per-device sessions do NOT populate the legacy single-session index.
  assert.equal(await sessions.getByPeerLinkId(OWNER, PEER_LINK), undefined);

  const list = await sessions.listByPeerLink(OWNER, PEER_LINK);
  assert.deepEqual(list.map((r) => r.peerDeviceId), ["rez:dev:1", "rez:dev:2"]);
});

test("a per-device put updates its OWN device session in place (no second slot)", async () => {
  const { sessions } = createKeyValueBackedPeerLinkStorage({ keyValueStore: makeKvStore() });
  const first = await sessions.put(sessionRecord({ sessionId: "s_dev1", peerDeviceId: "rez:dev:1" }));
  const advanced = await sessions.put({ ...sessionRecord({ sessionId: "s_dev1", peerDeviceId: "rez:dev:1" }), ratchetSnapshot: { v: 1, marker: "advanced" } });
  assert.equal(advanced.version, first.version + 1, "version bumps on update");

  const resolved = await sessions.getByPeerLinkAndDevice(OWNER, PEER_LINK, "rez:dev:1");
  assert.equal(resolved.ratchetSnapshot.marker, "advanced");
  const list = await sessions.listByPeerLink(OWNER, PEER_LINK);
  assert.equal(list.length, 1, "still one session for the device");
});

test("deleting one device session leaves the other intact", async () => {
  const { sessions } = createKeyValueBackedPeerLinkStorage({ keyValueStore: makeKvStore() });
  await sessions.put(sessionRecord({ sessionId: "s_dev1", peerDeviceId: "rez:dev:1" }));
  await sessions.put(sessionRecord({ sessionId: "s_dev2", peerDeviceId: "rez:dev:2" }));

  assert.equal(await sessions.delete(OWNER, "s_dev1"), true);
  assert.equal(await sessions.getByPeerLinkAndDevice(OWNER, PEER_LINK, "rez:dev:1"), undefined, "device 1 gone");
  const d2 = await sessions.getByPeerLinkAndDevice(OWNER, PEER_LINK, "rez:dev:2");
  assert.equal(d2.sessionId, "s_dev2", "device 2 survives");
  assert.deepEqual((await sessions.listByPeerLink(OWNER, PEER_LINK)).map((r) => r.peerDeviceId), ["rez:dev:2"]);
});

test("legacy and per-device sessions on the same peer-link do not interfere", async () => {
  const { sessions } = createKeyValueBackedPeerLinkStorage({ keyValueStore: makeKvStore() });
  await sessions.put(sessionRecord({ sessionId: "s_legacy" }));
  await sessions.put(sessionRecord({ sessionId: "s_dev1", peerDeviceId: "rez:dev:1" }));

  assert.equal((await sessions.getByPeerLinkId(OWNER, PEER_LINK)).sessionId, "s_legacy");
  assert.equal((await sessions.getByPeerLinkAndDevice(OWNER, PEER_LINK, "rez:dev:1")).sessionId, "s_dev1");
  assert.deepEqual((await sessions.listByPeerLink(OWNER, PEER_LINK)).map((r) => r.sessionId), ["s_dev1"]);
});
