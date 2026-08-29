// M2 (rez-chat plans/MOBILE_LIFECYCLE_ADAPTER_PLAN.md §7b) — connectNow():
// the app-level liveness kick. Frozen requirements pinned here:
//   - connectNow PARTICIPATES in the pool's connect/reconnect serialization:
//     it cancels the future scheduled attempt and JOINS an attempt already in
//     flight (a scheduled callback that entered its reconnect path must never
//     be raced by a platform wake).
//   - close() unconditionally terminates the reconnect machinery even when
//     the client never reached connected (the M1-found leak: a failed first
//     connect leaves a scheduled background reconnect armed past close()).

import test from "node:test";
import assert from "node:assert/strict";

import { UplinkPool } from "../src/pool/UplinkPool.js";
import { TypedEventBus } from "../src/events/TypedEventBus.js";

class GatedTransport {
  constructor(url, control) {
    this.url = url;
    this.control = control;
    this.stateHandler = null;
  }

  onFrame() { return () => {}; }

  onState(handler) {
    this.stateHandler = handler;
    return () => { this.stateHandler = null; };
  }

  async connect() {
    this.control.connectCalls += 1;
    if (this.control.gate) await this.control.gate;
    if (!this.control.online) {
      const err = new Error("ECONNREFUSED");
      err.code = "CONNECT_FAILED";
      err.retryable = true;
      throw err;
    }
  }

  async close() {}

  async sendRequest() { return { body: {} }; }
}

function makePool({ control, reconnectBackoffMs = 1000, onRestored = null } = {}) {
  const eventBus = new TypedEventBus();
  const pool = new UplinkPool({
    uplinks: ["ws://one"],
    transportFactory: (url) => new GatedTransport(url, control),
    authMachine: {
      sessionInfo: { nodeKeyId: "node", nodePublicKeyB64: "pub", relayKeyId: "relay" },
      async authenticate() {},
    },
    eventBus,
    warmSpareCount: 0,
    timeouts: { reconnectBackoffMs },
  });
  if (typeof onRestored === "function") pool.onReconnected(onRestored);
  return pool;
}

test("connectNow: an offline pool connects immediately — no waiting out the scheduled backoff — and restoration hooks run before it resolves", async () => {
  const control = { online: false, connectCalls: 0, gate: null };
  const restored = [];
  // Long backoff: if connectNow waited for the timer this test would hang.
  const pool = makePool({ control, reconnectBackoffMs: 60_000, onRestored: async () => { restored.push("restore"); } });

  await assert.rejects(pool.connect(), (err) => err.retryable === true);
  assert.equal(pool.getActiveUplink(), null);

  control.online = true;
  await pool.connectNow();

  assert.equal(pool.getActiveUplink(), "ws://one");
  assert.deepEqual(restored, ["restore"], "the awaited restoration hook ran, exactly once");
  await pool.close();
});

test("connectNow: a ready pool is a no-op (no transport churn)", async () => {
  const control = { online: true, connectCalls: 0, gate: null };
  const pool = makePool({ control });
  await pool.connect();
  const callsAfterConnect = control.connectCalls;

  await pool.connectNow();
  assert.equal(control.connectCalls, callsAfterConnect, "no new connection attempt");
  assert.equal(pool.getActiveUplink(), "ws://one");
  await pool.close();
});

test("connectNow: a closed pool refuses loudly", async () => {
  const control = { online: true, connectCalls: 0, gate: null };
  const pool = makePool({ control });
  await pool.connect();
  await pool.close();
  await assert.rejects(pool.connectNow(), (err) => err.code === "CLOSED" && err.retryable === false);
});

test("connectNow: SERIALIZES with a scheduled reconnect attempt already in flight — joined, never raced", async () => {
  const control = { online: false, connectCalls: 0, gate: null };
  const restored = [];
  const pool = makePool({ control, reconnectBackoffMs: 1000, onRestored: async () => { restored.push("restore"); } });

  await assert.rejects(pool.connect(), (err) => err.retryable === true);
  const callsAfterBoot = control.connectCalls;

  // Gate the NEXT transport connect so the scheduled (1s) attempt is caught
  // mid-flight, then fire connectNow while it is inside its reconnect path.
  let release = null;
  control.online = true;
  control.gate = new Promise((resolve) => { release = resolve; });
  await new Promise((resolve) => setTimeout(resolve, 1200));
  assert.equal(control.connectCalls, callsAfterBoot + 1, "the scheduled attempt entered connect and is gated");

  const kicked = pool.connectNow();
  // The kick must have JOINED the in-flight attempt: still exactly one
  // additional transport connect, even while both are pending.
  assert.equal(control.connectCalls, callsAfterBoot + 1, "connectNow did not race a second transport connect");

  release();
  control.gate = null;
  await kicked;

  assert.equal(pool.getActiveUplink(), "ws://one");
  assert.equal(control.connectCalls, callsAfterBoot + 1, "one attempt served both the timer and the kick");
  assert.deepEqual(restored, ["restore"], "restoration ran once, not once per caller");
  await pool.close();
});

test("connectNow: two concurrent kicks share one attempt", async () => {
  const control = { online: false, connectCalls: 0, gate: null };
  const pool = makePool({ control, reconnectBackoffMs: 60_000 });
  await assert.rejects(pool.connect(), (err) => err.retryable === true);
  const callsAfterBoot = control.connectCalls;

  let release = null;
  control.online = true;
  control.gate = new Promise((resolve) => { release = resolve; });
  const first = pool.connectNow();
  const second = pool.connectNow();
  release();
  control.gate = null;
  await Promise.all([first, second]);

  assert.equal(control.connectCalls, callsAfterBoot + 1);
  assert.equal(pool.getActiveUplink(), "ws://one");
  await pool.close();
});

test("connectNow: a failed kick reports the failure AND leaves the standard offline+backoff path armed", async () => {
  const control = { online: false, connectCalls: 0, gate: null };
  const pool = makePool({ control, reconnectBackoffMs: 1000 });
  await assert.rejects(pool.connect(), (err) => err.retryable === true);

  await assert.rejects(pool.connectNow(), (err) => err.retryable === true);

  // The standard machinery stands: once the network appears, the scheduled
  // backoff attempt (re-armed by the failed kick) recovers on its own.
  control.online = true;
  const deadline = Date.now() + 10_000;
  while (pool.getActiveUplink() === null && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(pool.getActiveUplink(), "ws://one", "the re-armed scheduled attempt recovered");
  await pool.close();
});

test("close() with NO successful connect ever: the armed background reconnect is terminated — the M1-found leak", async () => {
  const control = { online: false, connectCalls: 0, gate: null };
  const pool = makePool({ control, reconnectBackoffMs: 1000 });
  await assert.rejects(pool.connect(), (err) => err.retryable === true);
  await pool.close();

  // Bring the network up and wait past several backoff windows: a leaked
  // timer would connect here.
  control.online = true;
  const callsAfterClose = control.connectCalls;
  await new Promise((resolve) => setTimeout(resolve, 2500));
  assert.equal(control.connectCalls, callsAfterClose, "no connection attempt after close()");
  assert.equal(pool.getActiveUplink(), null);
});
