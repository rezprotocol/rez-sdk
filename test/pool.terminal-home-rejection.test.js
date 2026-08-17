import test from "node:test";
import assert from "node:assert/strict";

import { UplinkPool } from "../src/pool/UplinkPool.js";
import { AuthFailure } from "../src/errors/index.js";

/**
 * rez-node#2 — a filesystem-backed home cannot admit a delegated device. It said
 * so, but nothing carried the reason: the auth machine wrapped the node's error
 * in an AuthFailure (whose `code` is fixed at AUTH_FAILURE), and the pool then
 * reported `UNREACHABLE` because no uplink came up.
 *
 * `UNREACHABLE` is a network-shaped, retryable code. A tester saw it against a
 * node that was plainly running and answering, and went to debug their
 * connection. Worse, the pool kept reconnecting forever against a refusal that
 * could never change.
 *
 * These pin both halves: the node's code survives the wrap, and a home that
 * refused on the merits is reported as itself and not retried.
 */

const URL_A = "wss://home-a.example/ws";
const URL_B = "wss://home-b.example/ws";

function makeTransport(url) {
  return {
    url,
    async connect() {},
    async close() {},
    onFrame() { return () => {}; },
    onState() { return () => {}; },
    async sendRequest() { throw new Error("not used"); },
  };
}

function makePool({ uplinks, authenticate }) {
  const events = [];
  return {
    events,
    pool: new UplinkPool({
      uplinks,
      transportFactory: (url) => makeTransport(url),
      authMachine: { authenticate },
      eventBus: { emit: (name, payload) => events.push({ name, payload }) },
    }),
  };
}

/** What the auth machine produces for a node-sent error record. */
function authFailureCarrying(code, message) {
  const failure = new AuthFailure(message);
  failure.serverCode = code;
  return failure;
}

test("a home that refuses on the merits is reported as itself, not as UNREACHABLE", async () => {
  const { pool } = makePool({
    uplinks: [URL_A],
    authenticate: async () => {
      throw authFailureCarrying(
        "DELEGATED_DEVICES_UNSUPPORTED",
        "This home node is single-device and cannot admit a linked device.",
      );
    },
  });

  await assert.rejects(
    () => pool.connect(),
    (err) => {
      assert.equal(err.code, "DELEGATED_DEVICES_UNSUPPORTED",
        "collapsing this to UNREACHABLE is what sent a tester to debug their network");
      assert.equal(err.retryable, false, "no amount of retrying makes a single-device home multi-device");
      assert.match(err.message, /single-device/);
      return true;
    },
  );
  await pool.close();
});

test("a terminal refusal does not schedule a reconnect", async () => {
  let attempts = 0;
  const { pool } = makePool({
    uplinks: [URL_A],
    authenticate: async () => {
      attempts += 1;
      throw authFailureCarrying("DELEGATED_DEVICES_UNSUPPORTED", "single-device home");
    },
  });

  await assert.rejects(() => pool.connect());
  const afterConnect = attempts;
  // Long enough that any immediate reconnect would have fired.
  await new Promise((resolve) => setTimeout(resolve, 250));
  assert.equal(attempts, afterConnect,
    "reconnecting against a structural refusal burns the socket and buries the real message");
  await pool.close();
});

test("an ordinary connection failure still reports UNREACHABLE and still retries", async () => {
  const { pool } = makePool({
    uplinks: [URL_A],
    authenticate: async () => { throw new AuthFailure("session challenge expired"); },
  });

  await assert.rejects(
    () => pool.connect(),
    (err) => {
      assert.equal(err.code, "UNREACHABLE", "only known terminal codes change behaviour");
      assert.equal(err.retryable, true);
      return true;
    },
  );
  await pool.close();
});

test("an unrecognised error code is NOT promoted to terminal", async () => {
  // Conservative by construction: a code this pool has never heard of keeps the
  // old retrying behaviour rather than silently becoming fatal.
  const { pool } = makePool({
    uplinks: [URL_A],
    authenticate: async () => authFailureCarrying("SOME_FUTURE_CODE", "who knows"),
  });
  const failing = makePool({
    uplinks: [URL_A],
    authenticate: async () => { throw authFailureCarrying("SOME_FUTURE_CODE", "who knows"); },
  });

  await assert.rejects(
    () => failing.pool.connect(),
    (err) => { assert.equal(err.code, "UNREACHABLE"); return true; },
  );
  await failing.pool.close();
  await pool.close();
});

test("a healthy uplink still wins even if another home refuses terminally", async () => {
  const { pool } = makePool({
    uplinks: [URL_A, URL_B],
    authenticate: async (transport) => {
      if (transport.url === URL_A) {
        throw authFailureCarrying("DELEGATED_DEVICES_UNSUPPORTED", "single-device home");
      }
      return { sessionId: "s-1" };
    },
  });

  await pool.connect();
  assert.equal(pool.getActiveUplink(), URL_B,
    "one home's refusal must not disqualify a home that can actually serve us");
  await pool.close();
});
