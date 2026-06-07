import test from "node:test";
import assert from "node:assert/strict";

import {
  PEER_LINK_STATE,
  SESSION_STATUS,
  DECRYPTABLE_SESSION_STATUSES,
  PEER_LINK_TRANSITIONS,
  isSessionUsable,
  checkTransition,
  assertTransition,
} from "../src/peer-link/PeerLinkStateMachine.js";

// The state machine is the SSOT for peer-link lifecycle strings. These tests
// lock the exact persisted values and the transition table so a refactor that
// drifts a string or drops a real edge fails loudly.

test("PEER_LINK_STATE maps to the exact legacy persisted strings", () => {
  assert.deepEqual({ ...PEER_LINK_STATE }, {
    INVITE_ISSUED: "invite_issued",
    ACCEPT_COMMITTED: "accept_committed",
    HANDSHAKE_SENT: "handshake_sent",
    HANDSHAKE_RECEIVED: "handshake_received",
    SESSION_ESTABLISHED: "session_established",
    DEGRADED: "degraded",
    REHANDSHAKE_REQUESTED: "rehandshake_requested",
    REJECTED: "rejected",
    FAILED: "failed",
  });
});

test("SESSION_STATUS maps to the exact legacy persisted strings", () => {
  assert.deepEqual({ ...SESSION_STATUS }, {
    PENDING_REMOTE_CONFIRM: "pending_remote_confirm",
    ACTIVE: "active",
  });
});

test("isSessionUsable matches the legacy canSend/canDecrypt four-way gate", () => {
  // Usable — including the dead-but-historically-accepted "ready"/"established".
  for (const ok of ["active", "pending_remote_confirm", "ready", "established"]) {
    assert.equal(isSessionUsable(ok), true, ok + " must be usable");
  }
  assert.deepEqual(
    [...DECRYPTABLE_SESSION_STATUSES].sort(),
    ["active", "established", "pending_remote_confirm", "ready"],
  );
  // Not usable.
  for (const no of ["", "pending", "rejected", "degraded", "unknown", null, undefined]) {
    assert.equal(isSessionUsable(no), false, String(no) + " must NOT be usable");
  }
  // Whitespace is trimmed.
  assert.equal(isSessionUsable("  active  "), true);
});

test("checkTransition allows fresh-create (no from-state) and idempotent self-transitions", () => {
  assert.equal(checkTransition(null, "accept_committed").allowed, true, "fresh create");
  assert.equal(checkTransition("", "session_established").allowed, true, "empty from = create");
  assert.equal(checkTransition("session_established", "session_established").allowed, true, "self");
  assert.equal(checkTransition("rejected", "rejected").allowed, true, "self even for terminal");
});

test("checkTransition encodes the verified establishment edges", () => {
  // The four edges flagged as risky-but-real in the design.
  assert.equal(checkTransition("accept_committed", "session_established").allowed, true);
  assert.equal(checkTransition("accept_committed", "degraded").allowed, true);
  assert.equal(checkTransition("accept_committed", "handshake_sent").allowed, true);
  assert.equal(checkTransition("handshake_sent", "session_established").allowed, true);
  assert.equal(checkTransition("handshake_received", "session_established").allowed, true);
  assert.equal(checkTransition("session_established", "rehandshake_requested").allowed, true);
  assert.equal(checkTransition("rehandshake_requested", "session_established").allowed, true);
  // Reattempt: a terminal dead link is re-driven by acceptInvite.
  assert.equal(checkTransition("rejected", "accept_committed").allowed, true);
  assert.equal(checkTransition("failed", "accept_committed").allowed, true);
});

test("checkTransition rejects untabulated edges", () => {
  assert.equal(checkTransition("rejected", "session_established").allowed, false);
  assert.equal(checkTransition("handshake_received", "rejected").allowed, false);
  assert.equal(checkTransition("session_established", "handshake_sent").allowed, false);
  assert.equal(checkTransition("invite_issued", "session_established").allowed, false);
});

test("assertTransition log-and-allow: illegal edge calls onIllegal and does NOT throw", () => {
  const seen = [];
  const result = assertTransition("rejected", "session_established", {
    onIllegal: (r) => seen.push(r),
    strict: false,
  });
  assert.equal(result.allowed, false);
  assert.equal(seen.length, 1, "onIllegal invoked once");
  assert.equal(seen[0].from, "rejected");
  assert.equal(seen[0].to, "session_established");
});

test("assertTransition: legal edge does not invoke onIllegal", () => {
  let called = 0;
  const result = assertTransition("handshake_sent", "session_established", {
    onIllegal: () => { called += 1; },
  });
  assert.equal(result.allowed, true);
  assert.equal(called, 0);
});

test("assertTransition strict mode throws PEER_LINK_ILLEGAL_TRANSITION on an illegal edge", () => {
  assert.throws(
    () => assertTransition("rejected", "session_established", { strict: true }),
    (err) => err && err.code === "PEER_LINK_ILLEGAL_TRANSITION",
  );
  // Strict mode still permits legal edges.
  assert.equal(assertTransition("handshake_sent", "session_established", { strict: true }).allowed, true);
});

test("the transition table is frozen (SSOT cannot be mutated at runtime)", () => {
  assert.equal(Object.isFrozen(PEER_LINK_TRANSITIONS), true);
  assert.equal(Object.isFrozen(PEER_LINK_STATE), true);
  assert.equal(Object.isFrozen(SESSION_STATUS), true);
});
