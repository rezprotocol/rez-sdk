// PeerLinkStateMachine — single source of truth for peer-link lifecycle states,
// session statuses, and the legal transitions between peer-link states.
//
// Before this module the state strings were scattered string literals across
// the seven establishment entry points in PeerLinkService, each writing the
// same lifecycle by hand. That drift is what let the receive-path framing
// asymmetry (v0.4.5) and similar bugs hide. This module is pure (no I/O, no
// service imports) so it can be unit-tested in isolation and reused by every
// establishment path through PeerLinkService.#commitSession.

// Peer-link lifecycle states. Values are the exact strings persisted on the
// peerLinks `state` field — downstream consumers (chat-server teardown keys on
// "rejected"; snapshots assert "session_established") depend on them verbatim.
export const PEER_LINK_STATE = Object.freeze({
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

// Secure-session statuses actually written by the service.
export const SESSION_STATUS = Object.freeze({
  PENDING_REMOTE_CONFIRM: "pending_remote_confirm",
  ACTIVE: "active",
});

// Statuses under which a session may still encrypt/decrypt. Includes the
// historically-checked "ready"/"established" (never written today, but accepted
// by the legacy canSend/canDecrypt gate) so behavior stays byte-identical after
// consolidation. Order is not significant.
export const DECRYPTABLE_SESSION_STATUSES = Object.freeze([
  SESSION_STATUS.ACTIVE,
  SESSION_STATUS.PENDING_REMOTE_CONFIRM,
  "ready",
  "established",
]);

// True when a session in this status is permitted to encrypt/decrypt. Mirrors
// the four-way `canSend`/`canDecrypt` check the service used inline.
export function isSessionUsable(status) {
  const s = typeof status === "string" ? status.trim() : "";
  if (!s) return false;
  return DECRYPTABLE_SESSION_STATUSES.indexOf(s) !== -1;
}

// Allowed next-states per current peer-link state. Built strictly from the
// transitions the seven establishment paths actually perform — no speculative
// edges. A `from === to` self-transition and a fresh create (no prior state)
// are always allowed and are NOT enumerated here.
const TRANSITIONS = Object.freeze({
  invite_issued: Object.freeze(["accept_committed", "rejected", "failed"]),
  accept_committed: Object.freeze(["handshake_sent", "session_established", "degraded", "rejected", "failed"]),
  handshake_sent: Object.freeze(["session_established", "degraded", "rejected", "failed"]),
  handshake_received: Object.freeze(["session_established", "failed"]),
  session_established: Object.freeze(["session_established", "degraded", "rehandshake_requested", "failed"]),
  degraded: Object.freeze(["accept_committed", "session_established", "rehandshake_requested", "rejected", "failed"]),
  rehandshake_requested: Object.freeze(["session_established", "degraded", "failed"]),
  rejected: Object.freeze(["accept_committed"]),
  failed: Object.freeze(["accept_committed"]),
});

// Read-only view of the transition table (for tests/observability).
export const PEER_LINK_TRANSITIONS = TRANSITIONS;

// Pure check. Returns { allowed, from, to }. A missing/empty from-state means a
// fresh create (any target allowed). Idempotent self-transitions are allowed.
export function checkTransition(fromState, toState) {
  const from = typeof fromState === "string" ? fromState.trim() : "";
  const to = typeof toState === "string" ? toState.trim() : "";
  if (!from) {
    return { allowed: true, from: null, to };
  }
  if (from === to) {
    return { allowed: true, from, to };
  }
  const allowedNext = TRANSITIONS[from];
  const allowed = Array.isArray(allowedNext) && allowedNext.indexOf(to) !== -1;
  return { allowed, from, to };
}

// Validate a transition. On an illegal (untabulated) edge:
//   - invokes options.onIllegal({ allowed:false, from, to }) when provided, and
//   - throws PEER_LINK_ILLEGAL_TRANSITION only when options.strict === true.
// Default (log-and-allow) never throws — it returns the check result so the
// caller proceeds with byte-identical behavior while the illegal edge is
// observable. Flip options.strict to true to enforce once the table is proven.
export function assertTransition(fromState, toState, options = {}) {
  const result = checkTransition(fromState, toState);
  if (!result.allowed) {
    if (options && typeof options.onIllegal === "function") {
      options.onIllegal(result);
    }
    if (options && options.strict === true) {
      const err = new Error("Illegal peer-link transition: " + (result.from || "<none>") + " -> " + result.to);
      err.code = "PEER_LINK_ILLEGAL_TRANSITION";
      throw err;
    }
  }
  return result;
}
