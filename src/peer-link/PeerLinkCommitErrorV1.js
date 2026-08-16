import { RRecord } from "../defaults/createDefaultLogger.js";

// DT-007: the owned degraded-commit marker returned (never thrown) on a
// decrypt result when the post-decrypt session commit could not fully land
// but the receive-ratchet advance was VERIFIED durable. `stage` names the
// first commit stage that did not complete:
//   session-write         — this attempt's sessions.put did not report
//                           success. Reachable only on the fresh-read RETRY,
//                           where an earlier put already returned successfully
//                           and the snapshot re-verified; a first-attempt
//                           write that never returns is re-thrown, not marked
//                           (see #confirmAdvancedRatchetDurable).
//   peer-link-transition  — the peer-link CAS never landed
//   event-append          — the CAS landed; the lifecycle event append failed
export const PEER_LINK_COMMIT_STAGES = Object.freeze([
  "session-write",
  "peer-link-transition",
  "event-append",
]);

export class PeerLinkCommitErrorV1 extends RRecord {
  static type = "sdk.peerlink.commit_error.v1";

  constructor(raw = {}) {
    super();
    this.code = "PEER_LINK_COMMIT_FAILED";
    this.stage = String(raw.stage == null ? "" : raw.stage).trim();
    this.message = String(raw.message == null ? "" : raw.message).trim();
    this._seal();
  }

  validate() {
    this.assert(this.code === "PEER_LINK_COMMIT_FAILED", "code is fixed");
    this.assert(PEER_LINK_COMMIT_STAGES.includes(this.stage),
      "stage must be one of " + PEER_LINK_COMMIT_STAGES.join("|"));
    this.assert(this.message.length > 0, "message must be non-empty");
  }
}
