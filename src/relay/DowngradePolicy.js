/**
 * DowngradePolicy — the POLICY half of the downgrade floor (SESSION_AUTH_V5
 * slice 2B). Deliberately separate from RelayContractFloorStore:
 *
 *   the store answers  "what has this relay proven it supports?"   (a fact)
 *   the policy answers "may I start an identity-bearing handshake?" (a choice)
 *
 * Default posture is RECORD-ONLY: observations are recorded and downgrade
 * conditions surfaced, nothing is refused. Refusal is an embedder OPT-IN
 * (`enforce: true`), and even then only the identity-disclosing account-mode
 * handshake toward a known-v5 relay is refused — transport code NEVER reacts
 * to a failure by retrying with weaker identity disclosure; a permitted
 * legacy connection after a refusal is always an explicit user/embedder
 * decision surfaced above the transport (Phase 0 §7).
 */

/**
 * May an ACCOUNT-mode (identity-bearing) handshake be initiated toward this
 * relay identity?
 *
 * @param {object} opts
 * @param {string} opts.relayIdentityB64 — the PINNED/expected relay identity
 *   (pre-hello there is nothing verified yet, so only a pinned identity can
 *   gate; unpinned connections cannot be pre-refused and fall back to
 *   post-auth observation)
 * @param {import("./RelayContractFloorStore.js").RelayContractFloorStore} opts.floorStore
 * @param {boolean} [opts.enforce=false] — record-only unless the embedder
 *   opted into refusal
 * @returns {{ permitted: boolean, floor: number|null, reason: string|null }}
 */
export function permitsAccountModeAuth({ relayIdentityB64, floorStore, enforce = false } = {}) {
  const identity = typeof relayIdentityB64 === "string" ? relayIdentityB64.trim() : "";
  if (!floorStore || !identity) {
    return { permitted: true, floor: null, reason: null };
  }
  const floor = floorStore.floorFor(identity);
  if (floor === null || floor < 5) {
    return { permitted: true, floor, reason: null };
  }
  if (enforce !== true) {
    return { permitted: true, floor, reason: "downgrade-condition-recorded" };
  }
  return {
    permitted: false,
    floor,
    reason: "relay previously authenticated at contract " + floor
      + "; account-mode auth toward it is a downgrade and enforcement is enabled",
  };
}
