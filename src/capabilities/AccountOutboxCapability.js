import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";
import { requireResponseBody } from "../util/responseBody.js";

const T = REZ_CONTRACT_TYPES;

/**
 * Account authority-state propagation outbox — the CLIENT half of P1#3 (leaf 5).
 *
 * The home enqueues a publication obligation inside the same transaction that folds an
 * account device mutation (PgAccountMutationSerializer → PgPropagationOutbox), because the
 * node CANNOT publish for the account: an AccountAuthorityStateV1 is ACCOUNT-signed, and the
 * node holds no account key. So an authorized device drains the queue:
 *
 *   claim()      → take the head-advancing account lease (one per account, cluster-wide)
 *   prepare()    → FREEZE the epoch M this lease will publish
 *   ...          → build + sign the AccountAuthorityStateV1 for exactly M (caller's job)
 *   complete()   → submit the signed publication; the node verifies + stores it, then marks
 *                  every obligation epoch <= M done (the cumulative drain)
 *   release()    → give up the lease cleanly (nothing published)
 *   fail()       → record a failed attempt: backoff + attempt accounting on the node
 *
 * A delegated device needs the deviceSet.publish capability; a direct (account-root) session
 * always qualifies. Both are enforced by the node — this capability adds no authority of its
 * own, it only carries the ops.
 *
 * Rides the generic request path like every other capability — no per-directive facade.
 *
 * STRICTNESS: every response discriminant is REQUIRED to be a boolean, AND the payload the node
 * guarantees on the true branch is required too — both through the shared `requireResponseBody`
 * gate (src/util/responseBody.js — the SSOT for the convention: return what the JSDoc promises,
 * or throw). An empty-object fallback would be actively dangerous here: a missing `leased` reads
 * as "nothing to lease" and a missing `completed` as "the lease was lost", silently converting
 * contract drift into a plausible-but-wrong no-op that stalls revocation propagation. Validating
 * only the discriminant was not enough either — see the audit note on #send.
 */
export class AccountOutboxCapability {
  #pool;

  constructor({ pool }) {
    this.#pool = pool;
  }

  /**
   * Claim the account's publication lease. Returns the server-minted lease, or a not-leased answer
   * whose `awaitingRootSignature` says WHICH kind it is:
   *
   *   - `{ leased: false, awaitingRootSignature: false }` — nothing publishable, another device
   *     holds the lease, or the head is backing off. Come back later.
   *   - `{ leased: false, awaitingRootSignature: true }`  — an obligation exists, but this session
   *     is delegated and the authority state is root-signed only, so only a primary (account-root)
   *     session can discharge it. The node takes NO lease in this case, so nothing is counted as a
   *     failed attempt and the head stays immediately claimable.
   *
   * `awaitingRootSignature` is required on every claim response, not optional: absent and false
   * would otherwise be indistinguishable to a caller deciding whether to tell the user that their
   * primary device needs to come online.
   *
   * @returns {Promise<{ leased: boolean, awaitingRootSignature: boolean, token?: string, anchorEpoch?: number, headEpoch?: number, leaseExpiresAtMs?: number, attempts?: number }>}
   */
  async claim() {
    return this.#send({
      op: "claim",
      type: T.ACCOUNT_OUTBOX_LEASE_CLAIM,
      expectedResponseType: T.ACCOUNT_OUTBOX_LEASE_CLAIM_RES,
      // claim carries NO client input: the account comes from the authenticated session and
      // the lease owner from the session device.
      body: {},
      discriminant: "leased",
      // Present on BOTH branches, so it is required regardless of the discriminant.
      always: { awaitingRootSignature: "boolean" },
      // OutboxLeaseClaimResponse guarantees the whole lease on the leased branch.
      onTrue: {
        token: "nonEmptyString",
        anchorEpoch: "integer",
        headEpoch: "integer",
        leaseExpiresAtMs: "integer",
        attempts: "integer",
      },
    });
  }

  /**
   * Freeze the epoch this lease will publish. Idempotent: a repeat prepare under the same lease
   * returns the SAME frozen epoch, never re-pointing at a newer head under an in-flight publish.
   * `{ prepared: false }` means the lease is no longer live (expired, released, or revoked).
   *
   * `headEpoch` is the frozen epoch M — build the publication for exactly M, or `complete` will
   * be rejected with CONFLICT.
   *
   * @param {{ leaseToken: string }} args
   * @returns {Promise<{ prepared: boolean, anchorEpoch?: number, headEpoch?: number }>}
   */
  async prepare({ leaseToken } = {}) {
    return this.#send({
      op: "prepare",
      type: T.ACCOUNT_OUTBOX_LEASE_PREPARE,
      expectedResponseType: T.ACCOUNT_OUTBOX_LEASE_PREPARE_RES,
      body: { leaseToken: this.#requireToken("prepare", leaseToken) },
      discriminant: "prepared",
      // The FROZEN epoch is the whole point of prepare — a prepared lease without one is drift.
      onTrue: { anchorEpoch: "integer", headEpoch: "integer" },
    });
  }

  /**
   * Release this lease without publishing — the clean give-up path (e.g. the head advanced past
   * the frozen epoch, so this device must re-claim). No backoff is applied: the obligation stays
   * immediately eligible for the next claim. `{ released: false }` means the lease was already
   * gone.
   *
   * @param {{ leaseToken: string }} args
   * @returns {Promise<{ released: boolean }>}
   */
  async release({ leaseToken } = {}) {
    return this.#send({
      op: "release",
      type: T.ACCOUNT_OUTBOX_LEASE_RELEASE,
      expectedResponseType: T.ACCOUNT_OUTBOX_LEASE_RELEASE_RES,
      body: { leaseToken: this.#requireToken("release", leaseToken) },
      discriminant: "released",
    });
  }

  /**
   * Record a FAILED publication attempt: the node releases the lease and backs off the epoch this
   * lease actually attempted (its frozen prepared epoch), saturating `attempts` and stamping an
   * operator-visible blocked state at the threshold. The obligation is NEVER abandoned — it stays
   * outstanding until a verified publication (or a superseding verified epoch) completes it.
   * `{ recorded: false }` means there was no live lease to fail.
   *
   * @param {{ leaseToken: string }} args
   * @returns {Promise<{ recorded: boolean, attemptedEpoch?: number, anchorEpoch?: number, attempts?: number, backoffMs?: number, blocked?: boolean }>}
   */
  async fail({ leaseToken } = {}) {
    return this.#send({
      op: "fail",
      type: T.ACCOUNT_OUTBOX_LEASE_FAIL,
      expectedResponseType: T.ACCOUNT_OUTBOX_LEASE_FAIL_RES,
      body: { leaseToken: this.#requireToken("fail", leaseToken) },
      discriminant: "recorded",
      onTrue: {
        attemptedEpoch: "integer",
        anchorEpoch: "integer",
        attempts: "integer",
        backoffMs: "integer",
        blocked: "boolean",
      },
    });
  }

  /**
   * Submit the signed publication for the frozen epoch — the one crypto-bearing op. The node
   * verifies the DurableRecordV2 envelope + the inner AccountAuthorityStateV1 against the
   * account's own current revocation state, STORES it, and only then marks obligations done.
   *
   * `{ completed: false }` is the benign lease-lost race: the lease lapsed while the node was
   * verifying, so another device will re-drain (the record is stored and authentic either way).
   * A publication whose epoch differs from the frozen one is rejected with CONFLICT — re-claim
   * and re-prepare rather than retrying the same submission.
   *
   * The record rides VERBATIM: the node re-verifies every signature over these exact bytes, so
   * the SDK never trims or reshapes it.
   *
   * @param {{ leaseToken: string, record: object }} args
   * @returns {Promise<{ completed: boolean, doneThroughEpoch?: number }>}
   */
  async complete({ leaseToken, record } = {}) {
    const token = this.#requireToken("complete", leaseToken);
    if (record === undefined || record === null || typeof record !== "object" || Array.isArray(record)) {
      throw new Error("AccountOutboxCapability.complete requires record (the signed publication object)");
    }
    return this.#send({
      op: "complete",
      type: T.ACCOUNT_OUTBOX_LEASE_COMPLETE,
      expectedResponseType: T.ACCOUNT_OUTBOX_LEASE_COMPLETE_RES,
      body: { leaseToken: token, record },
      discriminant: "completed",
      // The watermark the caller records as "published through". Without it a completed
      // publication cannot be told from a lost lease.
      onTrue: { doneThroughEpoch: "integer" },
    });
  }

  /**
   * The token rides VERBATIM — no trim, no coercion. The node bounds its size in the contract
   * layer and compares it against the stored lease exactly; a client-side reshape could only
   * mask a caller bug or turn a valid token into an invalid one.
   */
  #requireToken(op, leaseToken) {
    if (typeof leaseToken !== "string" || leaseToken.length === 0) {
      throw new Error("AccountOutboxCapability." + op + " requires leaseToken (a non-empty string)");
    }
    return leaseToken;
  }

  /**
   * @param {object} args
   * @param {string} args.discriminant — the boolean every branch of the caller's logic turns on
   * @param {Record<string,string>} [args.always] — fields the node's response record guarantees on
   *     EVERY branch, checked alongside the discriminant
   * @param {Record<string,string>} [args.onTrue] — fields the node's response record guarantees
   *     WHEN the discriminant is true (see the audit note below)
   */
  async #send({ op, type, expectedResponseType, body, discriminant, always = null, onTrue = null }) {
    const response = await this.#pool.sendRequest({ type, body, expectedResponseType });
    const opName = "AccountOutboxCapability." + op;
    const result = requireResponseBody({
      op: opName,
      response,
      require: always === null ? { [discriminant]: "boolean" } : { [discriminant]: "boolean", ...always },
    });
    if (result[discriminant] !== true || onTrue === null) return result;
    // AUDIT FIX: validating the discriminant ALONE was not enough. The node's response records
    // guarantee a payload on the true branch, but a drifted `{prepared: true}` with no headEpoch
    // left the drain worker comparing against undefined — which reads as "the head advanced",
    // so it released the lease and re-claimed until it burned its entire cycle budget, silently,
    // instead of failing. A true discriminant with a missing payload is drift like any other.
    return requireResponseBody({ op: opName, response, require: onTrue });
  }
}
