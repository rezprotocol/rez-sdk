import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";

const T = REZ_CONTRACT_TYPES;

/**
 * Inboxes capability — open-registration claim of inboxes at the connected
 * node. Each claim is signed locally by the SDK using a fresh per-inbox
 * keypair; the node persists `inboxId → claimantPublicKey` and never sees
 * the private side.
 *
 * Wire op: `inbox.claim` (see docs/CAPABILITY_MODEL.md §6).
 *
 * Pairs with `InboxClaimStore` — caller provides the store; this capability
 * orchestrates claim creation, wire send, and persistence-on-success.
 */
export class InboxesCapability {
  #pool;
  #claimStore;

  constructor({ pool, claimStore }) {
    if (!pool) throw new Error("InboxesCapability requires pool");
    if (!claimStore) throw new Error("InboxesCapability requires claimStore (InboxClaimStore)");
    this.#pool = pool;
    this.#claimStore = claimStore;
  }

  /**
   * Claim a new inbox at the connected node. Generates a fresh keypair and
   * random inbox ID locally, signs the claim, sends `inbox.claim`, and on
   * success persists the claim record (including the private key) to the
   * SDK's claim store.
   *
   * Returns the persisted claim record. The caller is now the inbox owner;
   * use the returned `rootCap` to authorize subsequent owner-scoped ops.
   */
  async claimInbox() {
    const claim = await this.#claimStore.createClaim();
    const response = await this.#pool.sendRequest({
      type: T.INBOX_CLAIM,
      body: {
        inboxId: claim.inboxId,
        claimantPublicKeyB64: claim.claimantPublicKeyB64,
        claimedAtMs: claim.claimedAtMs,
        signatureB64: claim.claimSignatureB64,
      },
      expectedResponseType: T.INBOX_CLAIM_RES,
    });
    const body = response && typeof response.body === "object" ? response.body : {};
    if (body.inboxId !== claim.inboxId) {
      throw new Error("inbox.claim response inboxId mismatch: expected " + claim.inboxId + ", got " + body.inboxId);
    }
    return this.#claimStore.persist(claim);
  }

  /**
   * Re-attest an existing claim against the connected node. Used on reconnect
   * to re-bind the inbox to the new session (the node's InboxClaimRegistry
   * accepts idempotent re-claims by the same claimant pubkey).
   *
   * Returns the existing stored claim record unchanged on success.
   */
  async reattestInbox(inboxId) {
    if (!this.#claimStore.has(inboxId)) {
      throw new Error("InboxesCapability.reattestInbox: no stored claim for " + inboxId);
    }
    const attestation = await this.#claimStore.createReattestation(inboxId);
    const response = await this.#pool.sendRequest({
      type: T.INBOX_CLAIM,
      body: {
        inboxId: attestation.inboxId,
        claimantPublicKeyB64: attestation.claimantPublicKeyB64,
        claimedAtMs: attestation.claimedAtMs,
        signatureB64: attestation.claimSignatureB64,
      },
      expectedResponseType: T.INBOX_CLAIM_RES,
    });
    const body = response && typeof response.body === "object" ? response.body : {};
    if (body.inboxId !== attestation.inboxId) {
      throw new Error("inbox.claim response inboxId mismatch: expected " + attestation.inboxId + ", got " + body.inboxId);
    }
    return this.#claimStore.get(inboxId);
  }

  /**
   * List metadata for all claimed inboxes (private keys redacted). Safe for
   * logging or for higher app layers that only need to know which inboxes
   * the SDK owns.
   */
  listClaimed() {
    return this.#claimStore.listRedacted();
  }
}
