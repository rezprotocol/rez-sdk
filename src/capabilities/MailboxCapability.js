import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";
import { requireResponseBody } from "../util/responseBody.js";

const T = REZ_CONTRACT_TYPES;

/**
 * Mailbox capability — deposit, list, fetch, and acknowledge mailbox events.
 *
 * Authz: when the session has bound the mailboxId via `inbox.claim`, the
 * relay's session-binding shortcut grants access without an explicit cap
 * chain. Otherwise the caller must pass `capChain` (an array of
 * RCapability JSONs rooted at the inbox claimant). See
 * docs/SECURITY_AUDIT.md MED-3 / HIGH-6 and CAPABILITY_MODEL §7.
 */
export class MailboxCapability {
  #pool;

  constructor({ pool }) {
    this.#pool = pool;
  }

  async deposit({ mailboxId, objectId, ciphertextB64, data, metadata, capChain } = {}) {
    const body = { mailboxId, objectId, ciphertextB64: ciphertextB64 || data, metadata };
    if (Array.isArray(capChain) && capChain.length > 0) {
      body.capChain = capChain;
    }
    const response = await this.#pool.sendRequest({
      type: T.MAILBOX_DEPOSIT,
      body,
      expectedResponseType: T.MAILBOX_DEPOSIT_RES,
    });
    // Pinned against MailboxHandler.handleDeposit, which answers { mailboxId, eventId } on a
    // delivered deposit and { mailboxId, eventId: "", queued: true } when the packet was persisted
    // to the outbound queue instead. So eventId is REQUIRED but may be empty — `queued` appears
    // only on the queued branch and must not be required.
    return requireResponseBody({
      op: "MailboxCapability.deposit",
      response,
      require: { mailboxId: "nonEmptyString", eventId: "string" },
    });
  }

  async list({ mailboxId, cursor = null, limit = 50, capChain } = {}) {
    const body = { mailboxId, cursor, limit };
    if (Array.isArray(capChain) && capChain.length > 0) {
      body.capChain = capChain;
    }
    const response = await this.#pool.sendRequest({
      type: T.MAILBOX_LIST,
      body,
      expectedResponseType: T.MAILBOX_LIST_RES,
    });
    // `items` is REQUIRED, not defaulted. The old fallback turned drift into an EMPTY MAILBOX —
    // catch-up would conclude there was nothing to drain and ack nothing, indistinguishable from a
    // genuinely quiet inbox. An empty page is still a real answer; a missing one is not.
    const respBody = requireResponseBody({
      op: "MailboxCapability.list",
      response,
      require: { items: "array" },
    });
    return {
      items: respBody.items,
      nextCursor: respBody.nextCursor || null,
    };
  }

  async fetch({ mailboxId, eventId, capChain } = {}) {
    const body = { mailboxId, eventId };
    if (Array.isArray(capChain) && capChain.length > 0) {
      body.capChain = capChain;
    }
    const response = await this.#pool.sendRequest({
      type: T.MAILBOX_FETCH,
      body,
      expectedResponseType: T.MAILBOX_FETCH_RES,
    });
    // NOT-FOUND is NOT a missing body: MailboxHandler answers an unknown eventId with a complete
    // body carrying ciphertextB64: null. So the old `: null` return could only ever mean drift,
    // and the caller — which reads ciphertextB64 and substitutes "" — could not tell the two
    // apart, silently treating a broken response as an undecryptable deposit.
    return requireResponseBody({
      op: "MailboxCapability.fetch",
      response,
      require: { mailboxId: "nonEmptyString", eventId: "nonEmptyString" },
    });
  }

  async ack({ mailboxId, eventId, capChain } = {}) {
    const body = { mailboxId, eventId };
    if (Array.isArray(capChain) && capChain.length > 0) {
      body.capChain = capChain;
    }
    const response = await this.#pool.sendRequest({
      type: T.MAILBOX_ACK,
      body,
      expectedResponseType: T.MAILBOX_ACK_RES,
    });
    // Pinned against MailboxAckResponse: `removed` distinguishes a deleted event from an ack of
    // something already gone, and an ack is the last step before ciphertext is unrecoverable.
    return requireResponseBody({
      op: "MailboxCapability.ack",
      response,
      require: { mailboxId: "nonEmptyString", eventId: "nonEmptyString", removed: "boolean" },
    });
  }

  /**
   * Advance this device's durable cursor on the home log (S2). Used ONLY against
   * a durable-capable node (the `durableInbox` capability is advertised in
   * `session.ready`); against legacy/fs nodes the client keeps using `ack`
   * (delete). The cursor advances only when the chat pipeline reports the
   * deposit `consumed` (decrypt/apply or dedup-hit) — never on receive.
   *
   * No `deviceId` arg: the cursor's device is the authenticated session, bound
   * server-side. The response echoes the resolved `deviceId`.
   */
  async cursorAck({ mailboxId, throughSeq, capChain } = {}) {
    const body = { mailboxId, throughSeq };
    if (Array.isArray(capChain) && capChain.length > 0) {
      body.capChain = capChain;
    }
    const response = await this.#pool.sendRequest({
      type: T.MAILBOX_CURSOR_ACK,
      body,
      expectedResponseType: T.MAILBOX_CURSOR_ACK_RES,
    });
    // Pinned against MailboxCursorAckResponse. `lastSeq` is the durable watermark this device has
    // consumed through; a drifted response reading as "no cursor" would re-drain or, worse, be
    // mistaken for seq 0.
    return requireResponseBody({
      op: "MailboxCapability.cursorAck",
      response,
      require: { mailboxId: "nonEmptyString", deviceId: "nonEmptyString", lastSeq: "integer" },
    });
  }
}
