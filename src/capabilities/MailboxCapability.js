import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";

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
    return response && typeof response.body === "object" ? response.body : {};
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
    const respBody = response && typeof response.body === "object" ? response.body : {};
    return {
      items: Array.isArray(respBody.items) ? respBody.items : [],
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
    return response && typeof response.body === "object" ? response.body : null;
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
    return response && typeof response.body === "object" ? response.body : {};
  }
}
