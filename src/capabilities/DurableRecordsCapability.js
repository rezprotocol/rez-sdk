import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";
import { requireResponseBody } from "../util/responseBody.js";

const T = REZ_CONTRACT_TYPES;

/**
 * Durable signed-record capability — publish and fetch self-authenticating,
 * self-expiring records on the DHT overlay. Generic over the record blob:
 * the caller signs a DurableRecordV1 (see @rezprotocol/core durableRecordV1)
 * and publishes it; any peer can fetch it by its publisher-bound coordinates
 * without the publisher being online.
 *
 * Rides the same generic request path as mailbox — no per-directive facade.
 */
export class DurableRecordsCapability {
  #pool;

  constructor({ pool }) {
    this.#pool = pool;
  }

  /**
   * Publish a signed record. The local node verifies it, holds a copy, and
   * stores it on the k-closest backbone nodes to its slot.
   * @param {{ record: object }} args
   * @returns {Promise<{ localId: string, replicas: number }>}
   */
  async put({ record } = {}) {
    const response = await this.#pool.sendRequest({
      type: T.RECORD_PUT,
      body: { record },
      expectedResponseType: T.RECORD_PUT_RES,
    });
    // A response at all means STORED — RecordHandler answers a rejected or failed put with an
    // error frame, which the transport rejects. So `{}` here used to read as a successful
    // publication that named no local id and no replicas: publish-and-forget callers (authority
    // state, device sets) would carry on believing the record was retrievable.
    return requireResponseBody({
      op: "DurableRecordsCapability.put",
      response,
      require: { localId: "nonEmptyString", replicas: "integer" },
    });
  }

  /**
   * Fetch a record by its publisher-bound coordinates. Returns the verified
   * record, or null if not found anywhere on the overlay.
   * @param {{ recordKind: string, recordId: string, publisherPublicKeyB64: string }} args
   * @returns {Promise<object|null>}
   */
  async get({ recordKind, recordId, publisherPublicKeyB64 } = {}) {
    const response = await this.#pool.sendRequest({
      type: T.RECORD_GET,
      body: { recordKind, recordId, publisherPublicKeyB64 },
      expectedResponseType: T.RECORD_GET_RES,
    });
    // NOT-FOUND is an explicit `record: null` from RecordHandler, so the KEY is always present.
    // Requiring it separates "the overlay does not have this record" (a real answer, still null)
    // from "the response was malformed" (drift, now loud).
    const body = requireResponseBody({
      op: "DurableRecordsCapability.get",
      response,
      require: { record: "nullableObject" },
    });
    return body.record;
  }
}
