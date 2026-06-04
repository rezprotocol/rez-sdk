import { REZ_CONTRACT_TYPES, MESH_ADDRESS_KINDS, assertValidMeshAddress } from "@rezprotocol/core";
import { bytesToBase64 } from "../util/bytes.js";

const T = REZ_CONTRACT_TYPES;

/**
 * Mesh capability — the one place an app hands an object to the mesh.
 *
 * `dispatch(object, address)` is THE send verb. A creator builds an object,
 * declares a protocol address (inbox | rendezvous — see meshAddressV1 in
 * @rezprotocol/core), and gets a confirmation. It NEVER names a transport;
 * routing picks the substrate from the address kind:
 *   - inbox:      deposit the object's opaque payload bytes at address.inboxId.
 *                 The app has already encrypted (encryption needs the peer-link
 *                 session, an app concern); the mesh moves opaque bytes only.
 *   - rendezvous: publish the object's signed record on the durable overlay so
 *                 any holder of the coordinate can pull it, publisher offline.
 *
 * Transitional note (Phase 1 of transport unification): `object` is still
 * kind-specific because signing/encryption have not yet moved into routing.
 * Phases 3-4 collapse it to opaque payload bytes once the generic
 * self-authenticating value envelope and its validation gate land. Until then
 * dispatch delegates to the existing mailbox / durable-record capabilities so
 * the wire op stays single-sourced.
 *
 * Also retains `getMeshStatus()` (mesh-status query) — unchanged.
 */
export class MeshCapability {
  #pool;
  #mailbox;
  #durableRecords;

  constructor({ pool, mailbox = null, durableRecords = null }) {
    this.#pool = pool;
    this.#mailbox = mailbox;
    this.#durableRecords = durableRecords;
  }

  /**
   * Hand an object to the mesh. Routes by address kind; throws on an invalid
   * address before touching any transport.
   *
   * @param {object} object
   *   inbox:      { payloadBytes: Uint8Array, objectId?: string, metadata?: object, capChain?: array }
   *   rendezvous: { record: signed DurableRecordV1 }
   * @param {object} address  MeshAddressV1 (inbox | rendezvous)
   * @returns {Promise<object>} the underlying delivery/publish confirmation
   */
  async dispatch(object, address) {
    assertValidMeshAddress(address);
    if (address.kind === MESH_ADDRESS_KINDS.INBOX) {
      return this.#dispatchToInbox(object, address);
    }
    return this.#dispatchToRendezvous(object, address);
  }

  async #dispatchToInbox(object, address) {
    if (!this.#mailbox) {
      throw new Error("mesh.dispatch(inbox) requires a mailbox capability — construct MeshCapability with { mailbox }");
    }
    const o = object && typeof object === "object" ? object : {};
    if (!(o.payloadBytes instanceof Uint8Array)) {
      throw new Error("mesh.dispatch(inbox) requires object.payloadBytes (Uint8Array)");
    }
    const objectId = typeof o.objectId === "string" && o.objectId.trim().length > 0
      ? o.objectId
      : "obj_" + Date.now() + "_" + Math.random().toString(36).slice(2, 10);
    return this.#mailbox.deposit({
      mailboxId: address.inboxId,
      objectId,
      ciphertextB64: bytesToBase64(o.payloadBytes),
      metadata: o.metadata && typeof o.metadata === "object" ? o.metadata : {},
      capChain: Array.isArray(o.capChain) && o.capChain.length > 0 ? o.capChain : undefined,
    });
  }

  async #dispatchToRendezvous(object, address) {
    if (!this.#durableRecords) {
      throw new Error("mesh.dispatch(rendezvous) requires a durableRecords capability — construct MeshCapability with { durableRecords }");
    }
    const o = object && typeof object === "object" ? object : {};
    if (!o.record || typeof o.record !== "object") {
      throw new Error("mesh.dispatch(rendezvous) requires object.record (a signed durable record)");
    }
    // The record self-binds to its own coordinate (durableRecords.put derives
    // the slot from the record, not from `address`). Reject a record whose
    // coordinate disagrees with the address it is being dispatched to, so the
    // address can never be a silent lie about where the object lands.
    if (o.record.recordKind !== address.recordKind
        || o.record.recordId !== address.recordId
        || o.record.publisherPublicKeyB64 !== address.publisherPublicKeyB64) {
      throw new Error("mesh.dispatch(rendezvous): record coordinate does not match address coordinate");
    }
    return this.#durableRecords.put({ record: o.record });
  }

  async getMeshStatus({ timeoutMs = 5000, tryAllUplinks = true, continueOnCodes = [] } = {}) {
    const response = await this.#pool.sendRequest({
      type: T.NODE_MESH_STATUS,
      body: {},
      expectedResponseType: T.NODE_MESH_STATUS_RES,
      timeoutMs,
      tryAllUplinks,
      continueOnCodes,
    });
    return response && typeof response.body === "object" ? response.body : {};
  }
}
