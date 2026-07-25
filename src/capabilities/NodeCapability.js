import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";
import { requireResponseBody } from "../util/responseBody.js";

const T = REZ_CONTRACT_TYPES;

/**
 * Node capability — node status queries.
 */
export class NodeCapability {
  #pool;

  constructor({ pool }) {
    this.#pool = pool;
  }

  async status({ timeoutMs = 5000, tryAllUplinks = true, continueOnCodes = [] } = {}) {
    const response = await this.#pool.sendRequest({
      type: T.NODE_STATUS,
      body: {},
      expectedResponseType: T.NODE_STATUS_RES,
      timeoutMs,
      tryAllUplinks,
      continueOnCodes,
    });
    // Pinned against MeshStatusHandler, which always sends { node, mesh, peers } — `mesh` is null
    // on a node with meshing off, which is an answer, not an absence. (Note: the NodeStatusResponse
    // record class describes a DIFFERENT, older shape and is not what this op sends.)
    return requireResponseBody({
      op: "NodeCapability.status",
      response,
      require: { node: "object", mesh: "nullableObject", peers: "array" },
    });
  }
}
