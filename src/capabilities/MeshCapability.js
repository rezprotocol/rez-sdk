import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";

const T = REZ_CONTRACT_TYPES;

/**
 * Mesh capability — node mesh status queries.
 */
export class MeshCapability {
  #pool;

  constructor({ pool }) {
    this.#pool = pool;
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
