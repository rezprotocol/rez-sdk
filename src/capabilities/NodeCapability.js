import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";

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
    return response && typeof response.body === "object" ? response.body : {};
  }
}
