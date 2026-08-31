import { RAbstract } from "@rezprotocol/core";

/**
 * Post-seal delivery-carrier interface.
 *
 * Implementations receive only transport-facing records. They never encrypt,
 * decrypt, mutate ratchets, select policy, or receive router-internal state.
 */
export class RDeliveryTransport extends RAbstract {
  static type = "sdk.delivery.transport.abstract";

  descriptor() {
    return this.abstract("descriptor");
  }

  async start(_contextRecord) {
    return this.abstract("start");
  }

  async stop() {
    return this.abstract("stop");
  }

  async assess(_assessmentRequestRecord) {
    return this.abstract("assess");
  }

  async submit(_submissionRecord) {
    return this.abstract("submit");
  }

  onInbound(_handler) {
    return this.abstract("onInbound");
  }

  async settle(_settlementRecord) {
    return this.abstract("settle");
  }

  async queryCustody(_custodyQueryRecord) {
    return this.abstract("queryCustody");
  }
}
