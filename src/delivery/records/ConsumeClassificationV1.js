import { RRecord } from "@rezprotocol/core";
import {
  assertExactRecordKeys,
  canonicalRecordBytes,
  parseRecordBytes,
} from "./recordShared.js";

export const CONSUME_CLASSIFICATION_VERSION = 1;
export const CONSUME_CLASSIFICATIONS = Object.freeze([
  "consumed",
  "retryable-dependency",
  "terminal-auth-failure",
  "stale-replay",
]);

const RECORD_KEYS = Object.freeze(["v", "classification"]);

export class ConsumeClassificationV1 extends RRecord {
  static type = "sdk.delivery.consume_classification.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, RECORD_KEYS, "ConsumeClassificationV1");
    this.v = raw.v == null ? CONSUME_CLASSIFICATION_VERSION : raw.v;
    this.classification = raw.classification;
    this._seal();
  }

  validate() {
    this.assert(this.v === CONSUME_CLASSIFICATION_VERSION,
      "ConsumeClassificationV1.v must be 1");
    this.assert(CONSUME_CLASSIFICATIONS.includes(this.classification),
      "ConsumeClassificationV1.classification is unsupported");
  }

  toBytes() {
    return canonicalRecordBytes(this);
  }

  static fromBytes(bytes) {
    return ConsumeClassificationV1.fromJSON(
      parseRecordBytes(bytes, "ConsumeClassificationV1"),
    );
  }
}
