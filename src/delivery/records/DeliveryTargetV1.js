import {
  Hash,
  RRecord,
  base64ToBytes,
  requireCanonicalB64,
} from "@rezprotocol/core";
import {
  assertExactRecordKeys,
  canonicalRecordBytes,
  parseRecordBytes,
  requireSafeToken,
  requireSha256Hex,
  requireTransportInstanceId,
} from "./recordShared.js";

export const DELIVERY_TARGET_VERSION = 1;
export const MAX_DELIVERY_LOCATOR_BYTES = 4096;
export const VERSIONED_DELIVERY_LOCATOR_FORMAT =
  /^[A-Za-z0-9][A-Za-z0-9._:-]{0,118}\.v[1-9][0-9]{0,7}$/;

const RECORD_KEYS = Object.freeze([
  "v",
  "transportKind",
  "transportInstanceId",
  "locatorFormat",
  "locatorBytesB64",
  "locatorDigestHex",
  "bindingFingerprintHex",
]);

/**
 * One verified destination for one locally registered transport instance.
 *
 * The SDK can validate the locator's framing and integrity but never interprets
 * or logs its adapter-owned bytes. Credentials do not belong in this record.
 */
export class DeliveryTargetV1 extends RRecord {
  static type = "sdk.delivery.target.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, RECORD_KEYS, "DeliveryTargetV1");
    this.v = raw.v == null ? DELIVERY_TARGET_VERSION : raw.v;
    this.transportKind = raw.transportKind;
    this.transportInstanceId = raw.transportInstanceId;
    this.locatorFormat = raw.locatorFormat;
    this.locatorBytesB64 = raw.locatorBytesB64;
    this.locatorDigestHex = raw.locatorDigestHex;
    this.bindingFingerprintHex = raw.bindingFingerprintHex;
    this._seal();
  }

  validate() {
    this.assert(this.v === DELIVERY_TARGET_VERSION,
      "DeliveryTargetV1.v must be 1");
    requireSafeToken(this.transportKind, "DeliveryTargetV1.transportKind");
    requireTransportInstanceId(
      this.transportInstanceId,
      "DeliveryTargetV1.transportInstanceId",
    );
    requireSafeToken(this.locatorFormat, "DeliveryTargetV1.locatorFormat");
    this.assert(VERSIONED_DELIVERY_LOCATOR_FORMAT.test(this.locatorFormat),
      "DeliveryTargetV1.locatorFormat must end with an explicit positive .vN version");
    requireCanonicalB64(this.locatorBytesB64, "DeliveryTargetV1.locatorBytesB64");
    const locatorBytes = base64ToBytes(this.locatorBytesB64);
    this.assert(locatorBytes.length > 0 && locatorBytes.length <= MAX_DELIVERY_LOCATOR_BYTES,
      "DeliveryTargetV1.locatorBytesB64 must decode to 1..4096 bytes");
    requireSha256Hex(this.locatorDigestHex, "DeliveryTargetV1.locatorDigestHex");
    this.assert(this.locatorDigestHex === Hash.sha256Hex(locatorBytes),
      "DeliveryTargetV1.locatorDigestHex must match locator bytes");
    requireSha256Hex(
      this.bindingFingerprintHex,
      "DeliveryTargetV1.bindingFingerprintHex",
    );
  }

  toBytes() {
    return canonicalRecordBytes(this);
  }

  locatorBytes() {
    return base64ToBytes(this.locatorBytesB64);
  }

  static fromBytes(bytes) {
    return DeliveryTargetV1.fromJSON(parseRecordBytes(bytes, "DeliveryTargetV1"));
  }
}

export function newTransportInstanceId(randomBytes) {
  return RRecord.newId("trinst", randomBytes);
}
