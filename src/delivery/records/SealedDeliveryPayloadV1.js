import {
  Hash,
  RRecord,
  base64ToBytes,
  requireCanonicalB64,
  requireE2eeDeliveryId,
} from "@rezprotocol/core";
import {
  assertExactRecordKeys,
  canonicalRecordBytes,
  parseRecordBytes,
} from "./recordShared.js";

export const SEALED_DELIVERY_PAYLOAD_VERSION = 1;
export const SEALED_DELIVERY_PAYLOAD_KIND = "rez.delivery.sealed-payload.v1";
export const SUPPORTED_SEALED_DELIVERY_PAYLOAD_VERSIONS = Object.freeze([1]);

const RECORD_KEYS = Object.freeze([
  "kind",
  "v",
  "deliveryId",
  "envelopeVersion",
  "sealedBytesB64",
]);

/**
 * Carrier-neutral identity for one already-sealed device/session payload.
 *
 * The replay digest is SHA-256 over toBytes(), before any carrier armor. The
 * record intentionally contains no target, locator, policy, or operation id.
 */
export class SealedDeliveryPayloadV1 extends RRecord {
  static type = "sdk.delivery.sealed_payload.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, RECORD_KEYS, "SealedDeliveryPayloadV1");
    this.kind = raw.kind == null ? SEALED_DELIVERY_PAYLOAD_KIND : raw.kind;
    this.v = raw.v == null ? SEALED_DELIVERY_PAYLOAD_VERSION : raw.v;
    this.deliveryId = raw.deliveryId;
    this.envelopeVersion = raw.envelopeVersion;
    this.sealedBytesB64 = raw.sealedBytesB64;
    this._seal();
  }

  validate() {
    this.assert(this.kind === SEALED_DELIVERY_PAYLOAD_KIND,
      "SealedDeliveryPayloadV1.kind must be " + SEALED_DELIVERY_PAYLOAD_KIND);
    this.assert(this.v === SEALED_DELIVERY_PAYLOAD_VERSION,
      "SealedDeliveryPayloadV1.v must be 1");
    requireE2eeDeliveryId(this.deliveryId, "SealedDeliveryPayloadV1.deliveryId");
    this.assert(Number.isSafeInteger(this.envelopeVersion) && this.envelopeVersion > 0,
      "SealedDeliveryPayloadV1.envelopeVersion must be a positive safe integer");
    requireCanonicalB64(this.sealedBytesB64, "SealedDeliveryPayloadV1.sealedBytesB64");
    this.assert(base64ToBytes(this.sealedBytesB64).length > 0,
      "SealedDeliveryPayloadV1.sealedBytesB64 must decode to non-empty bytes");
  }

  toBytes() {
    return canonicalRecordBytes(this);
  }

  sealedBytes() {
    return base64ToBytes(this.sealedBytesB64);
  }

  replayDigestHex() {
    return Hash.sha256Hex(this.toBytes());
  }

  static fromBytes(bytes) {
    return SealedDeliveryPayloadV1.fromJSON(
      parseRecordBytes(bytes, "SealedDeliveryPayloadV1"),
    );
  }
}

export function sealedDeliveryPayloadVersionOf(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  if (raw.kind !== SEALED_DELIVERY_PAYLOAD_KIND) return null;
  return Number.isInteger(raw.v) ? raw.v : null;
}

export function isSupportedSealedDeliveryPayloadVersion(version) {
  return SUPPORTED_SEALED_DELIVERY_PAYLOAD_VERSIONS.includes(version);
}
