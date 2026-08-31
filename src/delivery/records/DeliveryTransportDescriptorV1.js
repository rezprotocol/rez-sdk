import { RRecord } from "@rezprotocol/core";
import {
  DELIVERY_CUSTODY_STAGES,
} from "./DeliverySecurityProfileV1.js";
import {
  assertExactRecordKeys,
  canonicalRecordBytes,
  canonicalStringSet,
  parseRecordBytes,
  requireSafeToken,
  requireSha256Hex,
  requireTransportInstanceId,
} from "./recordShared.js";

export const DELIVERY_TRANSPORT_DESCRIPTOR_VERSION = 1;
export const DELIVERY_IDEMPOTENCY_MODES = Object.freeze([
  "none",
  "transport-scoped-token",
  "reznet-custody-key",
]);

const RECORD_KEYS = Object.freeze([
  "v",
  "transportKind",
  "transportInstanceId",
  "profileId",
  "profileVersion",
  "profileFingerprintHex",
  "maxPayloadBytes",
  "maxDeliveryAgeMs",
  "custodyStages",
  "idempotencyMode",
]);

/** Immutable mechanical declaration for one constructed adapter instance. */
export class DeliveryTransportDescriptorV1 extends RRecord {
  static type = "sdk.delivery.transport_descriptor.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, RECORD_KEYS, "DeliveryTransportDescriptorV1");
    this.v = raw.v == null ? DELIVERY_TRANSPORT_DESCRIPTOR_VERSION : raw.v;
    this.transportKind = raw.transportKind;
    this.transportInstanceId = raw.transportInstanceId;
    this.profileId = raw.profileId;
    this.profileVersion = raw.profileVersion;
    this.profileFingerprintHex = raw.profileFingerprintHex;
    this.maxPayloadBytes = raw.maxPayloadBytes;
    this.maxDeliveryAgeMs = raw.maxDeliveryAgeMs;
    this.custodyStages = canonicalStringSet(
      raw.custodyStages,
      "DeliveryTransportDescriptorV1.custodyStages",
      { allowed: DELIVERY_CUSTODY_STAGES, allowEmpty: true },
    );
    this.idempotencyMode = raw.idempotencyMode;
    this._seal();
  }

  validate() {
    this.assert(this.v === DELIVERY_TRANSPORT_DESCRIPTOR_VERSION,
      "DeliveryTransportDescriptorV1.v must be 1");
    requireSafeToken(
      this.transportKind,
      "DeliveryTransportDescriptorV1.transportKind",
    );
    requireTransportInstanceId(
      this.transportInstanceId,
      "DeliveryTransportDescriptorV1.transportInstanceId",
    );
    requireSafeToken(this.profileId, "DeliveryTransportDescriptorV1.profileId");
    this.assert(Number.isSafeInteger(this.profileVersion) && this.profileVersion > 0,
      "DeliveryTransportDescriptorV1.profileVersion must be a positive safe integer");
    this.assert(this.profileId.endsWith(".v" + this.profileVersion),
      "DeliveryTransportDescriptorV1.profileId must end with its profile version");
    requireSha256Hex(
      this.profileFingerprintHex,
      "DeliveryTransportDescriptorV1.profileFingerprintHex",
    );
    this.assert(Number.isSafeInteger(this.maxPayloadBytes) && this.maxPayloadBytes > 0,
      "DeliveryTransportDescriptorV1.maxPayloadBytes must be a positive safe integer");
    this.assert(Number.isSafeInteger(this.maxDeliveryAgeMs) && this.maxDeliveryAgeMs >= 0,
      "DeliveryTransportDescriptorV1.maxDeliveryAgeMs must be a non-negative safe integer");
    this.assert(DELIVERY_IDEMPOTENCY_MODES.includes(this.idempotencyMode),
      "DeliveryTransportDescriptorV1.idempotencyMode is unsupported");
  }

  toBytes() {
    return canonicalRecordBytes(this);
  }

  static fromBytes(bytes) {
    return DeliveryTransportDescriptorV1.fromJSON(
      parseRecordBytes(bytes, "DeliveryTransportDescriptorV1"),
    );
  }
}
