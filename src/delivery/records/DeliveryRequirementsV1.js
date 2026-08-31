import { RRecord } from "@rezprotocol/core";
import {
  assertExactRecordKeys,
  canonicalRecordBytes,
  canonicalStringSet,
  parseRecordBytes,
} from "./recordShared.js";

export const DELIVERY_REQUIREMENTS_VERSION = 1;

export const DELIVERY_EXPIRY_MECHANISMS = Object.freeze([
  "envelope-absolute",
  "signed-absolute",
  "signed-created-plus-state-deadline",
  "none",
]);

export const DELIVERY_LATENCY_CLASSES = Object.freeze([
  "interactive",
  "background",
  "bulk",
]);

export const DELIVERY_ORDERING_LANE_CLASSES = Object.freeze([
  "ratchet-session",
  "owner-account-state",
  "owner-control",
]);

export const DELIVERY_RETURN_PATH_REQUIREMENTS = Object.freeze([
  "none",
  "policy-resolved",
]);

export const DELIVERY_ACK_REQUIREMENTS = Object.freeze([
  "none",
  "authenticated-commit",
  "legacy-delivery",
  "control-response",
]);

// DT-101 deliberately keeps Phase-1 records RezNet-only. A later carrier is
// admitted by a reviewed matrix amendment and a versioned contract change,
// never merely because an adapter registered itself.
export const DELIVERY_REQUIREMENTS_V1_PROFILE_IDS = Object.freeze([
  "reznet.default.v1",
  "reznet.legacy-unknown.v1",
  "reznet.onion-required.v1",
]);

const RECORD_KEYS = Object.freeze([
  "v",
  "expiryMechanism",
  "latencyClass",
  "orderingLaneClass",
  "returnPathRequirement",
  "ackRequirement",
  "maxPayloadBytes",
  "allowedProfileIds",
]);

export class DeliveryRequirementsV1 extends RRecord {
  static type = "sdk.delivery.requirements.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, RECORD_KEYS, "DeliveryRequirementsV1");
    this.v = raw.v == null ? DELIVERY_REQUIREMENTS_VERSION : raw.v;
    this.expiryMechanism = raw.expiryMechanism;
    this.latencyClass = raw.latencyClass;
    this.orderingLaneClass = raw.orderingLaneClass;
    this.returnPathRequirement = raw.returnPathRequirement;
    this.ackRequirement = raw.ackRequirement;
    this.maxPayloadBytes = raw.maxPayloadBytes;
    this.allowedProfileIds = canonicalStringSet(
      raw.allowedProfileIds,
      "DeliveryRequirementsV1.allowedProfileIds",
      { allowed: DELIVERY_REQUIREMENTS_V1_PROFILE_IDS },
    );
    this._seal();
  }

  validate() {
    this.assert(this.v === DELIVERY_REQUIREMENTS_VERSION,
      "DeliveryRequirementsV1.v must be 1");
    this.assert(DELIVERY_EXPIRY_MECHANISMS.includes(this.expiryMechanism),
      "DeliveryRequirementsV1.expiryMechanism is unsupported");
    this.assert(DELIVERY_LATENCY_CLASSES.includes(this.latencyClass),
      "DeliveryRequirementsV1.latencyClass is unsupported");
    this.assert(DELIVERY_ORDERING_LANE_CLASSES.includes(this.orderingLaneClass),
      "DeliveryRequirementsV1.orderingLaneClass is unsupported");
    this.assert(DELIVERY_RETURN_PATH_REQUIREMENTS.includes(this.returnPathRequirement),
      "DeliveryRequirementsV1.returnPathRequirement is unsupported");
    this.assert(DELIVERY_ACK_REQUIREMENTS.includes(this.ackRequirement),
      "DeliveryRequirementsV1.ackRequirement is unsupported");
    this.assert(Number.isSafeInteger(this.maxPayloadBytes) && this.maxPayloadBytes > 0,
      "DeliveryRequirementsV1.maxPayloadBytes must be a positive safe integer");
    this.assert(Array.isArray(this.allowedProfileIds) && this.allowedProfileIds.length > 0,
      "DeliveryRequirementsV1.allowedProfileIds must be non-empty");
  }

  toBytes() {
    return canonicalRecordBytes(this);
  }

  static fromBytes(bytes) {
    return DeliveryRequirementsV1.fromJSON(
      parseRecordBytes(bytes, "DeliveryRequirementsV1"),
    );
  }
}
