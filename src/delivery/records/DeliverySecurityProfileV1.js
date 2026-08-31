import {
  Hash,
  RRecord,
  canonicalJSONStringify,
} from "@rezprotocol/core";
import {
  assertExactRecordKeys,
  canonicalRecordBytes,
  canonicalStringSet,
  parseRecordBytes,
  requireSafeToken,
  requireSha256Hex,
} from "./recordShared.js";

export const DELIVERY_SECURITY_PROFILE_VERSION = 1;
export const DELIVERY_SECURITY_PROFILE_FINGERPRINT_DOMAIN =
  "rez.delivery-security-profile-fingerprint.v1\0";

export const CONTENT_PROTECTION_VALUES = Object.freeze(["rez-e2ee-required"]);
export const SENDER_RECIPIENT_LINKABILITY_VALUES = Object.freeze([
  "separated",
  "single-operator-visible",
  "foreign-service-visible",
  "local-observer-visible",
]);
export const LOCATOR_EXPOSURE_VALUES = Object.freeze([
  "none",
  "opaque-inbox",
  "carrier-account",
  "workspace-member",
  "radio-address",
]);
export const ROUTING_PRIVACY_VALUES = Object.freeze([
  "onion-enforced",
  "rez-default",
  "foreign-centralized",
  "local-proximity",
  "test-only",
]);
export const STORAGE_TRUST_VALUES = Object.freeze([
  "rez-opaque-store",
  "foreign-opaque-store",
  "local-volatile",
  "none",
]);
export const ROUTE_DISTRIBUTION_VALUES = Object.freeze([
  "distributed",
  "single-operator",
  "local-peer",
  "test-only",
]);
export const RETENTION_CLASS_VALUES = Object.freeze([
  "none",
  "volatile",
  "bounded-durable",
  "provider-controlled",
]);
export const DELIVERY_CUSTODY_STAGES = Object.freeze([
  "carrier-accepted",
  "carrier-stored",
  "recipient-bridge-received",
]);
export const PADDING_BEHAVIOR_VALUES = Object.freeze([
  "none",
  "fixed-block",
  "constant-size",
]);
export const LEAKAGE_VALUES = Object.freeze(["low", "medium", "high"]);
export const SECRETS_OWNER_VALUES = Object.freeze(["none", "sdk", "adapter"]);

const BODY_KEYS = Object.freeze([
  "v",
  "profileId",
  "profileVersion",
  "transportKind",
  "contentProtection",
  "senderRecipientLinkability",
  "recipientLocatorExposure",
  "senderLocatorExposure",
  "routingPrivacy",
  "storageTrust",
  "routeDistribution",
  "storeAndForward",
  "retentionClass",
  "supportsOfflineRecipient",
  "custodyStages",
  "maxPayloadBytes",
  "paddingBehavior",
  "maxDeliveryAgeMs",
  "timingLeakage",
  "sizeLeakage",
  "addressEnumerationRisk",
  "requiresLocalSecrets",
  "secretsOwner",
]);
const RECORD_KEYS = Object.freeze([...BODY_KEYS, "profileFingerprintHex"]);

function bodyOf(record) {
  const body = {};
  for (const key of BODY_KEYS) body[key] = record[key];
  return body;
}

function deliverySecurityProfileFingerprintHex(body) {
  return Hash.sha256Hex(
    DELIVERY_SECURITY_PROFILE_FINGERPRINT_DOMAIN + canonicalJSONStringify(body),
  );
}

function requireEnum(value, allowed, label) {
  if (!allowed.includes(value)) throw new Error(label + " is unsupported");
}

/** Immutable, trusted registration snapshot. */
export class DeliverySecurityProfileV1 extends RRecord {
  static type = "sdk.delivery.security_profile.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, RECORD_KEYS, "DeliverySecurityProfileV1");
    this.v = raw.v == null ? DELIVERY_SECURITY_PROFILE_VERSION : raw.v;
    this.profileId = raw.profileId;
    this.profileVersion = raw.profileVersion;
    this.transportKind = raw.transportKind;
    this.contentProtection = raw.contentProtection;
    this.senderRecipientLinkability = raw.senderRecipientLinkability;
    this.recipientLocatorExposure = raw.recipientLocatorExposure;
    this.senderLocatorExposure = raw.senderLocatorExposure;
    this.routingPrivacy = raw.routingPrivacy;
    this.storageTrust = raw.storageTrust;
    this.routeDistribution = raw.routeDistribution;
    this.storeAndForward = raw.storeAndForward;
    this.retentionClass = raw.retentionClass;
    this.supportsOfflineRecipient = raw.supportsOfflineRecipient;
    this.custodyStages = canonicalStringSet(
      raw.custodyStages,
      "DeliverySecurityProfileV1.custodyStages",
      { allowed: DELIVERY_CUSTODY_STAGES, allowEmpty: true },
    );
    this.maxPayloadBytes = raw.maxPayloadBytes;
    this.paddingBehavior = raw.paddingBehavior;
    this.maxDeliveryAgeMs = raw.maxDeliveryAgeMs;
    this.timingLeakage = raw.timingLeakage;
    this.sizeLeakage = raw.sizeLeakage;
    this.addressEnumerationRisk = raw.addressEnumerationRisk;
    this.requiresLocalSecrets = raw.requiresLocalSecrets;
    this.secretsOwner = raw.secretsOwner;
    const derivedFingerprint = deliverySecurityProfileFingerprintHex(bodyOf(this));
    this.profileFingerprintHex = raw.profileFingerprintHex == null
      ? derivedFingerprint
      : raw.profileFingerprintHex;
    this._seal();
  }

  validate() {
    this.assert(this.v === DELIVERY_SECURITY_PROFILE_VERSION,
      "DeliverySecurityProfileV1.v must be 1");
    requireSafeToken(this.profileId, "DeliverySecurityProfileV1.profileId");
    this.assert(Number.isSafeInteger(this.profileVersion) && this.profileVersion > 0,
      "DeliverySecurityProfileV1.profileVersion must be a positive safe integer");
    this.assert(this.profileId.endsWith(".v" + this.profileVersion),
      "DeliverySecurityProfileV1.profileId must end with its profile version");
    requireSafeToken(this.transportKind, "DeliverySecurityProfileV1.transportKind");
    requireEnum(this.contentProtection, CONTENT_PROTECTION_VALUES,
      "DeliverySecurityProfileV1.contentProtection");
    requireEnum(this.senderRecipientLinkability, SENDER_RECIPIENT_LINKABILITY_VALUES,
      "DeliverySecurityProfileV1.senderRecipientLinkability");
    requireEnum(this.recipientLocatorExposure, LOCATOR_EXPOSURE_VALUES,
      "DeliverySecurityProfileV1.recipientLocatorExposure");
    requireEnum(this.senderLocatorExposure, LOCATOR_EXPOSURE_VALUES,
      "DeliverySecurityProfileV1.senderLocatorExposure");
    requireEnum(this.routingPrivacy, ROUTING_PRIVACY_VALUES,
      "DeliverySecurityProfileV1.routingPrivacy");
    requireEnum(this.storageTrust, STORAGE_TRUST_VALUES,
      "DeliverySecurityProfileV1.storageTrust");
    requireEnum(this.routeDistribution, ROUTE_DISTRIBUTION_VALUES,
      "DeliverySecurityProfileV1.routeDistribution");
    this.assert(typeof this.storeAndForward === "boolean",
      "DeliverySecurityProfileV1.storeAndForward must be boolean");
    requireEnum(this.retentionClass, RETENTION_CLASS_VALUES,
      "DeliverySecurityProfileV1.retentionClass");
    this.assert(typeof this.supportsOfflineRecipient === "boolean",
      "DeliverySecurityProfileV1.supportsOfflineRecipient must be boolean");
    this.assert(Array.isArray(this.custodyStages),
      "DeliverySecurityProfileV1.custodyStages must be an array");
    this.assert(Number.isSafeInteger(this.maxPayloadBytes) && this.maxPayloadBytes > 0,
      "DeliverySecurityProfileV1.maxPayloadBytes must be a positive safe integer");
    requireEnum(this.paddingBehavior, PADDING_BEHAVIOR_VALUES,
      "DeliverySecurityProfileV1.paddingBehavior");
    this.assert(Number.isSafeInteger(this.maxDeliveryAgeMs) && this.maxDeliveryAgeMs >= 0,
      "DeliverySecurityProfileV1.maxDeliveryAgeMs must be a non-negative safe integer");
    requireEnum(this.timingLeakage, LEAKAGE_VALUES,
      "DeliverySecurityProfileV1.timingLeakage");
    requireEnum(this.sizeLeakage, LEAKAGE_VALUES,
      "DeliverySecurityProfileV1.sizeLeakage");
    requireEnum(this.addressEnumerationRisk, LEAKAGE_VALUES,
      "DeliverySecurityProfileV1.addressEnumerationRisk");
    this.assert(typeof this.requiresLocalSecrets === "boolean",
      "DeliverySecurityProfileV1.requiresLocalSecrets must be boolean");
    requireEnum(this.secretsOwner, SECRETS_OWNER_VALUES,
      "DeliverySecurityProfileV1.secretsOwner");

    this.assert(this.storeAndForward || this.retentionClass === "none",
      "DeliverySecurityProfileV1.retentionClass must be none without store-and-forward");
    this.assert(!this.storeAndForward || this.retentionClass !== "none",
      "DeliverySecurityProfileV1.retentionClass must be explicit with store-and-forward");
    this.assert(!this.supportsOfflineRecipient || this.storeAndForward,
      "DeliverySecurityProfileV1 offline support requires store-and-forward");
    this.assert(this.storeAndForward || this.maxDeliveryAgeMs === 0,
      "DeliverySecurityProfileV1.maxDeliveryAgeMs must be zero without store-and-forward");
    this.assert(!this.storeAndForward || this.maxDeliveryAgeMs > 0,
      "DeliverySecurityProfileV1.maxDeliveryAgeMs must be positive with store-and-forward");
    this.assert(this.requiresLocalSecrets || this.secretsOwner === "none",
      "DeliverySecurityProfileV1.secretsOwner must be none when local secrets are not required");
    this.assert(!this.requiresLocalSecrets || this.secretsOwner !== "none",
      "DeliverySecurityProfileV1.secretsOwner must identify the local owner");

    requireSha256Hex(
      this.profileFingerprintHex,
      "DeliverySecurityProfileV1.profileFingerprintHex",
    );
    this.assert(
      this.profileFingerprintHex === deliverySecurityProfileFingerprintHex(bodyOf(this)),
      "DeliverySecurityProfileV1.profileFingerprintHex must match the canonical profile body",
    );
  }

  fingerprintBodyBytes() {
    return new TextEncoder().encode(canonicalJSONStringify(bodyOf(this)));
  }

  fingerprintHex() {
    return this.profileFingerprintHex;
  }

  toBytes() {
    return canonicalRecordBytes(this);
  }

  static fromBytes(bytes) {
    return DeliverySecurityProfileV1.fromJSON(
      parseRecordBytes(bytes, "DeliverySecurityProfileV1"),
    );
  }
}
