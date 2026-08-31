import { RObject } from "@rezprotocol/core";
import {
  CONTENT_PROTECTION_VALUES,
  LEAKAGE_VALUES,
  LOCATOR_EXPOSURE_VALUES,
  ROUTE_DISTRIBUTION_VALUES,
  ROUTING_PRIVACY_VALUES,
  SENDER_RECIPIENT_LINKABILITY_VALUES,
  STORAGE_TRUST_VALUES,
} from "./records/DeliverySecurityProfileV1.js";

const ORDERED_CHAINS = Object.freeze({
  contentProtection: Object.freeze([
    Object.freeze([...CONTENT_PROTECTION_VALUES]),
  ]),
  senderRecipientLinkability: Object.freeze([
    Object.freeze(["separated", "single-operator-visible", "foreign-service-visible"]),
    Object.freeze(["separated", "single-operator-visible", "local-observer-visible"]),
  ]),
  routingPrivacy: Object.freeze([
    Object.freeze(["onion-enforced", "rez-default", "foreign-centralized"]),
    Object.freeze(["onion-enforced", "rez-default", "local-proximity"]),
  ]),
  routeDistribution: Object.freeze([
    Object.freeze(["distributed", "single-operator"]),
    Object.freeze(["distributed", "local-peer"]),
  ]),
  timingLeakage: Object.freeze([Object.freeze([...LEAKAGE_VALUES])]),
  sizeLeakage: Object.freeze([Object.freeze([...LEAKAGE_VALUES])]),
  addressEnumerationRisk: Object.freeze([Object.freeze([...LEAKAGE_VALUES])]),
});

const SET_DIMENSIONS = Object.freeze({
  recipientLocatorExposure: LOCATOR_EXPOSURE_VALUES,
  senderLocatorExposure: LOCATOR_EXPOSURE_VALUES,
  storageTrust: STORAGE_TRUST_VALUES,
});

function requireKnownValue(value, allowed, label) {
  if (!allowed.includes(value)) throw new Error(label + " is unsupported");
}

/**
 * Dimension-specific security comparison. No aggregate score or lexical/enum
 * ordering exists; incomparable values return false.
 */
export class DeliverySecurityProfileEvaluator extends RObject {
  static type = "sdk.delivery.security_profile_evaluator";

  satisfiesMinimum(dimension, actual, required) {
    const chains = ORDERED_CHAINS[dimension];
    if (!chains) {
      if (SET_DIMENSIONS[dimension]) {
        throw new Error(dimension + " has acceptable-set semantics");
      }
      throw new Error("unsupported ordered security dimension: " + dimension);
    }
    if (actual === "test-only" || required === "test-only") return false;
    for (const chain of chains) {
      const actualIndex = chain.indexOf(actual);
      const requiredIndex = chain.indexOf(required);
      if (actualIndex !== -1 && requiredIndex !== -1) {
        return actualIndex <= requiredIndex;
      }
    }
    const vocabulary = dimension === "senderRecipientLinkability"
      ? SENDER_RECIPIENT_LINKABILITY_VALUES
      : dimension === "routingPrivacy"
        ? ROUTING_PRIVACY_VALUES
        : dimension === "routeDistribution"
          ? ROUTE_DISTRIBUTION_VALUES
          : dimension === "contentProtection"
            ? CONTENT_PROTECTION_VALUES
            : LEAKAGE_VALUES;
    requireKnownValue(actual, vocabulary, dimension + " actual value");
    requireKnownValue(required, vocabulary, dimension + " required value");
    return false;
  }

  isAcceptable(dimension, actual, acceptableValues) {
    const vocabulary = SET_DIMENSIONS[dimension];
    if (!vocabulary) {
      if (ORDERED_CHAINS[dimension]) {
        throw new Error(dimension + " has ordered semantics");
      }
      throw new Error("unsupported acceptable-set security dimension: " + dimension);
    }
    requireKnownValue(actual, vocabulary, dimension + " actual value");
    if (!Array.isArray(acceptableValues) || acceptableValues.length === 0) {
      throw new Error(dimension + " acceptable values must be a non-empty array");
    }
    for (const value of acceptableValues) {
      requireKnownValue(value, vocabulary, dimension + " acceptable value");
    }
    return acceptableValues.includes(actual);
  }
}
