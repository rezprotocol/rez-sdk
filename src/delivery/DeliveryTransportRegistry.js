import { RObject } from "@rezprotocol/core";
import { RDeliveryTransport } from "./RDeliveryTransport.js";
import { DeliverySecurityProfileV1 } from "./records/DeliverySecurityProfileV1.js";
import { DeliveryTransportDescriptorV1 } from "./records/DeliveryTransportDescriptorV1.js";

export const DELIVERY_REGISTRY_ENVIRONMENTS = Object.freeze([
  "development",
  "test",
  "production",
]);

/**
 * Local immutable registry. Registration supplies the trusted profile; adapter
 * descriptors only prove they were constructed for that exact snapshot.
 */
export class DeliveryTransportRegistry extends RObject {
  static type = "sdk.delivery.transport_registry";

  #environment;
  #transports = new Map();
  #descriptors = new Map();
  #profileFingerprintByInstance = new Map();
  #profilesByFingerprint = new Map();

  constructor(environment = "development") {
    super();
    if (!DELIVERY_REGISTRY_ENVIRONMENTS.includes(environment)) {
      throw new Error("DeliveryTransportRegistry environment is unsupported");
    }
    this.#environment = environment;
  }

  register(transport, trustedProfile) {
    if (!(transport instanceof RDeliveryTransport)) {
      throw new Error("DeliveryTransportRegistry requires RDeliveryTransport");
    }
    if (!(trustedProfile instanceof DeliverySecurityProfileV1)) {
      throw new Error("DeliveryTransportRegistry requires trusted DeliverySecurityProfileV1");
    }
    const descriptor = transport.descriptor();
    if (!(descriptor instanceof DeliveryTransportDescriptorV1)) {
      throw new Error("delivery transport descriptor() must return DeliveryTransportDescriptorV1");
    }
    if (this.#transports.has(descriptor.transportInstanceId)) {
      throw new Error("duplicate delivery transport instance: " + descriptor.transportInstanceId);
    }
    this.#assertProfileMatch(descriptor, trustedProfile);
    if (this.#environment === "production" && this.#isTestOnly(trustedProfile)) {
      throw new Error("test-only delivery profiles cannot register in production");
    }

    const existingProfile = this.#profilesByFingerprint.get(trustedProfile.profileFingerprintHex);
    if (existingProfile && !this.#sameBytes(existingProfile.toBytes(), trustedProfile.toBytes())) {
      throw new Error("delivery profile fingerprint collision");
    }
    this.#profilesByFingerprint.set(trustedProfile.profileFingerprintHex, trustedProfile);
    this.#transports.set(descriptor.transportInstanceId, transport);
    this.#descriptors.set(descriptor.transportInstanceId, descriptor);
    this.#profileFingerprintByInstance.set(
      descriptor.transportInstanceId,
      trustedProfile.profileFingerprintHex,
    );
    return descriptor;
  }

  has(transportInstanceId) {
    return this.#transports.has(transportInstanceId);
  }

  transport(transportInstanceId) {
    return this.#requireInstanceValue(this.#transports, transportInstanceId);
  }

  descriptor(transportInstanceId) {
    return this.#requireInstanceValue(this.#descriptors, transportInstanceId);
  }

  profileForInstance(transportInstanceId) {
    const fingerprint = this.#requireInstanceValue(
      this.#profileFingerprintByInstance,
      transportInstanceId,
    );
    return this.profileByFingerprint(fingerprint);
  }

  profileByFingerprint(profileFingerprintHex) {
    const profile = this.#profilesByFingerprint.get(profileFingerprintHex);
    if (!profile) throw new Error("unknown delivery security profile fingerprint");
    return profile;
  }

  #assertProfileMatch(descriptor, profile) {
    if (descriptor.transportKind !== profile.transportKind
      || descriptor.profileId !== profile.profileId
      || descriptor.profileVersion !== profile.profileVersion
      || descriptor.profileFingerprintHex !== profile.profileFingerprintHex) {
      throw new Error("delivery transport descriptor/profile identity mismatch");
    }
    if (descriptor.maxPayloadBytes !== profile.maxPayloadBytes
      || descriptor.maxDeliveryAgeMs !== profile.maxDeliveryAgeMs
      || descriptor.custodyStages.length !== profile.custodyStages.length
      || descriptor.custodyStages.some((value, index) => value !== profile.custodyStages[index])) {
      throw new Error("delivery transport descriptor/profile capability mismatch");
    }
  }

  #isTestOnly(profile) {
    return profile.profileId === "fake.test.v1"
      || profile.routingPrivacy === "test-only"
      || profile.routeDistribution === "test-only";
  }

  #requireInstanceValue(map, transportInstanceId) {
    const value = map.get(transportInstanceId);
    if (!value) throw new Error("unknown delivery transport instance: " + transportInstanceId);
    return value;
  }

  #sameBytes(left, right) {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index += 1) {
      if (left[index] !== right[index]) return false;
    }
    return true;
  }
}
