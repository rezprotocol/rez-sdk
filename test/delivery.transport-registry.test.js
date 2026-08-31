import test from "node:test";
import assert from "node:assert/strict";
import {
  DeliverySecurityProfileV1,
  DeliveryTransportDescriptorV1,
  DeliveryTransportRegistry,
  RDeliveryTransport,
} from "@rezprotocol/sdk/delivery";

function profileInput(overrides = {}) {
  return {
    profileId: "reznet.default.v1",
    profileVersion: 1,
    transportKind: "reznet",
    contentProtection: "rez-e2ee-required",
    senderRecipientLinkability: "single-operator-visible",
    recipientLocatorExposure: "opaque-inbox",
    senderLocatorExposure: "opaque-inbox",
    routingPrivacy: "rez-default",
    storageTrust: "rez-opaque-store",
    routeDistribution: "single-operator",
    storeAndForward: true,
    retentionClass: "bounded-durable",
    supportsOfflineRecipient: true,
    custodyStages: ["carrier-accepted", "carrier-stored"],
    maxPayloadBytes: 65_536,
    paddingBehavior: "none",
    maxDeliveryAgeMs: 604_800_000,
    timingLeakage: "high",
    sizeLeakage: "high",
    addressEnumerationRisk: "low",
    requiresLocalSecrets: true,
    secretsOwner: "sdk",
    ...overrides,
  };
}

function descriptorFor(profile, transportInstanceId) {
  return new DeliveryTransportDescriptorV1({
    transportKind: profile.transportKind,
    transportInstanceId,
    profileId: profile.profileId,
    profileVersion: profile.profileVersion,
    profileFingerprintHex: profile.profileFingerprintHex,
    maxPayloadBytes: profile.maxPayloadBytes,
    maxDeliveryAgeMs: profile.maxDeliveryAgeMs,
    custodyStages: profile.custodyStages,
    idempotencyMode: profile.profileId === "fake.test.v1"
      ? "transport-scoped-token"
      : "reznet-custody-key",
  });
}

class TestTransport extends RDeliveryTransport {
  #descriptor;

  constructor(descriptor) {
    super();
    this.#descriptor = descriptor;
  }

  descriptor() { return this.#descriptor; }
}

test("DeliveryTransportRegistry accepts only an exact trusted immutable snapshot", () => {
  const profile = new DeliverySecurityProfileV1(profileInput());
  const descriptor = descriptorFor(
    profile,
    "trinst_0123456789abcdef0123456789abcdef",
  );
  const transport = new TestTransport(descriptor);
  const registry = new DeliveryTransportRegistry("test");
  assert.equal(registry.register(transport, profile), descriptor);
  assert.equal(registry.transport(descriptor.transportInstanceId), transport);
  assert.equal(registry.descriptor(descriptor.transportInstanceId), descriptor);
  assert.equal(registry.profileForInstance(descriptor.transportInstanceId), profile);
  assert.equal(registry.profileByFingerprint(profile.profileFingerprintHex), profile);
  assert.throws(() => registry.register(transport, profile), /duplicate/);
});

test("DeliveryTransportRegistry rejects adapter/profile drift", () => {
  const profile = new DeliverySecurityProfileV1(profileInput());
  const differentProfile = new DeliverySecurityProfileV1({
    ...profileInput(),
    routingPrivacy: "onion-enforced",
    routeDistribution: "distributed",
  });
  const registry = new DeliveryTransportRegistry("test");
  assert.throws(() => registry.register(new TestTransport(descriptorFor(
    profile,
    "trinst_11111111111111111111111111111111",
  )), differentProfile), /identity mismatch/);

  const weakDescriptor = new DeliveryTransportDescriptorV1({
    ...descriptorFor(
      profile,
      "trinst_22222222222222222222222222222222",
    ).toJSON(),
    maxPayloadBytes: 1024,
  });
  assert.throws(() => registry.register(
    new TestTransport(weakDescriptor),
    profile,
  ), /capability mismatch/);
  assert.throws(() => registry.register({ descriptor() {} }, profile), /RDeliveryTransport/);
});

test("DeliveryTransportRegistry gates test-only profiles out of production", () => {
  const profile = new DeliverySecurityProfileV1(profileInput({
    profileId: "fake.test.v1",
    transportKind: "fake",
    routingPrivacy: "test-only",
    routeDistribution: "test-only",
    storageTrust: "local-volatile",
    retentionClass: "volatile",
    requiresLocalSecrets: false,
    secretsOwner: "none",
  }));
  const transport = new TestTransport(descriptorFor(
    profile,
    "trinst_33333333333333333333333333333333",
  ));
  assert.throws(
    () => new DeliveryTransportRegistry("production").register(transport, profile),
    /test-only/,
  );
  assert.doesNotThrow(
    () => new DeliveryTransportRegistry("test").register(transport, profile),
  );
});
