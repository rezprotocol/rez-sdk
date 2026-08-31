import test from "node:test";
import assert from "node:assert/strict";
import { Hash, bytesToBase64 } from "@rezprotocol/core";
import {
  CONSUME_CLASSIFICATIONS,
  ConsumeClassificationV1,
  DeliveryRequirementsV1,
  DeliverySecurityProfileEvaluator,
  DeliverySecurityProfileV1,
  DeliveryTargetV1,
  DeliveryTransportDescriptorV1,
  SealedDeliveryPayloadV1,
  isSupportedSealedDeliveryPayloadVersion,
  newTransportInstanceId,
  sealedDeliveryPayloadVersionOf,
} from "@rezprotocol/sdk/delivery";

const SEALED_GOLDEN = "{\"deliveryId\":\"dlv_0123456789abcdef\",\"envelopeVersion\":1,\"kind\":\"rez.delivery.sealed-payload.v1\",\"sealedBytesB64\":\"AQIDBA==\",\"v\":1}";

function requirementsInput() {
  return {
    expiryMechanism: "envelope-absolute",
    latencyClass: "interactive",
    orderingLaneClass: "ratchet-session",
    returnPathRequirement: "policy-resolved",
    ackRequirement: "authenticated-commit",
    maxPayloadBytes: 65_536,
    allowedProfileIds: ["reznet.onion-required.v1", "reznet.default.v1"],
  };
}

function profileInput() {
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
    custodyStages: ["carrier-stored", "carrier-accepted"],
    maxPayloadBytes: 65_536,
    paddingBehavior: "none",
    maxDeliveryAgeMs: 604_800_000,
    timingLeakage: "high",
    sizeLeakage: "high",
    addressEnumerationRisk: "low",
    requiresLocalSecrets: true,
    secretsOwner: "sdk",
  };
}

test("SealedDeliveryPayloadV1 freezes carrier-neutral canonical bytes and replay digest", () => {
  const record = new SealedDeliveryPayloadV1({
    deliveryId: "dlv_0123456789abcdef",
    envelopeVersion: 1,
    sealedBytesB64: "AQIDBA==",
  });
  assert.equal(new TextDecoder().decode(record.toBytes()), SEALED_GOLDEN);
  assert.deepEqual([...record.sealedBytes()], [1, 2, 3, 4]);
  assert.equal(record.replayDigestHex(), Hash.sha256Hex(new TextEncoder().encode(SEALED_GOLDEN)));
  assert.deepEqual(SealedDeliveryPayloadV1.fromBytes(record.toBytes()).toJSON(), record.toJSON());
  assert.deepEqual(Object.keys(record.toJSON()).sort(), [
    "deliveryId", "envelopeVersion", "kind", "sealedBytesB64", "v",
  ]);
});

test("SealedDeliveryPayloadV1 version negotiation is explicit and schema is fail-closed", () => {
  assert.equal(sealedDeliveryPayloadVersionOf({ kind: "rez.delivery.sealed-payload.v1", v: 1 }), 1);
  assert.equal(sealedDeliveryPayloadVersionOf({ kind: "rez.delivery.sealed-payload.v1", v: "1" }), null);
  assert.equal(sealedDeliveryPayloadVersionOf({ kind: "rez.encrypted.v1", v: 1 }), null);
  assert.equal(isSupportedSealedDeliveryPayloadVersion(1), true);
  assert.equal(isSupportedSealedDeliveryPayloadVersion(2), false);
  assert.throws(() => new SealedDeliveryPayloadV1({
    deliveryId: "bad id",
    envelopeVersion: 1,
    sealedBytesB64: "AQIDBA==",
  }), /deliveryId/);
  assert.throws(() => new SealedDeliveryPayloadV1({
    deliveryId: "dlv_ok",
    envelopeVersion: 1,
    sealedBytesB64: "AQIDBA==",
    transportId: "smtp",
  }), /unknown field/);
  const hostile = SEALED_GOLDEN.slice(0, -1) + ',"__proto__":{"admin":true}}';
  assert.throws(
    () => SealedDeliveryPayloadV1.fromBytes(new TextEncoder().encode(hostile)),
    (err) => err && err.code === "UNSAFE_JSON_KEY",
  );
});

test("DeliveryRequirementsV1 canonicalizes its reviewed RezNet profile set", () => {
  const record = new DeliveryRequirementsV1(requirementsInput());
  assert.deepEqual(record.allowedProfileIds, [
    "reznet.default.v1",
    "reznet.onion-required.v1",
  ]);
  const decoded = DeliveryRequirementsV1.fromBytes(record.toBytes());
  assert.deepEqual(decoded.toJSON(), record.toJSON());
  assert.ok(Object.isFrozen(record.allowedProfileIds));
});

test("DeliveryRequirementsV1 rejects invented vocabulary and implicit foreign eligibility", () => {
  assert.throws(() => new DeliveryRequirementsV1({
    ...requirementsInput(),
    expiryMechanism: "carrier-timestamp",
  }), /expiryMechanism/);
  assert.throws(() => new DeliveryRequirementsV1({
    ...requirementsInput(),
    orderingLaneClass: "adapter-hint",
  }), /orderingLaneClass/);
  assert.throws(() => new DeliveryRequirementsV1({
    ...requirementsInput(),
    allowedProfileIds: ["smtp-imap.foreign.v1"],
  }), /unsupported value/);
  assert.throws(() => new DeliveryRequirementsV1({
    ...requirementsInput(),
    operationId: "op_secret",
  }), /unknown field/);
});

test("ConsumeClassificationV1 accepts only the frozen consume outcomes", () => {
  for (const classification of CONSUME_CLASSIFICATIONS) {
    const record = new ConsumeClassificationV1({ classification });
    assert.equal(
      ConsumeClassificationV1.fromBytes(record.toBytes()).classification,
      classification,
    );
  }
  assert.throws(
    () => new ConsumeClassificationV1({ classification: "settled" }),
    /classification/,
  );
  assert.throws(
    () => new ConsumeClassificationV1({ classification: "consumed", settlementReference: "mail-1" }),
    /unknown field/,
  );
});

test("DeliveryTargetV1 separates kind, immutable instance, and opaque locator", () => {
  const locatorBytes = new TextEncoder().encode("rez-inbox-1");
  const target = new DeliveryTargetV1({
    transportKind: "reznet",
    transportInstanceId: "trinst_0123456789abcdef0123456789abcdef",
    locatorFormat: "reznet.inbox.v1",
    locatorBytesB64: bytesToBase64(locatorBytes),
    locatorDigestHex: Hash.sha256Hex(locatorBytes),
    bindingFingerprintHex: "ab".repeat(32),
  });
  assert.equal(target.transportKind, "reznet");
  assert.equal(new TextDecoder().decode(target.locatorBytes()), "rez-inbox-1");
  assert.deepEqual(DeliveryTargetV1.fromBytes(target.toBytes()).toJSON(), target.toJSON());
  assert.equal(
    newTransportInstanceId(() => Uint8Array.from({ length: 16 }, (_, index) => index)),
    "trinst_000102030405060708090a0b0c0d0e0f",
  );
  assert.throws(() => new DeliveryTargetV1({
    ...target.toJSON(),
    transportInstanceId: "reznet",
  }), /transportInstanceId/);
  assert.throws(() => new DeliveryTargetV1({
    ...target.toJSON(),
    locatorDigestHex: "cd".repeat(32),
  }), /must match locator bytes/);
  assert.throws(() => new DeliveryTargetV1({
    ...target.toJSON(),
    locatorFormat: "reznet.inbox",
  }), /explicit positive \.vN version/);
  assert.throws(() => new DeliveryTargetV1({
    ...target.toJSON(),
    rawInboxId: "secret-address",
  }), /unknown field/);
});

test("DeliverySecurityProfileV1 freezes exact canonical claims and fingerprint", () => {
  const profile = new DeliverySecurityProfileV1(profileInput());
  assert.deepEqual(profile.custodyStages, ["carrier-accepted", "carrier-stored"]);
  assert.equal(
    profile.profileFingerprintHex,
    "33261796cf46dc52759adf6fbe981332f9de3c3968fa143bb23b815f22f95e89",
  );
  assert.equal(profile.fingerprintHex(), profile.profileFingerprintHex);
  assert.deepEqual(
    DeliverySecurityProfileV1.fromBytes(profile.toBytes()).toJSON(),
    profile.toJSON(),
  );
  assert.throws(() => new DeliverySecurityProfileV1({
    ...profileInput(),
    profileFingerprintHex: "00".repeat(32),
  }), /must match the canonical profile body/);
  assert.throws(() => new DeliverySecurityProfileV1({
    ...profileInput(),
    storeAndForward: false,
  }), /retentionClass must be none/);
  assert.throws(() => new DeliverySecurityProfileV1({
    ...profileInput(),
    requiresLocalSecrets: false,
  }), /secretsOwner must be none/);
  assert.throws(() => new DeliverySecurityProfileV1({
    ...profileInput(),
    maxDeliveryAgeMs: 0,
  }), /must be positive with store-and-forward/);
  assert.throws(() => new DeliverySecurityProfileV1({
    ...profileInput(),
    futureClaim: "stronger",
  }), /unknown field/);
});

test("DeliveryTransportDescriptorV1 pins one instance to one profile snapshot", () => {
  const profile = new DeliverySecurityProfileV1(profileInput());
  const descriptor = new DeliveryTransportDescriptorV1({
    transportKind: "reznet",
    transportInstanceId: "trinst_0123456789abcdef0123456789abcdef",
    profileId: profile.profileId,
    profileVersion: profile.profileVersion,
    profileFingerprintHex: profile.profileFingerprintHex,
    maxPayloadBytes: profile.maxPayloadBytes,
    maxDeliveryAgeMs: profile.maxDeliveryAgeMs,
    custodyStages: profile.custodyStages,
    idempotencyMode: "reznet-custody-key",
  });
  assert.deepEqual(
    DeliveryTransportDescriptorV1.fromBytes(descriptor.toBytes()).toJSON(),
    descriptor.toJSON(),
  );
  assert.throws(() => new DeliveryTransportDescriptorV1({
    ...descriptor.toJSON(),
    idempotencyMode: "global-operation-id",
  }), /idempotencyMode/);
});

test("DeliverySecurityProfileEvaluator preserves partial orders and set semantics", () => {
  const evaluator = new DeliverySecurityProfileEvaluator();
  assert.equal(evaluator.satisfiesMinimum(
    "senderRecipientLinkability",
    "separated",
    "single-operator-visible",
  ), true);
  assert.equal(evaluator.satisfiesMinimum(
    "senderRecipientLinkability",
    "foreign-service-visible",
    "local-observer-visible",
  ), false);
  assert.equal(evaluator.satisfiesMinimum(
    "routingPrivacy",
    "test-only",
    "local-proximity",
  ), false);
  assert.equal(evaluator.satisfiesMinimum("timingLeakage", "low", "medium"), true);
  assert.equal(evaluator.satisfiesMinimum("timingLeakage", "high", "medium"), false);
  assert.equal(evaluator.isAcceptable(
    "storageTrust",
    "rez-opaque-store",
    ["rez-opaque-store", "none"],
  ), true);
  assert.throws(() => evaluator.satisfiesMinimum(
    "storageTrust",
    "rez-opaque-store",
    "foreign-opaque-store",
  ), /acceptable-set semantics/);
  assert.throws(() => evaluator.isAcceptable(
    "routingPrivacy",
    "rez-default",
    ["rez-default"],
  ), /ordered semantics/);
});
