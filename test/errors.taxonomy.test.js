import test from "node:test";
import assert from "node:assert/strict";
import {
  SdkError,
  AuthFailure,
  UplinkUnavailable,
  RoutingUnavailable,
  RetryableTransportFailure,
  PermanentValidationFailure,
  AuthorizationFailure,
  ReauthRequired,
  CapabilityUnavailable,
  ConnectionTimeout,
  RequestTimeout,
} from "../src/errors/index.js";

// ── code & retryable fields ────────────────────────────────────────

const TAXONOMY = [
  { Ctor: AuthFailure, code: "AUTH_FAILURE", retryable: false },
  { Ctor: UplinkUnavailable, code: "UPLINK_UNAVAILABLE", retryable: true },
  { Ctor: RoutingUnavailable, code: "ROUTING_UNAVAILABLE", retryable: true },
  { Ctor: RetryableTransportFailure, code: "TRANSPORT_FAILURE", retryable: true },
  { Ctor: PermanentValidationFailure, code: "VALIDATION_FAILURE", retryable: false },
  { Ctor: AuthorizationFailure, code: "AUTHORIZATION_FAILURE", retryable: false },
  { Ctor: ReauthRequired, code: "REAUTH_REQUIRED", retryable: true },
  { Ctor: CapabilityUnavailable, code: "CAPABILITY_UNAVAILABLE", retryable: false },
  { Ctor: ConnectionTimeout, code: "CONNECTION_TIMEOUT", retryable: true },
  { Ctor: RequestTimeout, code: "REQUEST_TIMEOUT", retryable: true },
];

for (const { Ctor, code, retryable } of TAXONOMY) {
  test(`${Ctor.name} has code="${code}" and retryable=${retryable}`, () => {
    const err = new Ctor("test message");
    assert.equal(err.code, code);
    assert.equal(err.retryable, retryable);
  });
}

// ── instanceof checks ──────────────────────────────────────────────

for (const { Ctor } of TAXONOMY) {
  test(`${Ctor.name} is instanceof SdkError and Error`, () => {
    const err = new Ctor("check");
    assert.ok(err instanceof SdkError);
    assert.ok(err instanceof Error);
  });
}

// ── message is set correctly ───────────────────────────────────────

test("SdkError sets message from constructor", () => {
  const err = new SdkError("CUSTOM", "my message");
  assert.equal(err.message, "my message");
});

for (const { Ctor } of TAXONOMY) {
  test(`${Ctor.name} preserves message string`, () => {
    const msg = `specific ${Ctor.name} error`;
    const err = new Ctor(msg);
    assert.equal(err.message, msg);
  });
}

// ── cause propagation ──────────────────────────────────────────────

test("SdkError propagates cause when provided", () => {
  const root = new Error("root cause");
  const err = new SdkError("X", "wrapper", { cause: root });
  assert.equal(err.cause, root);
});

test("SdkError omits cause when not provided", () => {
  const err = new SdkError("X", "no cause");
  assert.equal(err.cause, undefined);
});

test("subclass propagates cause through opts", () => {
  const root = new TypeError("bad type");
  const err = new AuthFailure("auth failed", { cause: root });
  assert.equal(err.cause, root);
  assert.equal(err.code, "AUTH_FAILURE");
});
