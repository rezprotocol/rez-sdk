import test from "node:test";
import assert from "node:assert/strict";
import {
  wrapAccountStateEnvelope,
  isAccountStateEnvelope,
  siblingInboxesFromDeviceSet,
  ACCOUNT_STATE_ENVELOPE_VERSION,
} from "../src/peer-link/accountStateSeal.js";

test("wrap + recognize round-trips the outer envelope discriminator", () => {
  const env = wrapAccountStateEnvelope({ nonceB64: "nnn", ciphertextB64: "ccc" });
  assert.equal(env.accountState, ACCOUNT_STATE_ENVELOPE_VERSION);
  assert.equal(env.nonceB64, "nnn");
  assert.equal(env.ciphertextB64, "ccc");
  assert.ok(isAccountStateEnvelope(env));
});

test("isAccountStateEnvelope rejects peer + malformed envelopes", () => {
  assert.equal(isAccountStateEnvelope({ e2ee: 1, v: 1, payload: "..." }), false, "a peer e2ee envelope is not a self-event");
  assert.equal(isAccountStateEnvelope({ accountState: 1 }), false, "missing nonce/ciphertext");
  assert.equal(isAccountStateEnvelope({ accountState: 2, nonceB64: "n", ciphertextB64: "c" }), false, "wrong version");
  assert.equal(isAccountStateEnvelope(null), false);
});

test("wrapAccountStateEnvelope fails loud on missing fields", () => {
  assert.throws(() => wrapAccountStateEnvelope({ nonceB64: "n" }));
  assert.throws(() => wrapAccountStateEnvelope({}));
});

test("siblingInboxesFromDeviceSet excludes self (by inbox AND deviceId) and dedups", () => {
  const devices = [
    { deviceId: "rez:dev:self", bundle: { deviceId: "rez:dev:self", inboxId: "inbox:self" } },
    { deviceId: "rez:dev:sib1", bundle: { deviceId: "rez:dev:sib1", inboxId: "inbox:sib1" } },
    { deviceId: "rez:dev:sib2", bundle: { deviceId: "rez:dev:sib2", inboxId: "inbox:sib2" } },
    // a duplicate inbox (should collapse)
    { deviceId: "rez:dev:sib2", bundle: { deviceId: "rez:dev:sib2", inboxId: "inbox:sib2" } },
  ];
  const out = siblingInboxesFromDeviceSet({ devices, ownInboxId: "inbox:self", ownDeviceId: "rez:dev:self" });
  assert.deepEqual(out, [
    { deviceId: "rez:dev:sib1", inboxId: "inbox:sib1" },
    { deviceId: "rez:dev:sib2", inboxId: "inbox:sib2" },
  ]);
});

test("siblingInboxesFromDeviceSet: own device excluded even if inbox id differs (defense in depth)", () => {
  const devices = [
    { deviceId: "rez:dev:self", bundle: { deviceId: "rez:dev:self", inboxId: "inbox:weird" } },
    { deviceId: "rez:dev:sib", bundle: { deviceId: "rez:dev:sib", inboxId: "inbox:sib" } },
  ];
  const out = siblingInboxesFromDeviceSet({ devices, ownInboxId: "inbox:self", ownDeviceId: "rez:dev:self" });
  assert.deepEqual(out, [{ deviceId: "rez:dev:sib", inboxId: "inbox:sib" }]);
});

test("siblingInboxesFromDeviceSet skips entries missing inbox or deviceId", () => {
  const devices = [
    { deviceId: "rez:dev:sib", bundle: { deviceId: "rez:dev:sib" } }, // no inbox
    { bundle: { inboxId: "inbox:x" } }, // no deviceId
    { deviceId: "rez:dev:ok", bundle: { deviceId: "rez:dev:ok", inboxId: "inbox:ok" } },
  ];
  const out = siblingInboxesFromDeviceSet({ devices, ownInboxId: "inbox:self", ownDeviceId: "rez:dev:self" });
  assert.deepEqual(out, [{ deviceId: "rez:dev:ok", inboxId: "inbox:ok" }]);
});
