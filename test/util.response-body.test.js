import test from "node:test";
import assert from "node:assert/strict";

import { requireResponseBody } from "../src/util/responseBody.js";

const OP = "TestCapability.doThing";

test("returns the body VERBATIM — the same object, not a copy", () => {
  const body = { leased: true, token: "t", nested: { a: 1 } };
  const out = requireResponseBody({ op: OP, response: { body } });
  assert.equal(out, body, "same reference — a capability must not hand back a reshaped answer");
});

test("a missing, null, or non-object body THROWS instead of becoming {}", () => {
  for (const response of [undefined, null, {}, { body: null }, { body: undefined }, { body: "{}" }, { body: 7 }, { body: [] }]) {
    assert.throws(
      () => requireResponseBody({ op: OP, response }),
      /TestCapability\.doThing: node returned no response body/,
      "response " + JSON.stringify(response) + " must not pass",
    );
  }
});

test("regression: a null body does NOT slip through as null (typeof null === 'object')", () => {
  // The pattern this gate replaces read `response && typeof response.body === "object" ? response.body : {}`,
  // which returned NULL for this input — so the caller's next property access threw a TypeError
  // far from the cause. It must be a named contract failure at the boundary instead.
  assert.throws(() => requireResponseBody({ op: OP, response: { body: null } }), /node returned no response body/);
});

test("required fields are checked by type, and the message names op + field + type", () => {
  const response = { body: { leased: true, epoch: 4, id: "x", items: [], meta: {}, ratio: 1.5 } };
  // All satisfied.
  assert.equal(
    requireResponseBody({
      op: OP,
      response,
      require: { leased: "boolean", epoch: "integer", id: "nonEmptyString", items: "array", meta: "object", ratio: "number" },
    }),
    response.body,
  );

  assert.throws(
    () => requireResponseBody({ op: OP, response, require: { completed: "boolean" } }),
    /TestCapability\.doThing: response is missing the required 'completed' boolean/,
  );
  assert.throws(
    () => requireResponseBody({ op: OP, response, require: { epoch: "nonEmptyString" } }),
    /missing the required 'epoch' non-empty string/,
  );
  assert.throws(
    () => requireResponseBody({ op: OP, response, require: { items: "object" } }),
    /missing the required 'items' object/,
    "an array must not satisfy an object requirement",
  );
  assert.throws(
    () => requireResponseBody({ op: OP, response, require: { meta: "array" } }),
    /missing the required 'meta' array/,
  );
});

test("a present-but-wrong-typed field fails — coercible values are NOT accepted", () => {
  // The whole point: "false"/0/1 must never satisfy a boolean, or drift reads as a real answer.
  for (const value of ["true", "false", 0, 1, null, undefined]) {
    assert.throws(
      () => requireResponseBody({ op: OP, response: { body: { leased: value } }, require: { leased: "boolean" } }),
      /missing the required 'leased' boolean/,
      "leased=" + JSON.stringify(value) + " must not pass as a boolean",
    );
  }
  // NaN and Infinity are not finite numbers.
  for (const value of [Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => requireResponseBody({ op: OP, response: { body: { ratio: value } }, require: { ratio: "number" } }),
      /missing the required 'ratio' finite number/,
    );
  }
  assert.throws(
    () => requireResponseBody({ op: OP, response: { body: { epoch: 1.5 } }, require: { epoch: "integer" } }),
    /missing the required 'epoch' integer/,
  );
  assert.throws(
    () => requireResponseBody({ op: OP, response: { body: { id: "" } }, require: { id: "nonEmptyString" } }),
    /missing the required 'id' non-empty string/,
  );
});

test("a field explicitly present as false/0/empty SATISFIES its type — absence is not falsiness", () => {
  // `leased: false` and `attempts: 0` are real answers. A truthiness-based gate would reject them;
  // this one must not.
  const body = { leased: false, attempts: 0, items: [], id: "x" };
  assert.equal(
    requireResponseBody({ op: OP, response: { body }, require: { leased: "boolean", attempts: "integer", items: "array" } }),
    body,
  );
});

test("no `require` means shape-only: the body is returned unchecked", () => {
  const body = { anything: 1 };
  assert.equal(requireResponseBody({ op: OP, response: { body } }), body);
  assert.equal(requireResponseBody({ op: OP, response: { body }, require: null }), body);
});

test("a mis-specified requirement fails LOUDLY rather than silently checking nothing", () => {
  const response = { body: { leased: true } };
  assert.throws(
    () => requireResponseBody({ op: OP, response, require: { leased: "bool" } }),
    /cannot check unknown type 'bool' for field 'leased'/,
    "a typo'd type name must not silently pass everything",
  );
  assert.throws(
    () => requireResponseBody({ op: OP, response, require: ["leased"] }),
    /`require` must be a field→type object/,
  );
  assert.throws(
    () => requireResponseBody({ op: OP, response, require: "leased" }),
    /`require` must be a field→type object/,
  );
});

test("an unnamed op is rejected — an unactionable failure message helps nobody", () => {
  assert.throws(() => requireResponseBody({ response: { body: {} } }), /requires op/);
  assert.throws(() => requireResponseBody({ op: "", response: { body: {} } }), /requires op/);
  assert.throws(() => requireResponseBody(), /requires op/);
});

test("failure messages never interpolate a response VALUE", () => {
  // Bodies carry lease tokens, ciphertext, and identity material. A validation failure must not
  // leak them into logs or error strings — only the field NAME and expected type.
  const secret = "lease-token-deadbeef";
  let message = "";
  try {
    requireResponseBody({ op: OP, response: { body: { token: secret, leased: "yes" } }, require: { leased: "boolean" } });
  } catch (err) {
    message = err.message;
  }
  assert.ok(message.length > 0, "expected a throw");
  assert.equal(message.includes(secret), false, "token value must not appear in the message");
  assert.equal(message.includes("yes"), false, "offending value must not appear in the message");
  assert.ok(message.includes("leased"), "field name is what the developer needs");
});

test("nullableObject accepts an object OR null, but the key must be PRESENT", () => {
  // The contract for record.get (not-found) and node.status (meshing off): null is an ANSWER,
  // an absent key is drift. Collapsing the two is exactly what this convention exists to stop.
  assert.equal(
    requireResponseBody({ op: OP, response: { body: { record: null } }, require: { record: "nullableObject" } }).record,
    null,
  );
  const found = { record: { k: 1 } };
  assert.equal(requireResponseBody({ op: OP, response: { body: found }, require: { record: "nullableObject" } }), found);

  assert.throws(
    () => requireResponseBody({ op: OP, response: { body: {} }, require: { record: "nullableObject" } }),
    /missing the required 'record' object or null/,
  );
  for (const bad of [[], "null", 0, false]) {
    assert.throws(
      () => requireResponseBody({ op: OP, response: { body: { record: bad } }, require: { record: "nullableObject" } }),
      /missing the required 'record' object or null/,
      JSON.stringify(bad) + " must not satisfy nullableObject",
    );
  }
});
