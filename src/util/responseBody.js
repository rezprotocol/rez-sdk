/**
 * Response-body contract gate — the ONE place a capability turns a node response into the
 * value it promised its caller.
 *
 * CONVENTION: a capability returns exactly what its JSDoc promises, or it THROWS. It never
 * returns a shape that cannot be told apart from a legitimate answer.
 *
 * The pattern this replaces — `response && typeof response.body === "object" ? response.body : {}`
 * — was wrong in three ways:
 *
 *   1. UNREACHABLE. Both real transports already normalize the frame body to an object before
 *      resolving (WsTransport / TcpTransport), and reject error frames and mismatched response
 *      types outright. In production the fallback never fired; it only ever caught test doubles.
 *   2. BUGGY WHERE IT DID FIRE. `typeof null === "object"`, and the guard only tested `response`,
 *      so a `{ body: null }` response took the TRUE branch and returned null — the exact input the
 *      fallback appeared to be defending against.
 *   3. DANGEROUS DOWNSTREAM. An empty object is indistinguishable from a real answer whose fields
 *      happen to be absent, so drift became a plausible no-op: a missing `stale` read as "the
 *      mutation applied", a missing `items` as "the mailbox is empty", a missing `epoch` as
 *      "epoch 0". Each silently produced wrong behavior with no error anywhere.
 *
 * So: contract drift THROWS here. Legitimate ABSENCE (e.g. fetching an event that does not exist)
 * stays a documented return value of the capability — but it must come from a real not-found
 * signal in a well-formed body, never from a malformed one. An op that genuinely carries no
 * response fields should return nothing rather than a phantom object.
 *
 * Error messages name the op, the field, and the expected type — NEVER a value. Response bodies
 * carry lease tokens, ciphertext, and identity material; a validation failure must not leak them
 * into logs or error strings.
 */

const TYPE_CHECKS = {
  boolean: (v) => typeof v === "boolean",
  string: (v) => typeof v === "string",
  nonEmptyString: (v) => typeof v === "string" && v.length > 0,
  number: (v) => typeof v === "number" && Number.isFinite(v),
  integer: (v) => Number.isInteger(v),
  object: (v) => v !== null && typeof v === "object" && !Array.isArray(v),
  // A field whose contract is "an object, or explicitly null" — e.g. record.get answering
  // not-found, or node.status on a mesh-less node. The KEY must still be present: an absent key
  // is drift, a null value is an answer. Distinguishing those is the whole point.
  nullableObject: (v) => v === null || (typeof v === "object" && !Array.isArray(v)),
  array: (v) => Array.isArray(v),
};

// How each type name reads in an error message.
const TYPE_LABELS = {
  boolean: "boolean",
  string: "string",
  nonEmptyString: "non-empty string",
  number: "finite number",
  integer: "integer",
  object: "object",
  nullableObject: "object or null",
  array: "array",
};

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Require a well-formed response body, optionally with required fields of a given type.
 *
 * @param {object} args
 * @param {string} args.op — the caller's identity for error messages, e.g.
 *     "DevicesCapability.submitDeviceMutation". Required: an unnamed failure is unactionable.
 * @param {object} args.response — the raw frame resolved by the transport.
 * @param {Record<string,string>} [args.require] — field name → type name (see TYPE_CHECKS). Every
 *     listed field must be present with that type. Pin this list against the NODE's response
 *     record, not against the JSDoc — the node is the contract.
 * @returns {object} the response body, verbatim. Never a substitute, never a clone.
 * @throws when the op is unnamed, the body is missing/malformed, a required field is absent or
 *     of the wrong type, or an unknown type name is requested (a mis-specified requirement must
 *     fail loudly rather than silently validating nothing).
 */
export function requireResponseBody({ op, response, require = null } = {}) {
  if (typeof op !== "string" || op.length === 0) {
    throw new Error("requireResponseBody requires op (the calling capability method)");
  }
  const body = response !== null && response !== undefined && isPlainObject(response.body)
    ? response.body
    : null;
  if (body === null) {
    throw new Error(op + ": node returned no response body");
  }
  if (require === null || require === undefined) return body;
  if (!isPlainObject(require)) {
    throw new Error(op + ": requireResponseBody `require` must be a field→type object");
  }
  for (const field of Object.keys(require)) {
    const typeName = require[field];
    const check = Object.prototype.hasOwnProperty.call(TYPE_CHECKS, typeName) ? TYPE_CHECKS[typeName] : null;
    if (check === null) {
      throw new Error(op + ": requireResponseBody cannot check unknown type '" + String(typeName) + "' for field '" + field + "'");
    }
    if (!check(body[field])) {
      throw new Error(op + ": response is missing the required '" + field + "' " + TYPE_LABELS[typeName]);
    }
  }
  return body;
}
