import test from "node:test";
import assert from "node:assert/strict";
import { createFrameCodec } from "../src/transport/FrameCodec.js";

const codec = createFrameCodec();

// ── encode/decode round-trip ───────────────────────────────────────

test("round-trip preserves id, type, body, and version", () => {
  const input = { id: "req-1", type: "ping", body: { ts: 123 }, version: 2 };
  const encoded = codec.encodeFrame(input);
  const decoded = codec.decodeFrame(encoded);
  assert.equal(decoded.id, "req-1");
  assert.equal(decoded.type, "ping");
  assert.deepEqual(decoded.body, { ts: 123 });
  assert.equal(decoded.version, 2);
});

test("round-trip with empty body", () => {
  const input = { id: "req-2", type: "noop", body: {}, version: 1 };
  const encoded = codec.encodeFrame(input);
  const decoded = codec.decodeFrame(encoded);
  assert.equal(decoded.id, "req-2");
  assert.equal(decoded.type, "noop");
  assert.deepEqual(decoded.body, {});
  assert.equal(decoded.version, 1);
});

// ── id, type, body, version are preserved ──────────────────────────

test("encodeFrame serializes to JSON with wire fields id, t, v, body", () => {
  const raw = codec.encodeFrame({ id: "x", type: "test", body: { a: 1 }, version: 3 });
  const parsed = JSON.parse(raw);
  assert.equal(parsed.id, "x");
  assert.equal(parsed.t, "test");
  assert.equal(parsed.v, 3);
  assert.deepEqual(parsed.body, { a: 1 });
});

test("decodeFrame reads both t and type fields", () => {
  const withT = codec.decodeFrame(JSON.stringify({ id: "a", t: "foo", v: 1, body: {} }));
  assert.equal(withT.type, "foo");

  const withType = codec.decodeFrame(JSON.stringify({ id: "b", type: "bar", v: 1, body: {} }));
  assert.equal(withType.type, "bar");
});

// ── missing / invalid fields produce errors or defaults ────────────

test("decodeFrame throws on non-JSON input", () => {
  assert.throws(() => codec.decodeFrame("not json{{{"), (err) => {
    assert.equal(err.code, "BAD_FRAME");
    assert.equal(err.retryable, false);
    return true;
  });
});

test("decodeFrame throws on null input", () => {
  assert.throws(() => codec.decodeFrame("null"), (err) => {
    assert.equal(err.code, "BAD_FRAME");
    return true;
  });
});

test("decodeFrame returns null id when id is missing", () => {
  const decoded = codec.decodeFrame(JSON.stringify({ t: "test", v: 1, body: {} }));
  assert.equal(decoded.id, null);
});

test("decodeFrame returns empty string type when t is missing", () => {
  const decoded = codec.decodeFrame(JSON.stringify({ id: "x", v: 1, body: {} }));
  assert.equal(decoded.type, "");
});

test("decodeFrame returns empty object body when body is not an object", () => {
  const decoded = codec.decodeFrame(JSON.stringify({ id: "x", t: "y", v: 1, body: "str" }));
  assert.deepEqual(decoded.body, {});
});

test("encodeFrame defaults body to {} when omitted", () => {
  const raw = codec.encodeFrame({ id: "x", type: "y", version: 1 });
  const parsed = JSON.parse(raw);
  assert.deepEqual(parsed.body, {});
});

test("encodeFrame defaults version to 2 for non-finite input", () => {
  const raw = codec.encodeFrame({ id: "x", type: "y", body: {}, version: "bad" });
  const parsed = JSON.parse(raw);
  assert.equal(parsed.v, 2);
});
