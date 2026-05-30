import test from "node:test";
import assert from "node:assert/strict";
import { TypedEventBus } from "../src/events/TypedEventBus.js";

// ── on() returns unsubscribe function ──────────────────────────────

test("on() returns a function", () => {
  const bus = new TypedEventBus();
  const unsub = bus.on("evt", () => {});
  assert.equal(typeof unsub, "function");
});

test("calling unsubscribe removes the handler", () => {
  const bus = new TypedEventBus();
  const calls = [];
  const unsub = bus.on("evt", (d) => calls.push(d));
  bus.emit("evt", 1);
  unsub();
  bus.emit("evt", 2);
  assert.deepEqual(calls, [1]);
});

// ── on() handler receives emitted data ─────────────────────────────

test("on() handler receives emitted payload", () => {
  const bus = new TypedEventBus();
  let received;
  bus.on("msg", (data) => { received = data; });
  bus.emit("msg", { text: "hello" });
  assert.deepEqual(received, { text: "hello" });
});

// ── off() removes handler ──────────────────────────────────────────

test("off() removes a specific handler", () => {
  const bus = new TypedEventBus();
  const calls = [];
  const handler = (d) => calls.push(d);
  bus.on("evt", handler);
  bus.emit("evt", 1);
  bus.off("evt", handler);
  bus.emit("evt", 2);
  assert.deepEqual(calls, [1]);
});

// ── once() fires only once ─────────────────────────────────────────

test("once() handler fires exactly once", () => {
  const bus = new TypedEventBus();
  const calls = [];
  bus.once("evt", (d) => calls.push(d));
  bus.emit("evt", "a");
  bus.emit("evt", "b");
  bus.emit("evt", "c");
  assert.deepEqual(calls, ["a"]);
});

test("once() returns unsubscribe that prevents firing", () => {
  const bus = new TypedEventBus();
  const calls = [];
  const unsub = bus.once("evt", (d) => calls.push(d));
  unsub();
  bus.emit("evt", "x");
  assert.deepEqual(calls, []);
});

// ── emit() calls all handlers ──────────────────────────────────────

test("emit() calls all registered handlers for an event", () => {
  const bus = new TypedEventBus();
  const a = [];
  const b = [];
  bus.on("evt", (d) => a.push(d));
  bus.on("evt", (d) => b.push(d));
  bus.emit("evt", 42);
  assert.deepEqual(a, [42]);
  assert.deepEqual(b, [42]);
});

test("emit() on unknown event does not throw", () => {
  const bus = new TypedEventBus();
  assert.doesNotThrow(() => bus.emit("nope", {}));
});

test("emit() swallows listener errors", () => {
  const bus = new TypedEventBus();
  const calls = [];
  bus.on("evt", () => { throw new Error("boom"); });
  bus.on("evt", (d) => calls.push(d));
  assert.doesNotThrow(() => bus.emit("evt", 1));
  assert.deepEqual(calls, [1]);
});

// ── removeAllListeners() ───────────────────────────────────────────

test("removeAllListeners(eventName) removes handlers for that event", () => {
  const bus = new TypedEventBus();
  const calls = [];
  bus.on("a", (d) => calls.push(d));
  bus.on("b", (d) => calls.push(d));
  bus.removeAllListeners("a");
  bus.emit("a", 1);
  bus.emit("b", 2);
  assert.deepEqual(calls, [2]);
});

test("removeAllListeners() with no args clears all events", () => {
  const bus = new TypedEventBus();
  const calls = [];
  bus.on("a", (d) => calls.push(d));
  bus.on("b", (d) => calls.push(d));
  bus.removeAllListeners();
  bus.emit("a", 1);
  bus.emit("b", 2);
  assert.deepEqual(calls, []);
});

// ── listenerCount() ────────────────────────────────────────────────

test("listenerCount() returns 0 for unknown event", () => {
  const bus = new TypedEventBus();
  assert.equal(bus.listenerCount("nope"), 0);
});

test("listenerCount() returns correct count after on/off", () => {
  const bus = new TypedEventBus();
  const h1 = () => {};
  const h2 = () => {};
  bus.on("evt", h1);
  assert.equal(bus.listenerCount("evt"), 1);
  bus.on("evt", h2);
  assert.equal(bus.listenerCount("evt"), 2);
  bus.off("evt", h1);
  assert.equal(bus.listenerCount("evt"), 1);
});

// ── multiple handlers on same event all fire ───────────────────────

test("multiple handlers on same event all receive payload", () => {
  const bus = new TypedEventBus();
  const results = [];
  bus.on("data", (d) => results.push(`h1:${d}`));
  bus.on("data", (d) => results.push(`h2:${d}`));
  bus.on("data", (d) => results.push(`h3:${d}`));
  bus.emit("data", "x");
  assert.equal(results.length, 3);
  assert.ok(results.includes("h1:x"));
  assert.ok(results.includes("h2:x"));
  assert.ok(results.includes("h3:x"));
});
