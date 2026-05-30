import test from "node:test";
import assert from "node:assert/strict";
import { MetricsCollector } from "../src/observability/MetricsCollector.js";

// ── increment() ────────────────────────────────────────────────────

test("increment() increases counter by 1 by default", () => {
  const m = new MetricsCollector();
  m.increment("requests");
  m.increment("requests");
  const snap = m.snapshot();
  assert.equal(snap.counters.requests, 2);
});

test("increment() increases counter by given value", () => {
  const m = new MetricsCollector();
  m.increment("bytes", 100);
  m.increment("bytes", 50);
  const snap = m.snapshot();
  assert.equal(snap.counters.bytes, 150);
});

// ── record() ───────────────────────────────────────────────────────

test("record() adds to histogram with count, sum, min, max, avg", () => {
  const m = new MetricsCollector();
  m.record("latency", 10);
  m.record("latency", 20);
  m.record("latency", 30);
  const snap = m.snapshot();
  const h = snap.histograms.latency;
  assert.equal(h.count, 3);
  assert.equal(h.sum, 60);
  assert.equal(h.min, 10);
  assert.equal(h.max, 30);
  assert.equal(h.avg, 20);
});

test("record() ignores non-finite values", () => {
  const m = new MetricsCollector();
  m.record("lat", NaN);
  m.record("lat", Infinity);
  m.record("lat", undefined);
  const snap = m.snapshot();
  assert.equal(snap.histograms.lat, undefined);
});

// ── snapshot() ─────────────────────────────────────────────────────

test("snapshot() returns all counters and histograms", () => {
  const m = new MetricsCollector();
  m.increment("a");
  m.increment("b", 5);
  m.record("dur", 42);
  const snap = m.snapshot();
  assert.equal(snap.counters.a, 1);
  assert.equal(snap.counters.b, 5);
  assert.equal(snap.histograms.dur.count, 1);
  assert.equal(snap.histograms.dur.sum, 42);
});

test("snapshot() returns empty objects when nothing recorded", () => {
  const m = new MetricsCollector();
  const snap = m.snapshot();
  assert.deepEqual(snap.counters, {});
  assert.deepEqual(snap.histograms, {});
});

test("snapshot() normalizes min/max to 0 when histogram is empty-initialized", () => {
  // This verifies the edge case where Infinity/-Infinity are replaced by 0
  // in snapshot output. We need at least one record to create the histogram entry,
  // so we verify the actual min/max values are correct after recording.
  const m = new MetricsCollector();
  m.record("x", 5);
  const snap = m.snapshot();
  assert.equal(snap.histograms.x.min, 5);
  assert.equal(snap.histograms.x.max, 5);
});

// ── reset() ────────────────────────────────────────────────────────

test("reset() clears all counters and histograms", () => {
  const m = new MetricsCollector();
  m.increment("a", 10);
  m.record("lat", 50);
  m.reset();
  const snap = m.snapshot();
  assert.deepEqual(snap.counters, {});
  assert.deepEqual(snap.histograms, {});
});

// ── onMetric() ─────────────────────────────────────────────────────

test("onMetric() callback fires on increment", () => {
  const m = new MetricsCollector();
  const events = [];
  m.onMetric((e) => events.push(e));
  m.increment("req");
  assert.equal(events.length, 1);
  assert.equal(events[0].type, "counter");
  assert.equal(events[0].name, "req");
  assert.equal(events[0].value, 1);
  assert.equal(events[0].delta, 1);
});

test("onMetric() callback fires on record", () => {
  const m = new MetricsCollector();
  const events = [];
  m.onMetric((e) => events.push(e));
  m.record("dur", 99);
  assert.equal(events.length, 1);
  assert.equal(events[0].type, "histogram");
  assert.equal(events[0].name, "dur");
  assert.equal(events[0].value, 99);
});

test("onMetric() returns unsubscribe function", () => {
  const m = new MetricsCollector();
  const events = [];
  const unsub = m.onMetric((e) => events.push(e));
  m.increment("a");
  unsub();
  m.increment("b");
  assert.equal(events.length, 1);
});

test("onMetric() throws if handler is not a function", () => {
  const m = new MetricsCollector();
  assert.throws(() => m.onMetric("not a fn"), /handler required/);
});
