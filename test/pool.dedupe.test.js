import test from "node:test";
import assert from "node:assert/strict";
import { DeduperLRU } from "../src/pool/DeduperLRU.js";

// ── first-seen ID returns false (not a dupe) ──────────────────────

test("seen() returns false for an ID that was never marked", () => {
  const d = new DeduperLRU();
  assert.equal(d.seen("msg-1"), false);
});

// ── second-seen same ID returns true (is a dupe) ──────────────────

test("seen() returns true after mark() for the same ID", () => {
  const d = new DeduperLRU();
  const now = Date.now();
  d.mark("msg-1", now);
  assert.equal(d.seen("msg-1", now), true);
});

test("mark then seen round-trip for multiple IDs", () => {
  const d = new DeduperLRU();
  const now = Date.now();
  d.mark("a", now);
  d.mark("b", now);
  assert.equal(d.seen("a", now), true);
  assert.equal(d.seen("b", now), true);
  assert.equal(d.seen("c", now), false);
});

// ── eviction after maxSize ─────────────────────────────────────────

test("evicts oldest entry when capacity is exceeded", () => {
  const d = new DeduperLRU({ capacity: 100 });
  const now = Date.now();
  // Fill to capacity
  for (let i = 0; i < 100; i++) {
    d.mark(`id-${i}`, now);
  }
  // All should be seen
  assert.equal(d.seen(`id-0`, now), true);
  assert.equal(d.seen(`id-99`, now), true);

  // Add one more, which should evict the oldest (id-0)
  d.mark("id-100", now);
  assert.equal(d.seen("id-0", now), false);
  assert.equal(d.seen("id-100", now), true);
});

// ── TTL expiry ─────────────────────────────────────────────────────

test("seen() returns false after TTL expires", () => {
  const d = new DeduperLRU({ ttlMs: 1000 });
  const now = Date.now();
  d.mark("msg-1", now);
  assert.equal(d.seen("msg-1", now + 500), true);
  assert.equal(d.seen("msg-1", now + 1500), false);
});

// ── clear() resets state ───────────────────────────────────────────

test("clear() removes all entries", () => {
  const d = new DeduperLRU();
  const now = Date.now();
  d.mark("a", now);
  d.mark("b", now);
  d.clear();
  assert.equal(d.seen("a", now), false);
  assert.equal(d.seen("b", now), false);
});

// ── invalid keys ───────────────────────────────────────────────────

test("mark() and seen() ignore invalid keys", () => {
  const d = new DeduperLRU();
  d.mark("", Date.now());
  d.mark("  ", Date.now());
  d.mark(null, Date.now());
  d.mark(undefined, Date.now());
  assert.equal(d.seen("", Date.now()), false);
  assert.equal(d.seen(null, Date.now()), false);
});
