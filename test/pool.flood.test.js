import test from "node:test";
import assert from "node:assert/strict";
import { FloodGate } from "../src/pool/FloodGate.js";

// ── initial calls are allowed ──────────────────────────────────────

test("allow() returns true for initial calls within burst", () => {
  const gate = new FloodGate({ perConnBurst: 5, perConnRate: 5, globalBurst: 100, globalRate: 100 });
  const now = Date.now();
  for (let i = 0; i < 5; i++) {
    assert.equal(gate.allow("conn-1", now), true, `call ${i} should be allowed`);
  }
});

// ── calls exceeding burst are rejected ─────────────────────────────

test("allow() returns false after per-conn burst is exhausted", () => {
  const gate = new FloodGate({ perConnBurst: 3, perConnRate: 3, globalBurst: 1000, globalRate: 1000 });
  const now = Date.now();
  // Exhaust the per-connection burst
  for (let i = 0; i < 3; i++) {
    gate.allow("conn-1", now);
  }
  // Next call at the same instant should be rejected
  assert.equal(gate.allow("conn-1", now), false);
});

test("allow() returns false after global burst is exhausted", () => {
  const gate = new FloodGate({ perConnBurst: 1000, perConnRate: 1000, globalBurst: 3, globalRate: 3 });
  const now = Date.now();
  // Exhaust the global burst across different connections
  for (let i = 0; i < 3; i++) {
    gate.allow(`conn-${i}`, now);
  }
  assert.equal(gate.allow("conn-new", now), false);
});

// ── token replenishment over time ──────────────────────────────────

test("tokens replenish over time allowing new calls", () => {
  const gate = new FloodGate({ perConnBurst: 2, perConnRate: 10, globalBurst: 100, globalRate: 100 });
  const now = Date.now();
  // Exhaust burst
  gate.allow("conn-1", now);
  gate.allow("conn-1", now);
  assert.equal(gate.allow("conn-1", now), false);

  // After enough time, tokens replenish (rate=10/sec => 1 token per 100ms)
  // Wait 200ms worth of time to get 2 tokens replenished
  assert.equal(gate.allow("conn-1", now + 200), true);
});

// ── consumeWarn ────────────────────────────────────────────────────

test("consumeWarn returns null when no drops", () => {
  const gate = new FloodGate();
  assert.equal(gate.consumeWarn(), null);
});

test("consumeWarn returns drop count after rejections", () => {
  const gate = new FloodGate({ perConnBurst: 1, perConnRate: 1, globalBurst: 1000, globalRate: 1000 });
  const now = Date.now();
  gate.allow("c", now); // allowed
  gate.allow("c", now); // rejected
  gate.allow("c", now); // rejected
  const warn = gate.consumeWarn(now + 2000); // past warn interval
  assert.notEqual(warn, null);
  assert.equal(warn.droppedCount, 2);
  assert.equal(warn.code, "INBOUND_FLOOD");
});

test("consumeWarn resets drop count after consuming", () => {
  const gate = new FloodGate({ perConnBurst: 1, perConnRate: 1, globalBurst: 1000, globalRate: 1000 });
  const now = Date.now();
  gate.allow("c", now);
  gate.allow("c", now); // rejected
  gate.consumeWarn(now + 2000);
  assert.equal(gate.consumeWarn(now + 4000), null);
});

// ── clear() ────────────────────────────────────────────────────────

test("clear() resets all state", () => {
  const gate = new FloodGate({ perConnBurst: 1, perConnRate: 1, globalBurst: 1000, globalRate: 1000 });
  const now = Date.now();
  gate.allow("c", now);
  gate.allow("c", now); // rejected
  gate.clear();
  // After clear, new connection should get a fresh bucket
  assert.equal(gate.allow("c", now), true);
});
