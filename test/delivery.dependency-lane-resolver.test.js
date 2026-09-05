import test from "node:test";
import assert from "node:assert/strict";
import { DependencyLaneResolver } from "../src/delivery/index.js";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test("independent session lanes share an owner while equal sessions serialize", async () => {
  const lanes = new DependencyLaneResolver();
  const releaseA = deferred();
  const releaseB = deferred();
  const entered = [];
  const a = lanes.runSession("owner", "session-a", async () => {
    entered.push("a1");
    await releaseA.promise;
  });
  const b = lanes.runSession("owner", "session-b", async () => {
    entered.push("b");
    await releaseB.promise;
  });
  const a2 = lanes.runSession("owner", "session-a", async () => { entered.push("a2"); });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(entered, ["a1", "b"]);
  releaseA.resolve();
  await a;
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(entered, ["a1", "b", "a2"]);
  releaseB.resolve();
  await Promise.all([b, a2]);
});

test("owner-global is a fair two-direction barrier", async () => {
  const lanes = new DependencyLaneResolver();
  const releaseFirst = deferred();
  const releaseGlobal = deferred();
  const order = [];
  const first = lanes.runSession("owner", "s1", async () => {
    order.push("session-1-enter");
    await releaseFirst.promise;
    order.push("session-1-exit");
  });
  const global = lanes.runOwner("owner", async () => {
    order.push("global-enter");
    await releaseGlobal.promise;
    order.push("global-exit");
  });
  const later = lanes.runSession("owner", "s2", async () => { order.push("session-2-enter"); });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(order, ["session-1-enter"]);
  releaseFirst.resolve();
  await first;
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(order, ["session-1-enter", "session-1-exit", "global-enter"]);
  releaseGlobal.resolve();
  await Promise.all([global, later]);
  assert.deepEqual(order, ["session-1-enter", "session-1-exit", "global-enter", "global-exit", "session-2-enter"]);
});

test("owner barriers do not block a different owner", async () => {
  const lanes = new DependencyLaneResolver();
  const release = deferred();
  let otherRan = false;
  const blocked = lanes.runOwner("owner-a", async () => { await release.promise; });
  await lanes.runSession("owner-b", "session", async () => { otherRan = true; });
  assert.equal(otherRan, true);
  release.resolve();
  await blocked;
});

test("an owner-global writer cannot be starved by sustained session arrivals", async () => {
  const lanes = new DependencyLaneResolver();
  const releaseFirst = deferred();
  const order = [];
  const first = lanes.runSession("owner", "initial", async () => {
    order.push("initial");
    await releaseFirst.promise;
  });
  const global = lanes.runOwner("owner", async () => { order.push("global"); });
  const later = [];
  for (let index = 0; index < 100; index += 1) {
    later.push(lanes.runSession("owner", "later-" + index, async () => { order.push("later-" + index); }));
  }
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(order, ["initial"]);
  releaseFirst.resolve();
  await Promise.all([first, global, ...later]);
  assert.equal(order[1], "global", "queued exclusive work runs before every later shared arrival");
  assert.equal(order.length, 102);
});

test("interleaved owner/session acquisition storm drains without deadlock in barrier order", async () => {
  const lanes = new DependencyLaneResolver();
  const order = [];
  const work = [];
  for (let index = 0; index < 40; index += 1) {
    work.push(lanes.runSession("owner", "a-" + index, async () => { order.push("a-" + index); }));
    work.push(lanes.runSession("owner", "b-" + index, async () => { order.push("b-" + index); }));
    work.push(lanes.runOwner("owner", async () => { order.push("owner-" + index); }));
  }
  let timer = null;
  try {
    await Promise.race([
      Promise.all(work),
      new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error("lane storm deadlocked")), 2_000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
  for (let index = 0; index < 40; index += 1) {
    const barrier = order.indexOf("owner-" + index);
    assert.ok(barrier > order.indexOf("a-" + index));
    assert.ok(barrier > order.indexOf("b-" + index));
    if (index < 39) {
      assert.ok(barrier < order.indexOf("a-" + (index + 1)));
      assert.ok(barrier < order.indexOf("b-" + (index + 1)));
    }
  }
});

test("closeOwner drains prior work and rejects every later mutation", async () => {
  const lanes = new DependencyLaneResolver();
  const events = [];
  let release;
  const held = lanes.runSession("owner-a", "session-a", async () => {
    events.push("session:start");
    await new Promise((resolve) => { release = resolve; });
    events.push("session:end");
  });
  await Promise.resolve();
  const closing = lanes.closeOwner("owner-a").then(() => events.push("closed"));
  await assert.rejects(
    () => lanes.runSession("owner-a", "session-b", async () => {}),
    /owner is closed/,
  );
  await assert.rejects(
    () => lanes.runOwner("owner-a", async () => {}),
    /owner is closed/,
  );
  assert.deepEqual(events, ["session:start"]);
  release();
  await Promise.all([held, closing]);
  assert.deepEqual(events, ["session:start", "session:end", "closed"]);
});
