import test from "node:test";
import assert from "node:assert/strict";
import { RelayContractFloorStore } from "../src/relay/RelayContractFloorStore.js";
import { permitsAccountModeAuth } from "../src/relay/DowngradePolicy.js";

// SESSION_AUTH_V5 slice 2B — the frozen store contract:
// highestObservedContract(R) = max(existing, successfulContract); a later
// LOWER observation sets downgrade state but NEVER reduces the stored floor.

test("the floor is MONOTONIC per identity — never 'last seen version'", () => {
  const store = new RelayContractFloorStore();

  let r = store.recordObserved({ relayIdentityB64: "R1", contractVersion: 5 });
  assert.deepEqual(r, { floor: 5, observedCurrent: 5, downgrade: false });

  r = store.recordObserved({ relayIdentityB64: "R1", contractVersion: 4 });
  assert.equal(r.floor, 5, "the stored floor did not lower");
  assert.equal(r.observedCurrent, 4);
  assert.equal(r.downgrade, true, "the lower observation IS a downgrade condition");
  assert.equal(store.floorFor("R1"), 5);

  r = store.recordObserved({ relayIdentityB64: "R1", contractVersion: 5 });
  assert.equal(r.downgrade, false, "re-observing at the floor is not a downgrade");

  // First observation at 4 then 5 raises the floor.
  store.recordObserved({ relayIdentityB64: "R2", contractVersion: 4 });
  r = store.recordObserved({ relayIdentityB64: "R2", contractVersion: 5 });
  assert.equal(r.floor, 5);
  assert.equal(r.downgrade, false, "raising is never a downgrade");
});

test("floors are keyed by verified relay IDENTITY — same endpoint, different identity → independent floors", () => {
  const store = new RelayContractFloorStore();
  store.recordObserved({ relayIdentityB64: "identity-A", contractVersion: 5 });
  assert.equal(store.floorFor("identity-A"), 5);
  assert.equal(store.floorFor("identity-B"), null, "an unseen identity has no floor");
  assert.equal(store.floorFor(""), null);
});

test("a backing store cannot weaken monotonicity — the rule is enforced above it", () => {
  const backing = new Map();
  const store = new RelayContractFloorStore({
    backing: { get: (k) => (backing.has(k) ? backing.get(k) : null), set: (k, v) => backing.set(k, v) },
  });
  store.recordObserved({ relayIdentityB64: "R", contractVersion: 5 });
  // A hostile/buggy backing hands back garbage; reads treat it as unobserved
  // rather than trusting it.
  backing.set("R", "five");
  assert.equal(store.floorFor("R"), null, "a non-integer backing value is not a floor");
  backing.set("R", 5);
  const r = store.recordObserved({ relayIdentityB64: "R", contractVersion: 4 });
  assert.equal(backing.get("R"), 5, "the lower observation never reached the backing");
  assert.equal(r.downgrade, true);
});

test("recordObserved fails loud on garbage instead of recording nonsense", () => {
  const store = new RelayContractFloorStore();
  assert.throws(() => store.recordObserved({ relayIdentityB64: "", contractVersion: 5 }));
  assert.throws(() => store.recordObserved({ relayIdentityB64: "R", contractVersion: 0 }));
  assert.throws(() => store.recordObserved({ relayIdentityB64: "R", contractVersion: 4.5 }));
  assert.throws(() => store.recordObserved({ relayIdentityB64: "R" }));
});

// ---- The policy half: a fact is not a decision ----

test("permitsAccountModeAuth: record-only default always permits; enforcement refuses only a pinned known-v5 relay", () => {
  const store = new RelayContractFloorStore();

  // Unknown relay: permitted regardless of enforcement.
  assert.equal(permitsAccountModeAuth({ relayIdentityB64: "R", floorStore: store, enforce: true }).permitted, true);

  store.recordObserved({ relayIdentityB64: "R", contractVersion: 4 });
  assert.equal(permitsAccountModeAuth({ relayIdentityB64: "R", floorStore: store, enforce: true }).permitted, true,
    "a v4-only relay is not a downgrade target");

  store.recordObserved({ relayIdentityB64: "R", contractVersion: 5 });
  const recorded = permitsAccountModeAuth({ relayIdentityB64: "R", floorStore: store });
  assert.equal(recorded.permitted, true, "DEFAULT is record-only: nothing is refused");
  assert.equal(recorded.reason, "downgrade-condition-recorded");

  const enforced = permitsAccountModeAuth({ relayIdentityB64: "R", floorStore: store, enforce: true });
  assert.equal(enforced.permitted, false, "opt-in enforcement refuses the identity-bearing handshake");
  assert.equal(enforced.floor, 5);

  // No pinned identity / no store → nothing to gate on; permitted.
  assert.equal(permitsAccountModeAuth({ relayIdentityB64: "", floorStore: store, enforce: true }).permitted, true);
  assert.equal(permitsAccountModeAuth({ relayIdentityB64: "R", floorStore: null, enforce: true }).permitted, true);
});
