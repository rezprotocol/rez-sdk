import test from "node:test";
import assert from "node:assert/strict";
import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";

import { AccountOutboxCapability } from "../src/capabilities/AccountOutboxCapability.js";
import { RezClient } from "../src/client/RezClient.js";

const T = REZ_CONTRACT_TYPES;
const TOKEN = "a".repeat(48); // the node mints a 48-hex lease token.

// A pool that records every request and answers with a scripted body.
function makePool(bodies) {
  const calls = [];
  const queue = Array.isArray(bodies) ? [...bodies] : [bodies];
  return {
    calls,
    async sendRequest(req) {
      calls.push(req);
      const body = queue.length > 1 ? queue.shift() : queue[0];
      return { body };
    },
  };
}

test("claim sends ACCOUNT_OUTBOX_LEASE_CLAIM with an empty body and returns the lease", async () => {
  const lease = { leased: true, token: TOKEN, anchorEpoch: 4, headEpoch: 6, leaseExpiresAtMs: 1_700_000_030_000, attempts: 0 };
  const pool = makePool(lease);
  const cap = new AccountOutboxCapability({ pool });

  const res = await cap.claim();

  assert.equal(pool.calls.length, 1);
  assert.equal(pool.calls[0].type, T.ACCOUNT_OUTBOX_LEASE_CLAIM);
  assert.equal(pool.calls[0].expectedResponseType, T.ACCOUNT_OUTBOX_LEASE_CLAIM_RES);
  // The account is the authenticated session's and the owner is the session device — NEITHER
  // is a wire field, so the body carries no client input at all.
  assert.deepEqual(pool.calls[0].body, {});
  assert.deepEqual(res, lease, "lease returned verbatim");
});

test("claim returns { leased: false } verbatim — nothing to publish is not an error", async () => {
  const pool = makePool({ leased: false });
  const cap = new AccountOutboxCapability({ pool });
  const res = await cap.claim();
  assert.deepEqual(res, { leased: false });
  assert.equal("token" in res, false, "no lease, no token");
});

test("prepare sends the token verbatim and returns the FROZEN epoch", async () => {
  const pool = makePool({ prepared: true, anchorEpoch: 4, headEpoch: 6 });
  const cap = new AccountOutboxCapability({ pool });

  const res = await cap.prepare({ leaseToken: TOKEN });

  assert.equal(pool.calls[0].type, T.ACCOUNT_OUTBOX_LEASE_PREPARE);
  assert.equal(pool.calls[0].expectedResponseType, T.ACCOUNT_OUTBOX_LEASE_PREPARE_RES);
  assert.deepEqual(pool.calls[0].body, { leaseToken: TOKEN });
  assert.equal(res.headEpoch, 6, "the epoch this lease must publish");
});

test("prepare returns { prepared: false } verbatim when the lease is gone", async () => {
  const pool = makePool({ prepared: false });
  const cap = new AccountOutboxCapability({ pool });
  const res = await cap.prepare({ leaseToken: TOKEN });
  assert.deepEqual(res, { prepared: false });
});

test("release sends ACCOUNT_OUTBOX_LEASE_RELEASE and reports whether this lease was released", async () => {
  const pool = makePool([{ released: true }, { released: false }]);
  const cap = new AccountOutboxCapability({ pool });

  const first = await cap.release({ leaseToken: TOKEN });
  assert.equal(pool.calls[0].type, T.ACCOUNT_OUTBOX_LEASE_RELEASE);
  assert.equal(pool.calls[0].expectedResponseType, T.ACCOUNT_OUTBOX_LEASE_RELEASE_RES);
  assert.deepEqual(pool.calls[0].body, { leaseToken: TOKEN });
  assert.deepEqual(first, { released: true });

  const second = await cap.release({ leaseToken: TOKEN });
  assert.deepEqual(second, { released: false }, "already-gone lease is a benign false, not an error");
});

test("fail returns the backoff accounting verbatim, including a blocked lease", async () => {
  const accounting = { recorded: true, attemptedEpoch: 6, anchorEpoch: 4, attempts: 9, backoffMs: 60_000, blocked: true };
  const pool = makePool(accounting);
  const cap = new AccountOutboxCapability({ pool });

  const res = await cap.fail({ leaseToken: TOKEN });

  assert.equal(pool.calls[0].type, T.ACCOUNT_OUTBOX_LEASE_FAIL);
  assert.equal(pool.calls[0].expectedResponseType, T.ACCOUNT_OUTBOX_LEASE_FAIL_RES);
  assert.deepEqual(pool.calls[0].body, { leaseToken: TOKEN });
  // blocked:true is operator-visible state, NOT an abandoned obligation — it must reach the
  // caller intact rather than being flattened into a bare boolean.
  assert.deepEqual(res, accounting);
});

test("fail returns { recorded: false } verbatim when there was no live lease", async () => {
  const pool = makePool({ recorded: false });
  const cap = new AccountOutboxCapability({ pool });
  assert.deepEqual(await cap.fail({ leaseToken: TOKEN }), { recorded: false });
});

test("complete carries the signed publication VERBATIM and returns the done watermark", async () => {
  const pool = makePool({ completed: true, doneThroughEpoch: 6 });
  const cap = new AccountOutboxCapability({ pool });
  // A DurableRecordV2 envelope shape — the node re-verifies signatures over these exact bytes.
  const record = {
    v: 2,
    recordKind: "rez.account.authority-state.v1",
    ownerPublicKeyB64: "acct-pub",
    payloadB64: "eyJlcG9jaCI6Nn0=",
    sig: { sigB64: "sig" },
    certChain: [{ certId: "rez:cap:" + "c".repeat(64) }],
  };

  const res = await cap.complete({ leaseToken: TOKEN, record });

  assert.equal(pool.calls[0].type, T.ACCOUNT_OUTBOX_LEASE_COMPLETE);
  assert.equal(pool.calls[0].expectedResponseType, T.ACCOUNT_OUTBOX_LEASE_COMPLETE_RES);
  assert.equal(pool.calls[0].body.leaseToken, TOKEN);
  assert.deepEqual(pool.calls[0].body.record, record, "record unreshaped");
  assert.equal(pool.calls[0].body.record, record, "record passed by reference — not cloned or trimmed");
  assert.deepEqual(res, { completed: true, doneThroughEpoch: 6 });
});

test("complete returns { completed: false } verbatim — the benign lease-lost race", async () => {
  const pool = makePool({ completed: false });
  const cap = new AccountOutboxCapability({ pool });
  const res = await cap.complete({ leaseToken: TOKEN, record: { v: 2 } });
  assert.deepEqual(res, { completed: false });
  assert.equal("doneThroughEpoch" in res, false, "a lost lease advanced no watermark");
});

test("every token-bearing op fails loud on a missing/blank/non-string token — nothing is sent", async () => {
  const pool = makePool({ prepared: true, anchorEpoch: 1, headEpoch: 1 });
  const cap = new AccountOutboxCapability({ pool });

  for (const op of ["prepare", "release", "fail"]) {
    await assert.rejects(() => cap[op]({}), new RegExp(op + " requires leaseToken"));
    await assert.rejects(() => cap[op](), new RegExp(op + " requires leaseToken"));
    await assert.rejects(() => cap[op]({ leaseToken: "" }), new RegExp(op + " requires leaseToken"));
    await assert.rejects(() => cap[op]({ leaseToken: 42 }), new RegExp(op + " requires leaseToken"));
  }
  await assert.rejects(() => cap.complete({ record: { v: 2 } }), /complete requires leaseToken/);
  assert.equal(pool.calls.length, 0, "an invalid token never reaches the wire");
});

test("complete fails loud on a missing or non-object record — nothing is sent", async () => {
  const pool = makePool({ completed: true, doneThroughEpoch: 1 });
  const cap = new AccountOutboxCapability({ pool });

  await assert.rejects(() => cap.complete({ leaseToken: TOKEN }), /complete requires record/);
  await assert.rejects(() => cap.complete({ leaseToken: TOKEN, record: null }), /complete requires record/);
  await assert.rejects(() => cap.complete({ leaseToken: TOKEN, record: "{}" }), /complete requires record/);
  await assert.rejects(() => cap.complete({ leaseToken: TOKEN, record: [] }), /complete requires record/);
  assert.equal(pool.calls.length, 0);
});

test("a response missing its discriminant THROWS — drift never reads as a benign no-op", async () => {
  // The dangerous coercions this guards: a missing `leased` reading as "nothing to publish",
  // and a missing `completed` reading as "the lease was lost". Both would silently stall
  // revocation propagation while looking like normal operation.
  const cases = [
    ["claim", {}, () => new AccountOutboxCapability({ pool: makePool({}) })],
    ["claim", { leased: "true" }, () => new AccountOutboxCapability({ pool: makePool({ leased: "true" }) })],
    ["prepare", {}, () => new AccountOutboxCapability({ pool: makePool({}) })],
    ["release", {}, () => new AccountOutboxCapability({ pool: makePool({}) })],
    ["fail", {}, () => new AccountOutboxCapability({ pool: makePool({}) })],
    ["complete", {}, () => new AccountOutboxCapability({ pool: makePool({}) })],
  ];
  const discriminants = { claim: "leased", prepare: "prepared", release: "released", fail: "recorded", complete: "completed" };
  for (const [op, , build] of cases) {
    const cap = build();
    const args = op === "complete" ? { leaseToken: TOKEN, record: { v: 2 } } : { leaseToken: TOKEN };
    await assert.rejects(
      () => cap[op](args),
      new RegExp("missing the required '" + discriminants[op] + "' boolean"),
      op + " must reject a drifted response",
    );
  }
});

test("a response with no body at all THROWS rather than returning an empty object", async () => {
  const cap = new AccountOutboxCapability({
    pool: { async sendRequest() { return { body: null }; } },
  });
  await assert.rejects(() => cap.claim(), /returned no response body/);

  const noResponse = new AccountOutboxCapability({
    pool: { async sendRequest() { return undefined; } },
  });
  await assert.rejects(() => noResponse.claim(), /returned no response body/);
});

test("RezClient exposes an accountOutbox capability", () => {
  const client = new RezClient({
    pool: { authState: "idle" },
    eventBus: { on: () => () => {} },
    authMachine: {},
    identity: { accountId: "rez:acct:test", publicKeyB64: "p", privateKeyB64: "s" },
  });
  assert.ok(client.accountOutbox instanceof AccountOutboxCapability);
});
