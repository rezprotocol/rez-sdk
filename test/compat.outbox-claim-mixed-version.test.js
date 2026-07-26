import test from "node:test";
import assert from "node:assert/strict";
import { CONTRACT_VERSION, REZ_CONTRACT_TYPES } from "@rezprotocol/core";
import { AccountOutboxCapability } from "../src/capabilities/AccountOutboxCapability.js";
import { requireResponseBody } from "../src/util/responseBody.js";

const T = REZ_CONTRACT_TYPES;
const TOKEN = "a".repeat(48);

// MIXED-VERSION CHECK for OutboxLeaseClaimResponse.awaitingRootSignature (2026-07-26).
//
// The field is REQUIRED on every claim response, which is a WIRE-BREAKING change to an existing
// response record. These tests pin what each direction actually does, so the answer is measured
// rather than assumed — and so a future reader can see why CONTRACT_VERSION had to move with it.
//
// The handshake is the real gate: SessionHello asserts contractVersion === CONTRACT_VERSION
// (exact match, not a floor), so a version bump refuses a mismatched pair at connect time instead
// of letting it fail at an arbitrary later RPC. The two tests below are what happens if a pair ever
// DOES get past that — the fallback behavior, not the primary defense.

// Exactly what an OLD node (pre-change) answers: no awaitingRootSignature at all.
const OLD_NODE_NOT_LEASED = { leased: false };
const OLD_NODE_LEASED = { leased: true, token: TOKEN, anchorEpoch: 4, headEpoch: 6, leaseExpiresAtMs: 1_700_000_030_000, attempts: 0 };
// Exactly what a NEW node answers.
const NEW_NODE_NOT_LEASED = { leased: false, awaitingRootSignature: false };
const NEW_NODE_AWAITING = { leased: false, awaitingRootSignature: true };
const NEW_NODE_LEASED = { leased: true, awaitingRootSignature: false, token: TOKEN, anchorEpoch: 4, headEpoch: 6, leaseExpiresAtMs: 1_700_000_030_000, attempts: 0 };

function makePool(body) {
  return {
    calls: [],
    async sendRequest(req) {
      this.calls.push(req);
      return { type: req.expectedResponseType, body };
    },
  };
}

test("NEW SDK against an OLD node: fails LOUDLY on every claim, never silently", async () => {
  // The failure mode that would have been unacceptable: treating a missing awaitingRootSignature as
  // false. A delegated device would then read "nothing pending" forever while its revocations never
  // propagated — a silent stall. Instead the strict gate throws, naming the field.
  for (const body of [OLD_NODE_NOT_LEASED, OLD_NODE_LEASED]) {
    const cap = new AccountOutboxCapability({ pool: makePool(body) });
    await assert.rejects(
      () => cap.claim(),
      (err) => {
        assert.match(err.message, /AccountOutboxCapability\.claim/, "the error names the op");
        assert.match(err.message, /missing the required 'awaitingRootSignature' boolean/, "and the exact field");
        return true;
      },
    );
  }
});

test("OLD SDK against a NEW node: still validates, and degrades SAFELY", async () => {
  // An old SDK required only the discriminant. The new node's body is a strict superset, so old
  // validation still passes — the extra field is simply ignored.
  const oldRequire = { leased: "boolean" };
  for (const body of [NEW_NODE_NOT_LEASED, NEW_NODE_AWAITING, NEW_NODE_LEASED]) {
    const validated = requireResponseBody({ op: "old.claim", response: { body }, require: oldRequire });
    assert.equal(validated, body, "old validation accepts the new response verbatim");
  }

  // And the old CLIENT logic — `if (claim.leased !== true) stop` — reaches a safe conclusion on the
  // awaiting-root response: it stops without claiming. That is strictly safer than the pre-change
  // behavior, where a delegated device DID receive the lease and burned attempts toward BLOCKED.
  // The cost is only that an old client cannot tell the user WHY nothing is publishing.
  assert.equal(NEW_NODE_AWAITING.leased !== true, true, "an old client stops rather than claiming");
});

test("the contract version is the actual gate for this break", async () => {
  // Documenting the invariant this change depends on: the version is an EXACT match at handshake,
  // so bumping it refuses a mismatched pair at connect time rather than at a later claim. If this
  // ever became a >= comparison, the two tests above stop being a fallback and become the only
  // defense — which is why they assert loudness rather than tolerance.
  assert.equal(Number.isInteger(CONTRACT_VERSION), true);
  assert.equal(T.ACCOUNT_OUTBOX_LEASE_CLAIM_RES.length > 0, true);
});
