import test from "node:test";
import assert from "node:assert/strict";
import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";

const T = REZ_CONTRACT_TYPES;

// --- RCGP primitive types ---

test("MAILBOX_DEPOSIT has correct value", () => {
  assert.equal(T.MAILBOX_DEPOSIT, "mailbox.deposit");
});

test("MAILBOX_LIST has correct value", () => {
  assert.equal(T.MAILBOX_LIST, "mailbox.list");
});

test("NODE_STATUS has correct value", () => {
  assert.equal(T.NODE_STATUS, "node.status");
});

test("EVT_MAILBOX_DEPOSITED has correct value", () => {
  assert.equal(T.EVT_MAILBOX_DEPOSITED, "evt.mailbox.deposited");
});

// --- Session types ---

test("SESSION_HELLO has correct value", () => {
  assert.equal(T.SESSION_HELLO, "session.hello");
});

test("SESSION_READY has correct value", () => {
  assert.equal(T.SESSION_READY, "session.ready");
});

test("ERROR has correct value", () => {
  assert.equal(T.ERROR, "error");
});
