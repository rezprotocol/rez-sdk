import test from "node:test";
import assert from "node:assert/strict";
import { createRezClient, createRezClientAsync } from "../src/client/createRezClient.js";
import { RezClient } from "../src/client/RezClient.js";
import { TypedEventBus } from "../src/events/TypedEventBus.js";
import { AuthStateMachine } from "../src/auth/AuthStateMachine.js";
import { MetricsCollector } from "../src/observability/MetricsCollector.js";
import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";

const STUB_IDENTITY = {
  accountId: "acct:test",
  deviceId: "dev:1",
  publicKeyB64: "cHVibGljLWtleQ==",
  privateKeyB64: "cHJpdmF0ZS1rZXk=",
};

function createAuthMachine() {
  return new AuthStateMachine({
    identity: STUB_IDENTITY,
    eventBus: new TypedEventBus(),
  });
}

// --- createRezClient validation ---

test("createRezClient throws without uplinks", () => {
  assert.throws(
    () => createRezClient({ identity: STUB_IDENTITY }),
    /uplinks/i,
  );
});

test("createRezClient throws with empty uplinks array", () => {
  assert.throws(
    () => createRezClient({ uplinks: [], identity: STUB_IDENTITY }),
    /uplinks/i,
  );
});

test("createRezClient throws without identity", () => {
  assert.throws(
    () => createRezClient({ uplinks: ["ws://localhost:8080/ws"] }),
    /identity/i,
  );
});

test("createRezClient throws with incomplete identity (missing accountId)", () => {
  assert.throws(
    () =>
      createRezClient({
        uplinks: ["ws://localhost:8080/ws"],
        identity: { publicKeyB64: "a", privateKeyB64: "b" },
      }),
    /identity/i,
  );
});

test("createRezClient returns a RezClient instance", () => {
  const client = createRezClient({
    uplinks: ["ws://localhost:8080/ws"],
    identity: STUB_IDENTITY,
  });
  assert.ok(client instanceof RezClient);
});

test("new RezClient accepts public identity/uplinks options", () => {
  const client = new RezClient({
    uplinks: ["ws://localhost:8080/ws"],
    identity: STUB_IDENTITY,
  });
  assert.ok(client instanceof RezClient);
});

test("RezClient constructor is inert and does not create transports", () => {
  let constructed = 0;
  const client = new RezClient({
    uplinks: ["ws://localhost:8080/ws"],
    identity: STUB_IDENTITY,
    wsFactory: function FakeWebSocket() {
      constructed++;
    },
  });
  assert.ok(client instanceof RezClient);
  assert.equal(constructed, 0);
});

// --- RezClient public API shape ---

test("RezClient has expected lifecycle methods", () => {
  const client = createRezClient({
    uplinks: ["ws://localhost:8080/ws"],
    identity: STUB_IDENTITY,
  });
  assert.equal(typeof client.start, "function");
  assert.equal(typeof client.connect, "function");
  assert.equal(typeof client.disconnect, "function");
  assert.equal(typeof client.stop, "function");
  assert.equal(typeof client.close, "function");
});

test("RezClient has expected event methods", () => {
  const client = createRezClient({
    uplinks: ["ws://localhost:8080/ws"],
    identity: STUB_IDENTITY,
  });
  assert.equal(typeof client.on, "function");
  assert.equal(typeof client.once, "function");
  assert.equal(typeof client.off, "function");
});

test("RezClient does not expose lifecycle helper aliases", () => {
  const client = createRezClient({
    uplinks: ["ws://localhost:8080/ws"],
    identity: STUB_IDENTITY,
  });
  assert.equal(client.onStart, undefined);
  assert.equal(client.onStop, undefined);
  assert.equal(client.onConnect, undefined);
  assert.equal(client.onDisconnect, undefined);
  assert.equal(client.onReady, undefined);
});

test("RezClient has sendRequest method", () => {
  const client = createRezClient({
    uplinks: ["ws://localhost:8080/ws"],
    identity: STUB_IDENTITY,
  });
  assert.equal(typeof client.sendRequest, "function");
});

test("RezClient sends generic payloads as opaque mailbox deposits", async () => {
  const sent = [];
  const client = new RezClient({
    pool: {
      sendRequest: async (request) => {
        sent.push(request);
        return { body: { mailboxId: request.body.mailboxId, eventId: "evt-1" } };
      },
      on() {
        return () => {};
      },
      getActiveUplink() {
        return null;
      },
      getUplinkStates() {
        return [];
      },
      getSessionInfo() {
        return null;
      },
    },
    eventBus: new TypedEventBus(),
    authMachine: createAuthMachine(),
    metrics: new MetricsCollector(),
    identity: STUB_IDENTITY,
  });

  const result = await client.sendPayload({
    peerAccountId: "acct-remote",
    deliverInboxId: "inbox-remote",
    receiptInboxId: "inbox-local",
    payloadBytes: new Uint8Array([1, 2, 3]),
  });

  assert.equal(sent.length, 1);
  assert.equal(sent[0].type, REZ_CONTRACT_TYPES.MAILBOX_DEPOSIT);
  assert.equal(sent[0].body.mailboxId, "inbox-remote");
  assert.equal(sent[0].body.ciphertextB64, "AQID");
  assert.equal(Object.keys(sent[0].body.metadata).length, 0);
  assert.equal(result.eventId, "evt-1");
  assert.equal(result.objectId.startsWith("payload_"), true);
});

test("RezClient payload event alias decodes mailbox payload bytes", () => {
  const handlers = new Map();
  const client = new RezClient({
    pool: {
      sendRequest: async () => ({ body: {} }),
      on(type, handler) {
        handlers.set(type, handler);
        return () => handlers.delete(type);
      },
      getActiveUplink() {
        return null;
      },
      getUplinkStates() {
        return [];
      },
      getSessionInfo() {
        return null;
      },
    },
    eventBus: new TypedEventBus(),
    authMachine: createAuthMachine(),
    metrics: new MetricsCollector(),
    identity: STUB_IDENTITY,
  });

  const received = [];
  const off = client.on("payload", (evt) => received.push(evt));
  handlers.get(REZ_CONTRACT_TYPES.EVT_MAILBOX_DEPOSITED)({
    body: { mailboxId: "inbox-local", eventId: "evt-2", ciphertextB64: "BAUG" },
  });
  off();

  assert.equal(received.length, 1);
  assert.deepEqual([...received[0].payloadBytes], [4, 5, 6]);
  assert.equal(received[0].mailboxId, "inbox-local");
  assert.equal(handlers.has(REZ_CONTRACT_TYPES.EVT_MAILBOX_DEPOSITED), false);
});

test("RezClient has expected capability accessors", () => {
  const client = createRezClient({
    uplinks: ["ws://localhost:8080/ws"],
    identity: STUB_IDENTITY,
  });
  const expectedCapabilities = [
    "mailbox",
    "node",
    "subscriptions",
    "connectivity",
    "identity",
  ];
  for (const cap of expectedCapabilities) {
    assert.ok(client[cap] != null, `expected capability accessor '${cap}' to be defined`);
  }
});

test("RezClient has expected state getters", () => {
  const client = createRezClient({
    uplinks: ["ws://localhost:8080/ws"],
    identity: STUB_IDENTITY,
  });
  // connectionState returns a string
  assert.equal(typeof client.connectionState, "string");
  // authState returns a string
  assert.equal(typeof client.authState, "string");
});

test("RezClient emits lifecycle events in order with pre-start listeners", async () => {
  const events = [];
  const client = createLifecycleClient();
  client.on("start", () => events.push("start"));
  client.on("ready", () => events.push("ready"));
  client.on("connect", () => events.push("connect"));
  client.on("disconnect", () => events.push("disconnect"));
  client.on("stop", () => events.push("stop"));

  await client.start();
  await client.connect();
  await client.disconnect();
  await client.stop();

  assert.deepEqual(events, ["start", "ready", "connect", "disconnect", "stop"]);
});

test("RezClient connect starts first for backwards compatibility", async () => {
  const events = [];
  const client = createLifecycleClient();
  client.on("start", () => events.push("start"));
  client.on("ready", () => events.push("ready"));
  client.on("connect", () => events.push("connect"));

  await client.connect();

  assert.deepEqual(events, ["start", "ready", "connect"]);
});

test("RezClient lifecycle methods are idempotent", async () => {
  const events = [];
  const client = createLifecycleClient();
  for (const name of ["start", "ready", "connect", "disconnect", "stop"]) {
    client.on(name, () => events.push(name));
  }

  await client.start();
  await client.start();
  await client.connect();
  await client.connect();
  await client.disconnect();
  await client.disconnect();
  await client.stop();
  await client.stop();

  assert.deepEqual(events, ["start", "ready", "connect", "disconnect", "stop"]);
});

test("RezClient on() unsubscribe removes lifecycle listener", async () => {
  const events = [];
  const client = createLifecycleClient();
  const off = client.on("start", () => events.push("start"));
  off();

  await client.start();

  assert.deepEqual(events, []);
});

test("RezClient lifecycle errors emit error and reject", async () => {
  const events = [];
  const err = new Error("connect failed");
  const client = createLifecycleClient({
    async connect() {
      throw err;
    },
  });
  client.on("error", (payload) => events.push(payload));

  await assert.rejects(() => client.connect(), /connect failed/);

  assert.equal(events.length, 1);
  assert.equal(events[0].phase, "connect");
  assert.equal(events[0].error, err);
});

test("createRezClientAsync remains a compatibility helper", async () => {
  const client = await createRezClientAsync({
    uplinks: ["ws://localhost:8080/ws"],
    identity: STUB_IDENTITY,
  });
  assert.ok(client instanceof RezClient);
});

function createLifecycleClient(poolPatch = {}) {
  const eventBus = new TypedEventBus();
  let active = null;
  const pool = {
    async connect() {
      active = "ws://unit.test/ws";
    },
    async close() {
      active = null;
    },
    getActiveUplink() {
      return active;
    },
    getUplinkStates() {
      return [{
        url: "ws://unit.test/ws",
        active: active != null,
        ready: active != null,
        healthy: active != null,
      }];
    },
    getSessionInfo() {
      return active ? { accountId: STUB_IDENTITY.accountId, deviceId: STUB_IDENTITY.deviceId } : null;
    },
    sendRequest() {
      throw new Error("sendRequest unused in lifecycle tests");
    },
    onState() {
      return () => {};
    },
    ...poolPatch,
  };
  const authMachine = new AuthStateMachine({
    identity: STUB_IDENTITY,
    eventBus,
    sessionHello: { requestType: "session.hello", body: {} },
  });
  return new RezClient({
    pool,
    eventBus,
    authMachine,
    metrics: new MetricsCollector(),
    identity: STUB_IDENTITY,
  });
}
