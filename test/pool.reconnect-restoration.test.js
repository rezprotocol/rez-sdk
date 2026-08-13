import test from "node:test";
import assert from "node:assert/strict";

import { UplinkPool } from "../src/pool/UplinkPool.js";
import { TypedEventBus } from "../src/events/TypedEventBus.js";
import { SDK_EVENTS } from "../src/events/SdkEvents.js";

class FakeTransport {
  constructor(url) {
    this.url = url;
    this.frameHandler = null;
    this.stateHandler = null;
  }

  onFrame(handler) {
    this.frameHandler = handler;
    return () => { this.frameHandler = null; };
  }

  onState(handler) {
    this.stateHandler = handler;
    return () => { this.stateHandler = null; };
  }

  async connect() {}

  async close() {}

  async sendRequest() {
    return { body: {} };
  }

  disconnect() {
    if (this.stateHandler) this.stateHandler({ phase: "disconnected", reason: "test" });
  }
}

async function waitFor(predicate, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("condition not reached");
}

test("warm-spare failover awaits session restoration before announcing reconnect", async () => {
  const eventBus = new TypedEventBus();
  const transports = new Map();
  const order = [];
  const authMachine = {
    sessionInfo: { nodeKeyId: "node", nodePublicKeyB64: "pub", relayKeyId: "relay" },
    async authenticate() {},
  };
  const pool = new UplinkPool({
    uplinks: ["ws://one", "ws://two"],
    transportFactory(url) {
      const transport = new FakeTransport(url);
      transports.set(url, transport);
      return transport;
    },
    authMachine,
    eventBus,
    warmSpareCount: 1,
  });
  pool.onState((state) => {
    if (state && state.phase) order.push("state:" + state.phase);
  });
  pool.onReconnected(async () => {
    order.push("restore:start");
    await Promise.resolve();
    order.push("restore:end");
  });
  eventBus.on(SDK_EVENTS.TRANSPORT_RECONNECTED, () => order.push("event:reconnected"));

  await pool.connect();
  order.length = 0;
  transports.get("ws://one").disconnect();
  await waitFor(() => pool.getActiveUplink() === "ws://two" && order.includes("event:reconnected"));

  assert.deepEqual(order, [
    "state:failover",
    "restore:start",
    "restore:end",
    "event:reconnected",
    "state:connected",
  ]);
  await pool.close();
});

test("failed session restoration refuses to announce a usable replacement session", async () => {
  const eventBus = new TypedEventBus();
  const transports = new Map();
  let reconnectEvents = 0;
  const pool = new UplinkPool({
    uplinks: ["ws://one", "ws://two"],
    transportFactory(url) {
      const transport = new FakeTransport(url);
      transports.set(url, transport);
      return transport;
    },
    authMachine: {
      sessionInfo: { nodeKeyId: "node", nodePublicKeyB64: "pub", relayKeyId: "relay" },
      async authenticate() {},
    },
    eventBus,
    warmSpareCount: 1,
  });
  pool.onReconnected(async () => { throw new Error("binding refused"); });
  eventBus.on(SDK_EVENTS.TRANSPORT_RECONNECTED, () => { reconnectEvents += 1; });

  await pool.connect();
  transports.get("ws://one").disconnect();
  await waitFor(() => pool.getActiveUplink() === null);

  assert.equal(reconnectEvents, 0);
  assert.equal(pool.getSessionInfo(), null);
  await pool.close();
});
