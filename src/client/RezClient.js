import { SDK_EVENTS } from "../events/SdkEvents.js";
import { REZ_CONTRACT_TYPES, buildInboxAddress } from "@rezprotocol/core";
import { wrapAccountStateEnvelope, siblingInboxesFromDeviceSet, accountStateAad } from "../peer-link/accountStateSeal.js";
import { MetricsCollector } from "../observability/MetricsCollector.js";
import { MailboxCapability } from "../capabilities/MailboxCapability.js";
import { DurableRecordsCapability } from "../capabilities/DurableRecordsCapability.js";
import { NodeCapability } from "../capabilities/NodeCapability.js";
import { SubscriptionCapability } from "../capabilities/SubscriptionCapability.js";
import { ConnectivityCapability } from "../capabilities/ConnectivityCapability.js";
import { IdentityCapability } from "../capabilities/IdentityCapability.js";
import { DevicesCapability } from "../capabilities/DevicesCapability.js";
import { AccountOutboxCapability } from "../capabilities/AccountOutboxCapability.js";
import { MeshCapability } from "../capabilities/MeshCapability.js";
import { bytesToBase64, base64ToBytes } from "../util/bytes.js";
import { requireResponseBody } from "../util/responseBody.js";
import { buildRezClientRuntime } from "./buildRezClientRuntime.js";
import { RezPayloadSendParams } from "./RezPayloadSendParams.js";

const T = REZ_CONTRACT_TYPES;

/**
 * RezClient — high-level facade composing pool + event bus + auth + capabilities.
 *
 * Access pattern: rez.mailbox.deposit(...), rez.subscriptions.onMailboxDeposited(...).
 * Peer-link create/accept/get/list moved to chat-server-local PeerLinkService
 * in Shape A; the SDK no longer exposes a peerLinks capability.
 */
export class RezClient {
  #pool;
  #eventBus;
  #authMachine;
  #metrics;
  #identity;
  #started;
  #connected;
  #startPromise;
  #connectPromise;
  #stopPromise;

  // Capabilities
  #mailbox;
  #durableRecords;
  #node;
  #subscriptions;
  #connectivity;
  #identityCap;
  #devices;
  #accountOutbox;
  #mesh;
  // Local PeerLinkService instance (Shape A). When set, the SDK encrypts
  // outbound messages locally and sends them as plain MAILBOX_DEPOSIT, so the
  // node never sees plaintext. Constructed by the caller (e.g. chat-server)
  // and injected via the `peerLinkService` option. See docs/CAPABILITY_MODEL.md
  // and project_relay_network_thesis.md.
  #peerLinkService;

  // Mesh-status subscribers (passive — fires on refreshMesh)
  #meshHandlers;

  constructor(options = {}) {
    const runtime = this.#resolveRuntime(options);
    const { pool, eventBus, authMachine, metrics, identity } = runtime;
    const opts = options && typeof options === "object" ? options : {};
    this.#peerLinkService = opts.peerLinkService || null;

    this.#pool = pool;
    this.#eventBus = eventBus;
    this.#authMachine = authMachine;
    this.#metrics = metrics || new MetricsCollector();
    this.#identity = identity;
    this.#started = false;
    this.#connected = false;
    this.#startPromise = null;
    this.#connectPromise = null;
    this.#stopPromise = null;

    // Wire metrics to pool events
    this.#eventBus.on(SDK_EVENTS.CONNECTION_STATE_CHANGED, () => {
      this.#metrics.increment("sdk.connection.state_changes");
    });
    this.#eventBus.on(SDK_EVENTS.TRANSPORT_RECONNECTED, () => {
      this.#metrics.increment("sdk.reconnect.count");
    });
    this.#eventBus.on(SDK_EVENTS.AUTH_AUTHENTICATED, () => {
      this.#metrics.increment("sdk.auth.attempts");
    });

    // Initialize capabilities
    this.#meshHandlers = new Set();
    this.#mailbox = new MailboxCapability({ pool });
    this.#durableRecords = new DurableRecordsCapability({ pool });
    this.#node = new NodeCapability({ pool });
    this.#subscriptions = new SubscriptionCapability({ pool, eventBus });
    this.#connectivity = new ConnectivityCapability({ pool, eventBus });
    this.#identityCap = new IdentityCapability({ pool, eventBus, identity });
    this.#devices = new DevicesCapability({ pool });
    this.#accountOutbox = new AccountOutboxCapability({ pool });
    // The one mesh-dispatch verb. Delegates to mailbox / durableRecords so the
    // wire op stays single-sourced; apps call rez.mesh.dispatch(object, address).
    this.#mesh = new MeshCapability({ mailbox: this.#mailbox, durableRecords: this.#durableRecords });
  }

  #resolveRuntime(options) {
    const row = options && typeof options === "object" ? options : {};
    if (row.pool || row.eventBus || row.authMachine) {
      if (!row.pool) throw new Error("RezClient requires pool");
      if (!row.eventBus) throw new Error("RezClient requires eventBus");
      if (!row.authMachine) throw new Error("RezClient requires authMachine");
      return {
        pool: row.pool,
        eventBus: row.eventBus,
        authMachine: row.authMachine,
        metrics: row.metrics,
        identity: row.identity,
      };
    }
    return buildRezClientRuntime(row, "RezClient");
  }

  // --- Lifecycle ---

  async start() {
    if (this.#started) return this;
    if (this.#startPromise) return this.#startPromise;
    this.#startPromise = (async () => {
      this.#eventBus.emit(SDK_EVENTS.LIFECYCLE_START, { client: this });
      try {
        this.#started = true;
        this.#eventBus.emit(SDK_EVENTS.LIFECYCLE_READY, { client: this });
        return this;
      } catch (err) {
        this.#emitError(err, "start");
        this.#started = false;
        throw err;
      } finally {
        this.#startPromise = null;
      }
    })();
    return this.#startPromise;
  }

  async connect() {
    if (this.#connected) return this;
    if (this.#connectPromise) return this.#connectPromise;
    this.#connectPromise = (async () => {
      try {
        if (!this.#started) {
          await this.start();
        }
        await this.#pool.connect();
        this.#connected = true;
        this.#eventBus.emit(SDK_EVENTS.LIFECYCLE_CONNECT, { client: this });
        this.#eventBus.emit(SDK_EVENTS.SESSION_READY, {});
        return this;
      } catch (err) {
        this.#emitError(err, "connect");
        this.#connected = false;
        throw err;
      } finally {
        this.#connectPromise = null;
      }
    })();
    return this.#connectPromise;
  }

  async disconnect() {
    if (!this.#connected) return this;
    try {
      await this.#pool.close();
      this.#connected = false;
      this.#eventBus.emit(SDK_EVENTS.LIFECYCLE_DISCONNECT, { client: this });
      this.#eventBus.emit(SDK_EVENTS.SESSION_LOST, {});
      return this;
    } catch (err) {
      this.#emitError(err, "disconnect");
      throw err;
    }
  }

  async close() {
    return this.stop();
  }

  async stop() {
    if (this.#stopPromise) return this.#stopPromise;
    this.#stopPromise = (async () => {
      try {
        if (this.#connected) {
          await this.disconnect();
        }
        if (!this.#started) return this;
        this.#started = false;
        this.#eventBus.emit(SDK_EVENTS.LIFECYCLE_STOP, { client: this });
        return this;
      } catch (err) {
        this.#emitError(err, "stop");
        throw err;
      } finally {
        this.#stopPromise = null;
      }
    })();
    return this.#stopPromise;
  }

  #emitError(err, phase) {
    this.#eventBus.emit(SDK_EVENTS.LIFECYCLE_ERROR, {
      phase,
      error: err,
      message: err && typeof err.message === "string" ? err.message : String(err),
    });
  }

  // --- State ---

  get connectionState() {
    return this.#pool.getActiveUplink() ? "connected" : "disconnected";
  }

  get authState() {
    return this.#authMachine.state;
  }

  getSessionInfo() {
    return this.#pool.getSessionInfo();
  }

  /**
   * Returns the identity by which this client is known to its node — same
   * shape that the in-process `nodeRuntime.getIdentity()` returns. Sourced
   * from session.ready (so it reflects what the node confirmed for this
   * authenticated session, not just what the client requested).
   */
  getIdentity() {
    const session = this.#pool.getSessionInfo();
    const id = session && typeof session === "object" ? session : {};
    return {
      accountId: typeof id.accountId === "string" ? id.accountId : (this.#identity && this.#identity.accountId) || "",
      deviceId: typeof id.deviceId === "string" ? id.deviceId : (this.#identity && this.#identity.deviceId) || "",
      localInboxId: typeof id.localInboxId === "string" ? id.localInboxId : "",
      nodePublicKeyB64: typeof id.nodePublicKeyB64 === "string" ? id.nodePublicKeyB64 : "",
    };
  }

  getActiveUplink() {
    return this.#pool.getActiveUplink();
  }

  getUplinkStates() {
    return this.#pool.getUplinkStates();
  }

  // --- Events ---

  on(name, handler) {
    if (name === "payload") {
      return this.#subscriptions.onMailboxDeposited((frame) => {
        handler(this.#payloadEventFromFrame(frame));
      });
    }
    return this.#eventBus.on(name, handler);
  }

  once(name, handler) {
    return this.#eventBus.once(name, handler);
  }

  off(name, handler) {
    return this.#eventBus.off(name, handler);
  }

  // --- Pool state (direct pool lifecycle events) ---

  onPoolState(handler) {
    if (typeof handler !== "function") {
      throw new Error("onPoolState(handler) requires a function");
    }
    return this.#pool.onState(handler);
  }

  // --- Raw request (generic — for app-specific wire types) ---

  async sendRequest(args = {}) {
    const startMs = Date.now();
    this.#metrics.increment("sdk.request.count");
    try {
      const result = await this.#pool.sendRequest(args);
      this.#metrics.record("sdk.request.duration_ms", Date.now() - startMs);
      return result;
    } catch (err) {
      this.#metrics.record("sdk.request.duration_ms", Date.now() - startMs);
      throw err;
    }
  }

  async sendPayload(args = {}) {
    const params = args instanceof RezPayloadSendParams ? args : new RezPayloadSendParams(args);
    const objectId = params.objectId || "payload_" + Date.now() + "_" + Math.random().toString(36).slice(2, 10);
    const response = await this.#pool.sendRequest({
      type: T.MAILBOX_DEPOSIT,
      body: {
        mailboxId: params.deliverInboxId,
        objectId,
        ciphertextB64: bytesToBase64(new Uint8Array(params.payloadBytes)),
        metadata: {},
      },
      expectedResponseType: T.MAILBOX_DEPOSIT_RES,
    });
    // Same MAILBOX_DEPOSIT_RES contract MailboxCapability.deposit is pinned to: mailboxId always,
    // eventId present but empty on the queued branch. The `||` defaults below are for that queued
    // case, NOT for a missing response — drift now throws before it can look like a delivery.
    const body = requireResponseBody({
      op: "RezClient.sendPayload",
      response,
      require: { mailboxId: "nonEmptyString", eventId: "string" },
    });
    return {
      mailboxId: body.mailboxId || params.deliverInboxId,
      eventId: body.eventId || null,
      objectId,
      receiptInboxId: params.receiptInboxId || null,
      queued: body.queued === true,
    };
  }

  /**
   * Seal a plaintext body for a peer (Shape A — the "build the object" step).
   *
   * This is an identity/relationship concern: it encrypts locally via the
   * injected peerLinkService, resolves the peer's current inbox into a protocol
   * `inbox(inboxId)` address, and attaches the inviter-signed post-cap (if any).
   * It NEVER touches a transport — it returns a ready-to-dispatch mesh object
   * plus its protocol address, which the caller hands straight to
   * `rez.mesh.dispatch(sealed.object, sealed.address)`. The dispatch-object
   * shape is single-sourced HERE so no creator re-assembles it. Routing owns
   * mechanism selection; the creator only seals and dispatches.
   *
   * @returns {Promise<{ object: { payloadBytes: Uint8Array, metadata: object, capChain: array|null }, address: object }>}
   */
  async sealForPeer({ peerAccountId, plaintextBodyBytes, deliverInboxId, receiptInboxId } = {}) {
    if (!(plaintextBodyBytes instanceof Uint8Array)) {
      throw new Error("sealForPeer requires Uint8Array plaintextBodyBytes");
    }
    const remote = typeof peerAccountId === "string" ? peerAccountId.trim() : "";
    if (!remote) {
      throw new Error("sealForPeer requires peerAccountId");
    }
    const peerLinkService = this.#peerLinkService;
    if (!peerLinkService || typeof peerLinkService.encryptDirectMessage !== "function") {
      throw new Error("sealForPeer requires a peerLinkService — pass one to createRezClient");
    }

    let resolvedDeliverInboxId = typeof deliverInboxId === "string" ? deliverInboxId.trim() : "";
    let peerLinkRecord = null;
    if (!resolvedDeliverInboxId) {
      const storage = peerLinkService.peerLinkStorage;
      const ownerAccountId = peerLinkService.ownerAccountId;
      if (!storage || !ownerAccountId) {
        const err = new Error("sealForPeer: cannot resolve deliverInboxId — peerLinkService missing storage or ownerAccountId");
        err.code = "NO_DELIVERY_TARGET";
        throw err;
      }
      peerLinkRecord = await storage.peerLinks.getByPair(ownerAccountId, remote);
      if (!peerLinkRecord || typeof peerLinkRecord.peerInboxId !== "string" || !peerLinkRecord.peerInboxId.trim()) {
        const err = new Error("sealForPeer: no peer-link target inbox for " + remote);
        err.code = "NO_DELIVERY_TARGET";
        throw err;
      }
      resolvedDeliverInboxId = peerLinkRecord.peerInboxId.trim();
    } else if (peerLinkService.peerLinkStorage && peerLinkService.ownerAccountId) {
      peerLinkRecord = await peerLinkService.peerLinkStorage.peerLinks.getByPair(
        peerLinkService.ownerAccountId, remote,
      );
    }

    const encResult = await peerLinkService.encryptDirectMessage({
      peerAccountId: remote,
      plaintextBytes: plaintextBodyBytes,
    });
    if (!encResult || !encResult.encryptedPacket) {
      throw new Error("sealForPeer: peerLinkService.encryptDirectMessage returned no packet");
    }
    const ciphertextBytes = encResult.encryptedPacket.toBytes();

    // Look up the inviter-signed bearer post-cap for this peer-link, if one
    // was attached at invite time. Without a cap, delivery relies on the
    // recipient's relay accepting anonymous deposits (subject to its pubkey
    // blocklist).
    let capChain = null;
    if (peerLinkRecord && peerLinkRecord.peerLinkId && typeof peerLinkService.getPostCapForPeerLink === "function") {
      const cap = await peerLinkService.getPostCapForPeerLink(peerLinkService.ownerAccountId, peerLinkRecord.peerLinkId);
      if (cap) capChain = [cap];
    }

    const metadata = {};
    if (typeof receiptInboxId === "string" && receiptInboxId.trim().length > 0) {
      metadata.receiptInboxId = receiptInboxId.trim();
    }

    return {
      object: {
        payloadBytes: ciphertextBytes,
        metadata,
        capChain: Array.isArray(capChain) && capChain.length > 0 ? capChain : null,
      },
      address: buildInboxAddress({ inboxId: resolvedDeliverInboxId }),
    };
  }

  /**
   * Seal a message for ONE recipient DEVICE (S2.5 Slice 5 per-device fan-out).
   * Mirrors sealForPeer but uses the per-device session (peerDeviceId) and
   * delivers to that device's own inbox. The caller (rez-chat fan-out) resolves
   * the recipient's device set and calls this once per device. `deliverInboxId`
   * is the device's inbox (from its DeviceSetRecordV1 entry). `deviceHandshakeData`
   * (when present) is the X3DH initiator output the recipient device needs to
   * complete its responder session before it can decrypt — carried on first
   * contact; the inbound pipeline routes it to completeDeviceSetResponder.
   *
   * This is the GATED path: it is only called when the E6 fan-out gate is open
   * (Slice 8). The default send path stays sealForPeer (single-device).
   */
  async sealForPeerDevice({ peerAccountId, peerDeviceId, deliverInboxId, plaintextBodyBytes, receiptInboxId, deviceHandshakeData = null } = {}) {
    if (!(plaintextBodyBytes instanceof Uint8Array)) {
      throw new Error("sealForPeerDevice requires Uint8Array plaintextBodyBytes");
    }
    const remote = typeof peerAccountId === "string" ? peerAccountId.trim() : "";
    if (!remote) {
      throw new Error("sealForPeerDevice requires peerAccountId");
    }
    const device = typeof peerDeviceId === "string" ? peerDeviceId.trim() : "";
    if (!device) {
      throw new Error("sealForPeerDevice requires peerDeviceId");
    }
    const deliver = typeof deliverInboxId === "string" ? deliverInboxId.trim() : "";
    if (!deliver) {
      throw new Error("sealForPeerDevice requires deliverInboxId (the recipient device's inbox)");
    }
    const peerLinkService = this.#peerLinkService;
    if (!peerLinkService || typeof peerLinkService.encryptDirectMessageForDevice !== "function") {
      throw new Error("sealForPeerDevice requires a peerLinkService with per-device sessions");
    }

    let peerLinkRecord = null;
    if (peerLinkService.peerLinkStorage && peerLinkService.ownerAccountId) {
      peerLinkRecord = await peerLinkService.peerLinkStorage.peerLinks.getByPair(
        peerLinkService.ownerAccountId, remote,
      );
    }
    const peerLinkId = peerLinkRecord && typeof peerLinkRecord.peerLinkId === "string" && peerLinkRecord.peerLinkId.trim().length > 0
      ? peerLinkRecord.peerLinkId.trim()
      : null;

    const encResult = await peerLinkService.encryptDirectMessageForDevice({
      peerAccountId: remote,
      peerLinkId,
      peerDeviceId: device,
      plaintextBytes: plaintextBodyBytes,
    });
    if (!encResult || !encResult.encryptedPacket) {
      throw new Error("sealForPeerDevice: encryptDirectMessageForDevice returned no packet");
    }
    let payloadBytes = encResult.encryptedPacket.toBytes();

    // First-contact device handshake — carried IN-BAND in the deposit envelope,
    // NOT in the wire metadata (Audit P1). The envelope IS the stored outer-packet
    // body; the durable home log persists ONLY those bytes and drops metadata, and
    // the receiver only ever parses the envelope (never metadata). So the responder
    // material must ride inside the envelope to survive the store AND reach the
    // receiver on both live-push and reconnect catch-up. It is bound to the SENDER's
    // identity so the receiver can complete the responder device session against us
    // (peerAccountId = our account, peerDeviceId = our device) before decrypting.
    if (deviceHandshakeData != null) {
      const senderAccountId = typeof peerLinkService.ownerAccountId === "string" ? peerLinkService.ownerAccountId.trim() : "";
      const senderDeviceId = typeof peerLinkService.deviceId === "string" ? peerLinkService.deviceId.trim() : "";
      if (!senderAccountId || !senderDeviceId) {
        throw new Error("sealForPeerDevice: a device handshake requires the sender's ownerAccountId + deviceId");
      }
      const env = JSON.parse(new TextDecoder().decode(payloadBytes));
      env.deviceHandshake = { senderAccountId, senderDeviceId, handshakeData: deviceHandshakeData };
      payloadBytes = new TextEncoder().encode(JSON.stringify(env));
    }

    let capChain = null;
    if (peerLinkRecord && peerLinkRecord.peerLinkId && typeof peerLinkService.getPostCapForPeerLink === "function") {
      const cap = await peerLinkService.getPostCapForPeerLink(peerLinkService.ownerAccountId, peerLinkRecord.peerLinkId);
      if (cap) capChain = [cap];
    }

    const metadata = { peerDeviceId: device };
    if (typeof receiptInboxId === "string" && receiptInboxId.trim().length > 0) {
      metadata.receiptInboxId = receiptInboxId.trim();
    }

    return {
      object: {
        payloadBytes,
        metadata,
        capChain: Array.isArray(capChain) && capChain.length > 0 ? capChain : null,
      },
      address: buildInboxAddress({ inboxId: deliver }),
    };
  }

  /**
   * The SIBLING device inboxes of THIS account (S2.5 S14) — the home-served
   * account device set minus this device's own inbox/deviceId. The self fan-out
   * targets for an account-state event. @returns {Promise<Array<{deviceId,inboxId}>>}
   */
  async listSiblingDeviceInboxes() {
    const identity = this.getIdentity();
    const ownInboxId = identity && typeof identity.localInboxId === "string" ? identity.localInboxId : "";
    const ownDeviceId = this.#peerLinkService && typeof this.#peerLinkService.deviceId === "string"
      ? this.#peerLinkService.deviceId : "";
    const { devices } = await this.#devices.getAccountDeviceSet();
    return siblingInboxesFromDeviceSet({ devices, ownInboxId, ownDeviceId });
  }

  /**
   * Build a self account-state deposit (S2.5 S14): seal the event under the
   * account-state key (openable only by this account's own devices) and address it
   * to a sibling inbox. Returns the same {object,address} shape sealForPeerDevice
   * does, so the caller dispatches it via the identical sdk.mesh.dispatch path.
   * @returns {Promise<{object:object, address:object}>}
   */
  async buildAccountStateDeposit({ deliverInboxId, plaintextBodyBytes } = {}) {
    if (!(plaintextBodyBytes instanceof Uint8Array) || plaintextBodyBytes.length === 0) {
      throw new Error("buildAccountStateDeposit requires non-empty plaintextBodyBytes");
    }
    const deliver = typeof deliverInboxId === "string" ? deliverInboxId.trim() : "";
    if (!deliver) {
      throw new Error("buildAccountStateDeposit requires deliverInboxId (a sibling device inbox)");
    }
    const peerLinkService = this.#peerLinkService;
    if (!peerLinkService || typeof peerLinkService.sealAccountStateEvent !== "function") {
      throw new Error("buildAccountStateDeposit requires a peerLinkService with account-state sealing");
    }
    // Bind the ciphertext to its delivery inbox (AAD) so it can't be relocated to
    // another of the account's inboxes (audit F3, cross-inbox replay).
    const sealed = await peerLinkService.sealAccountStateEvent({ plaintextBytes: plaintextBodyBytes, aad: accountStateAad(deliver) });
    const envelope = wrapAccountStateEnvelope({ nonceB64: sealed.nonceB64, ciphertextB64: sealed.ciphertextB64 });
    return {
      object: {
        payloadBytes: new TextEncoder().encode(JSON.stringify(envelope)),
        metadata: {},
        capChain: null,
      },
      address: buildInboxAddress({ inboxId: deliver }),
    };
  }

  /**
   * Trigger and return the latest mesh status from the node. Mirrors the
   * in-process `nodeRuntime.refreshMesh()`. Notifies any subscribers
   * registered via onMeshStatusChanged.
   */
  async refreshMesh() {
    if (!this.#node || typeof this.#node.status !== "function") return null;
    const status = await this.#node.status({});
    const mesh = status && typeof status === "object" && status.mesh && typeof status.mesh === "object"
      ? status.mesh
      : null;
    if (mesh) {
      for (const handler of [...this.#meshHandlers]) {
        try { handler(mesh); } catch { /* ignore subscriber errors */ }
      }
    }
    return mesh;
  }

  /**
   * Subscribe to mesh-status changes. The SDK does not yet receive mesh
   * push events from the node; for now this fires whenever refreshMesh()
   * is invoked. Hosted-node push events plug into this same surface.
   */
  onMeshStatusChanged(handler) {
    if (typeof handler !== "function") return () => {};
    this.#meshHandlers.add(handler);
    return () => { this.#meshHandlers.delete(handler); };
  }

  #payloadEventFromFrame(frame) {
    const body = frame && frame.body && typeof frame.body === "object" ? frame.body : {};
    const ciphertextB64 = typeof body.ciphertextB64 === "string" ? body.ciphertextB64 : "";
    return {
      mailboxId: body.mailboxId || null,
      eventId: body.eventId || null,
      objectId: body.objectId || null,
      payloadBytes: ciphertextB64 ? base64ToBytes(ciphertextB64) : new Uint8Array(0),
      frame,
    };
  }

  // --- Metrics ---

  getMetrics() {
    return this.#metrics.snapshot();
  }

  // --- Capabilities ---

  get mailbox() {
    return this.#mailbox;
  }

  get durableRecords() {
    return this.#durableRecords;
  }

  get node() {
    return this.#node;
  }

  get subscriptions() {
    return this.#subscriptions;
  }

  get connectivity() {
    return this.#connectivity;
  }

  get identity() {
    return this.#identityCap;
  }

  get devices() {
    return this.#devices;
  }

  /**
   * The account authority-state propagation outbox (P1#3): claim → prepare → publish →
   * complete. Only an authorized device can drain it — the node cannot publish an
   * account-signed record on the account's behalf.
   */
  get accountOutbox() {
    return this.#accountOutbox;
  }

  get mesh() {
    return this.#mesh;
  }
}
