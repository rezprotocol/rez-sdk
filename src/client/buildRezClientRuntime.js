import { CONTRACT_VERSION, REZ_CONTRACT_TYPES } from "@rezprotocol/core";
import { TypedEventBus } from "../events/TypedEventBus.js";
import { SDK_EVENTS } from "../events/SdkEvents.js";
import { AuthStateMachine } from "../auth/AuthStateMachine.js";
import { UplinkPool } from "../pool/UplinkPool.js";
import { MetricsCollector } from "../observability/MetricsCollector.js";
import { WsTransport } from "../transport/WsTransport.js";
import { createFrameCodec } from "../transport/FrameCodec.js";

function assertPublicOptions({ uplinks, identity, callerName }) {
  if (!uplinks || !Array.isArray(uplinks) || uplinks.length === 0) {
    throw new Error(callerName + " requires uplinks[]");
  }
  const row = identity && typeof identity === "object" ? identity : null;
  if (!row || !row.accountId || !row.publicKeyB64 || !row.privateKeyB64) {
    throw new Error(callerName + " requires identity with accountId, publicKeyB64, privateKeyB64");
  }
}

function resolveUplinkUrl(url, scheme) {
  if (!url) return "";
  if (/^(ws|wss|tcp|tls):\/\//.test(url)) return url;

  const hasPort = url.includes(":");
  const host = hasPort ? url.split(":")[0] : url;
  const port = hasPort ? url.split(":")[1] : null;

  if (scheme === "tcp") return "tcp://" + host + ":" + (port || "8787");
  if (scheme === "tls") return "tls://" + host + ":" + (port || "8787");
  if (scheme === "ws") return "ws://" + host + ":" + (port || "8080") + "/ws";
  if (scheme === "wss") return "wss://" + host + ":" + (port || "443") + "/ws";

  if (port === "443" || port === "8443") return "wss://" + host + ":" + port + "/ws";
  if (port === "8787" || port === "8788") return "tcp://" + host + ":" + port;
  return "ws://" + host + ":" + (port || "8080") + "/ws";
}

function createTcpTransport({ TcpTransportClass, url, transportOpts }) {
  if (!TcpTransportClass) {
    throw new Error("TcpTransport must be created via async createRezClientAsync() or passed as tcpTransportClass");
  }
  const isTls = url.startsWith("tls://");
  const stripped = url.replace(/^(tcp|tls):\/\//, "");
  const parts = stripped.split(":");
  const hostPart = parts[0] || "127.0.0.1";
  const portStr = parts[1] || "8787";
  return new TcpTransportClass({
    host: hostPart,
    port: Number(portStr) || 8787,
    tls: isTls,
    frameCodec: transportOpts.frameCodec,
    timeouts: transportOpts.timeouts,
    maxFrameBytes: transportOpts.maxFrameBytes,
  });
}

export function normalizeRezClientOptions(options = {}, callerName = "RezClient") {
  const opts = options && typeof options === "object" ? options : {};
  assertPublicOptions({
    uplinks: opts.uplinks,
    identity: opts.identity,
    callerName,
  });

  const transportScheme = opts.transport || "auto";
  return {
    uplinks: opts.uplinks,
    identity: opts.identity,
    transportScheme,
    warmSpareCount: opts.warmSpareCount == null ? 2 : opts.warmSpareCount,
    timeouts: opts.timeouts && typeof opts.timeouts === "object" ? opts.timeouts : {},
    limits: opts.limits && typeof opts.limits === "object" ? opts.limits : {},
    dedupe: opts.dedupe && typeof opts.dedupe === "object" ? opts.dedupe : {},
    flood: opts.flood && typeof opts.flood === "object" ? opts.flood : {},
    wsFactory: opts.wsFactory,
    frameCodec: opts.frameCodec,
    sessionHello: opts.sessionHello,
    metrics: opts.metrics,
    clientVersion: opts.clientVersion,
    tcpTransportClass: opts.tcpTransportClass || null,
    // CRITICAL-2: when set, AuthStateMachine refuses any challenge whose
    // nodePublicKeyB64 doesn't match. For local/in-process node deployment
    // the launcher should pass the node's published pubkey here.
    expectedNodePublicKeyB64: typeof opts.expectedNodePublicKeyB64 === "string" ? opts.expectedNodePublicKeyB64 : "",
  };
}

export function buildRezClientRuntime(options = {}, callerName = "RezClient") {
  const opts = normalizeRezClientOptions(options, callerName);
  const eventBus = new TypedEventBus();
  const metrics = opts.metrics || new MetricsCollector();

  const resolvedSessionHello = opts.sessionHello || {
    requestType: REZ_CONTRACT_TYPES.SESSION_HELLO,
    body: { contractVersion: CONTRACT_VERSION },
  };

  const authMachine = new AuthStateMachine({
    identity: opts.identity,
    eventBus,
    sessionHello: resolvedSessionHello,
    clientVersion: opts.clientVersion,
    expectedNodePublicKeyB64: opts.expectedNodePublicKeyB64,
  });

  const codec = opts.frameCodec || createFrameCodec();
  const transportOpts = {
    frameCodec: codec,
    timeouts: opts.timeouts,
    maxFrameBytes: Number.isFinite(Number(opts.limits.maxFrameBytes)) ? Number(opts.limits.maxFrameBytes) : undefined,
  };
  if (opts.wsFactory) {
    transportOpts.wsFactory = opts.wsFactory;
  }

  const normalizedUplinks = opts.uplinks.map((u) => {
    const url = typeof u === "string" ? u : String(u && u.url ? u.url : "");
    return resolveUplinkUrl(url, opts.transportScheme);
  }).filter(Boolean);

  const transportFactory = (url) => {
    if (url.startsWith("ws://") || url.startsWith("wss://")) {
      return new WsTransport({ url, ...transportOpts });
    }
    if (url.startsWith("tcp://") || url.startsWith("tls://")) {
      return createTcpTransport({
        TcpTransportClass: opts.tcpTransportClass,
        url,
        transportOpts,
      });
    }
    throw new Error("Unknown transport scheme: " + url);
  };

  const pool = new UplinkPool({
    uplinks: normalizedUplinks,
    transportFactory,
    authMachine,
    eventBus,
    warmSpareCount: opts.warmSpareCount,
    timeouts: opts.timeouts,
    maxRequestAttempts: Number(opts.limits.maxRequestAttempts) || 3,
    dedupe: opts.dedupe,
    flood: opts.flood,
  });

  pool.onState((state) => {
    eventBus.emit(SDK_EVENTS.CONNECTION_STATE_CHANGED, state);
  });

  return {
    pool,
    eventBus,
    authMachine,
    metrics,
    identity: opts.identity,
  };
}
