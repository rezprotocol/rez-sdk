import { RezClient } from "./RezClient.js";

/**
 * Create a fully-wired RezClient.
 *
 * @param {object} options
 * @param {Array<string|{url:string}>} options.uplinks  — required uplink URLs
 * @param {object} options.identity  — required { accountId, deviceId, publicKeyB64, privateKeyB64 }
 * @param {'ws'|'tcp'|'auto'} [options.transport='auto'] — transport scheme preference
 * @param {number} [options.warmSpareCount=2]
 * @param {object} [options.timeouts]
 * @param {object} [options.limits]
 * @param {object} [options.dedupe]
 * @param {object} [options.flood]
 * @param {Function} [options.wsFactory] — custom WebSocket constructor
 * @param {object} [options.frameCodec]
 * @param {object} [options.sessionHello] — custom session.hello override
 * @param {object} [options.metrics] — custom MetricsCollector instance
 * @param {string} [options.clientVersion]
 * @returns {RezClient}
 */
export function createRezClient(options = {}) {
  return new RezClient(options);
}

/**
 * Async variant for TCP uplinks (requires dynamic import of TcpTransport).
 */
export async function createRezClientAsync(options = {}) {
  const opts = options && typeof options === "object" ? options : {};
  let TcpTransportClass = opts.tcpTransportClass || null;
  if (!TcpTransportClass && usesTcpTransport(opts)) {
    const mod = await import("../transport/TcpTransport.js");
    TcpTransportClass = mod.TcpTransport;
  }
  return new RezClient({
    ...opts,
    tcpTransportClass: TcpTransportClass,
  });
}

function usesTcpTransport(options = {}) {
  const opts = options && typeof options === "object" ? options : {};
  const scheme = String(opts.transport || "auto");
  if (scheme === "tcp" || scheme === "tls") return true;
  const uplinks = Array.isArray(opts.uplinks) ? opts.uplinks : [];
  return uplinks.some((u) => {
    const url = typeof u === "string" ? u : String(u && u.url ? u.url : "");
    return url.startsWith("tcp://") || url.startsWith("tls://");
  });
}
