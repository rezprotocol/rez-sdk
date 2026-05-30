import { WsTransport } from "./WsTransport.js";

/**
 * Factory function that creates the appropriate transport for a given endpoint URL.
 * - ws:// or wss:// -> WsTransport
 * - tcp:// or tls:// -> TcpTransport (lazy-loaded, server-side only)
 */
export async function createTransport(endpoint, options = {}) {
  const url = typeof endpoint === "string" ? endpoint : String(endpoint?.url || "");
  if (!url) throw new Error("createTransport requires endpoint url");

  if (url.startsWith("ws://") || url.startsWith("wss://")) {
    return new WsTransport({ url, ...options });
  }

  if (url.startsWith("tcp://") || url.startsWith("tls://")) {
    const parsed = parseTcpUrl(url);
    const { TcpTransport } = await import("./TcpTransport.js");
    return new TcpTransport({ ...parsed, ...options });
  }

  throw new Error(`Unknown transport scheme: ${url}`);
}

function parseTcpUrl(url) {
  const isTls = url.startsWith("tls://");
  const stripped = url.replace(/^(tcp|tls):\/\//, "");
  const [hostPart, portStr] = stripped.split(":");
  return {
    host: hostPart || "127.0.0.1",
    port: Number(portStr) || 8787,
    tls: isTls,
  };
}
