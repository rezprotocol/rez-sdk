import { parseUntrustedJson, UNSAFE_JSON_KEY } from "@rezprotocol/core";

/**
 * JSON frame codec. Frame shape: { id, t, v, body }
 *
 * SDK-1: this is the trust boundary EVERY remote frame crosses. Individual
 * handlers validate their own fields, but the codec is where bytes become
 * objects, so it is the only place that can refuse a hostile shape once for all
 * of them — `decodeFrame` used to hand `parsed.body` straight through, and a
 * body one `Object.assign` away from re-parenting its target reached every
 * handler in the SDK. The check lives in `@rezprotocol/core` (`util/safeJson.js`)
 * so the node's frame codec and the profile/packet boundaries all apply the
 * same rule; a second implementation here would be a second thing to drift.
 *
 * Two distinguishable refusals, because they mean different things about the
 * peer: `BAD_FRAME` is "not JSON" (a broken or mismatched sender) and
 * `UNSAFE_JSON_KEY` is "JSON built to poison us" (a hostile one). Both are
 * `retryable: false` — resending identical bytes cannot help either way.
 */
export function createFrameCodec() {
  return {
    encodeFrame({ id, type, body = {}, version = 2 }) {
      return JSON.stringify({
        id: String(id || ""),
        t: String(type || ""),
        v: Number.isFinite(Number(version)) ? Number(version) : 2,
        body: body && typeof body === "object" ? body : {},
      });
    },
    decodeFrame(raw) {
      let parsed;
      try {
        parsed = parseUntrustedJson(raw, "frame");
      } catch (err) {
        // A hostile frame is NOT a malformed one and must not be flattened into
        // it: an operator reading "bad frame json" would go looking for an
        // encoding bug. Re-thrown with the boundary's own code intact.
        if (err && err.code === UNSAFE_JSON_KEY) {
          err.retryable = false;
          throw err;
        }
        parsed = null;
      }
      if (!parsed || typeof parsed !== "object") {
        const err = new Error("bad frame json");
        err.code = "BAD_FRAME";
        err.retryable = false;
        throw err;
      }
      const typeStr =
        typeof parsed.type === "string" && parsed.type.trim().length > 0
          ? parsed.type.trim()
          : typeof parsed.t === "string" && parsed.t.trim().length > 0
            ? parsed.t.trim()
            : "";
      return {
        id: typeof parsed.id === "string" && parsed.id.length > 0 ? parsed.id : null,
        type: typeStr,
        version: parsed.v,
        body: parsed.body && typeof parsed.body === "object" ? parsed.body : {},
      };
    },
  };
}
