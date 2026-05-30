/**
 * JSON frame codec. Frame shape: { id, t, v, body }
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
        parsed = JSON.parse(raw);
      } catch {
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
