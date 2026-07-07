import {
  durableRecordLocalId,
  durableRecordSignableBytes,
  base64ToBytes,
} from "@rezprotocol/core";

// In-memory durable-record overlay double enforcing the NODE's real rules
// (rez-node RecordHandler + DurableRecordStore): signature verified against
// the embedded publisher key, payloadB64 ≤ 16384 chars, bounded future skew,
// same-publisher slots roll forward by issuedAtMs, expired records are
// neither stored nor served. One overlay is shared by both ceremony sides —
// each side gets the same { put, get } surface DurableRecordsCapability has.
export function createMemoryRecordOverlay({ crypto, nowMs = () => Date.now() } = {}) {
  const map = new Map();

  async function put({ record } = {}) {
    if (!record || typeof record !== "object") throw new Error("overlay: record required");
    if (record.v !== 1) throw new Error("overlay: bad-version");
    const kind = String(record.recordKind || "");
    const id = String(record.recordId || "");
    const pub = String(record.publisherPublicKeyB64 || "");
    if (!kind || !id || !pub || typeof record.sigB64 !== "string") throw new Error("overlay: missing-fields");
    if (!Number.isFinite(record.issuedAtMs) || !Number.isFinite(record.expiresAtMs)) throw new Error("overlay: bad-timestamps");
    const at = nowMs();
    if (record.expiresAtMs <= at) throw new Error("overlay: expired");
    if (record.issuedAtMs > at + 5 * 60_000) throw new Error("overlay: future-issuance");
    if (String(record.payloadB64 || "").length > 16384) throw new Error("overlay: too-large");
    const ok = await crypto.verify({
      publicKey: base64ToBytes(pub),
      msg: durableRecordSignableBytes(record),
      sig: base64ToBytes(record.sigB64),
    });
    if (ok !== true) throw new Error("overlay: bad-signature");

    const localId = durableRecordLocalId({ publisherPublicKeyB64: pub, recordKind: kind, recordId: id });
    const existing = map.get(localId);
    if (existing && existing.expiresAtMs > at) {
      if (existing.sigB64 === record.sigB64) return { localId, replicas: 1 };
      if (record.issuedAtMs < existing.issuedAtMs) throw new Error("overlay: older-record");
    }
    map.set(localId, { ...record });
    return { localId, replicas: 1 };
  }

  async function get({ recordKind, recordId, publisherPublicKeyB64 } = {}) {
    const localId = durableRecordLocalId({ publisherPublicKeyB64, recordKind, recordId });
    const record = map.get(localId);
    if (!record) return null;
    if (record.expiresAtMs <= nowMs()) {
      map.delete(localId);
      return null;
    }
    return { ...record };
  }

  return {
    put,
    get,
    // Harness-only: direct slot tamper for adversarial cases.
    _rawSet(localId, record) { map.set(localId, record); },
    _localId({ publisherPublicKeyB64, recordKind, recordId }) {
      return durableRecordLocalId({ publisherPublicKeyB64, recordKind, recordId });
    },
    _rawGet(localId) { return map.get(localId); },
  };
}
