import { RRecord } from "../defaults/createDefaultLogger.js";

function normalizeString(value) {
  return String(value == null ? "" : value).trim();
}

function normalizeBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  throw new Error("payloadBytes must be Uint8Array");
}

export class RezPayloadSendParams extends RRecord {
  static type = "sdk.params.payload_send";

  constructor(raw = {}) {
    super();
    this.peerAccountId = normalizeString(raw.peerAccountId);
    this.payloadBytes = Array.from(normalizeBytes(raw.payloadBytes));
    this.deliverInboxId = normalizeString(raw.deliverInboxId);
    this.receiptInboxId = normalizeString(raw.receiptInboxId);
    this.objectId = normalizeString(raw.objectId);
    this._seal();
  }

  validate() {
    this.assert(this.peerAccountId.length > 0, "peerAccountId must be non-empty");
    this.assert(Array.isArray(this.payloadBytes), "payloadBytes must be an array");
    this.assert(this.payloadBytes.length > 0, "payloadBytes must be non-empty");
    for (const value of this.payloadBytes) {
      this.assert(Number.isInteger(value) && value >= 0 && value <= 255, "payloadBytes must contain bytes");
    }
    this.assert(this.deliverInboxId.length > 0, "deliverInboxId must be non-empty");
  }
}
