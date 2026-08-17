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
    // SDK-4. `sendPayload` puts these bytes on the wire in a field named
    // `ciphertextB64` and encrypts NOTHING — the name describes what the mailbox
    // contract expects to receive, not what this path does. A caller who reads
    // the wire shape and infers the SDK seals for them deposits plaintext.
    //
    // So the caller states it, in one word, at the call site. `preSealed` is not
    // a feature flag and enables no behaviour: its only job is to make the
    // assumption impossible to hold silently. Strict `=== true` — a truthy
    // string or 1 is someone passing data through, not someone asserting.
    this.preSealed = raw.preSealed === true;
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
    this.assert(
      this.preSealed === true,
      "payloadBytes are deposited verbatim into `ciphertextB64` — this call encrypts nothing. "
      + "Pass preSealed: true to confirm the bytes are already sealed, or use sealForPeer() + mesh.dispatch().",
    );
  }
}
