import {
  toUint8Array,
  objectToBytes,
  bytesToObject,
  bytesToBase64,
} from "@rezprotocol/core";

export function encodeEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("encodeEnvelope(envelope) requires an object envelope");
  }
  return objectToBytes(envelope);
}

export function decodeEnvelope(bytes) {
  const parsed = bytesToObject(bytes);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("decodeEnvelope(bytes) produced a non-object envelope");
  }
  return parsed;
}

export function verifyEnvelope(envelopeOrBytes, context = {}) {
  const envelope =
    envelopeOrBytes instanceof Uint8Array ||
    envelopeOrBytes instanceof ArrayBuffer ||
    ArrayBuffer.isView(envelopeOrBytes)
      ? decodeEnvelope(envelopeOrBytes)
      : envelopeOrBytes;

  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("verifyEnvelope(envelope|bytes) requires an object envelope");
  }

  if (typeof context.verify === "function") {
    const ok = context.verify(envelope);
    if (!ok) throw new Error("Envelope verification failed");
  }

  return envelope;
}

export async function signEnvelope(envelope, keyRef) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("signEnvelope(envelope, keyRef) requires an object envelope");
  }
  if (!keyRef || typeof keyRef.sign !== "function") {
    throw new Error("signEnvelope(envelope, keyRef) requires keyRef.sign(bytes)");
  }

  const bytes = encodeEnvelope(envelope);
  const signature = await keyRef.sign(bytes);
  return {
    ...envelope,
    signature: bytesToBase64(toUint8Array(signature)),
  };
}

export function resolveSessionIdentity(sessionInfo = {}, fallback = {}) {
  const featureMap = sessionInfo && typeof sessionInfo === "object" ? sessionInfo.capabilities : null;
  const accountId = String((sessionInfo && sessionInfo.accountId) || fallback.accountId || "").trim();
  const deviceId = String((featureMap && featureMap.deviceId) || fallback.deviceId || "").trim();
  const localInboxId = String((featureMap && featureMap.localInboxId) || "").trim() || null;
  return { accountId, deviceId, localInboxId };
}
