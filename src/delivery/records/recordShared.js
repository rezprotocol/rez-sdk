import {
  assertSafeJsonKeys,
  canonicalJSONStringify,
  parseUntrustedJson,
} from "@rezprotocol/core";

export const SAFE_DELIVERY_TOKEN = /^[A-Za-z0-9._:-]{1,128}$/;
export const SHA256_HEX = /^[0-9a-f]{64}$/;
export const TRANSPORT_INSTANCE_ID = /^trinst_[0-9a-f]{32}$/;

export function assertExactRecordKeys(raw, allowedKeys, label) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(label + " requires an object");
  }
  assertSafeJsonKeys(raw, label);
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) throw new Error(label + " contains unknown field: " + key);
  }
}

export function canonicalRecordBytes(record) {
  return new TextEncoder().encode(canonicalJSONStringify(record.toJSON()));
}

export function parseRecordBytes(bytes, label) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw new Error(label + ".fromBytes requires non-empty Uint8Array");
  }
  return parseUntrustedJson(new TextDecoder().decode(bytes), label);
}

export function requireSafeToken(value, label) {
  if (typeof value !== "string" || !SAFE_DELIVERY_TOKEN.test(value)) {
    throw new Error(label + " must be 1..128 safe ASCII characters");
  }
  return value;
}

export function requireSha256Hex(value, label) {
  if (typeof value !== "string" || !SHA256_HEX.test(value)) {
    throw new Error(label + " must be 64 lowercase hex characters");
  }
  return value;
}

export function requireTransportInstanceId(value, label) {
  if (typeof value !== "string" || !TRANSPORT_INSTANCE_ID.test(value)) {
    throw new Error(label + " must be trinst_ followed by 32 lowercase hex characters");
  }
  return value;
}

export function canonicalStringSet(value, label, { allowed = null, allowEmpty = false } = {}) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    throw new Error(label + (allowEmpty ? " must be an array" : " must be a non-empty array"));
  }
  const normalized = [];
  for (const item of value) {
    const token = requireSafeToken(item, label + " entry");
    if (allowed && !allowed.includes(token)) {
      throw new Error(label + " contains unsupported value: " + token);
    }
    normalized.push(token);
  }
  return [...new Set(normalized)].sort();
}
