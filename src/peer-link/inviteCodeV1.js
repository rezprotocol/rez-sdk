function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function stableNormalize(value) {
  if (Array.isArray(value)) return value.map((item) => stableNormalize(item));
  if (isPlainObject(value)) {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = stableNormalize(value[key]);
    return out;
  }
  return value;
}

export function canonicalPayloadBytesV1(value) {
  return new TextEncoder().encode(JSON.stringify(stableNormalize(value)));
}
