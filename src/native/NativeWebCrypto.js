import { NativePrimitiveClient, NativePrimitiveRequestV1, NativeCryptoKeyV1, NativeCryptoKeyMaterialV1, NativeCryptoKeyPairV1, NativePublicJwkV1 } from "./NativePrimitiveRecords.js";

function bytes(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  throw new TypeError("crypto requires BufferSource");
}
function name(value) { return typeof value === "string" ? value : value.name; }
function checkUsages(algorithm, format, extractable, usages) {
  if (!Array.isArray(usages) || new Set(usages).size !== usages.length) throw new Error("invalid key usages");
  let allowed;
  if (algorithm === "Ed25519" && format === "pkcs8") allowed = ["sign"];
  else if (algorithm === "Ed25519" && format === "spki") allowed = ["verify"];
  else if (algorithm === "X25519" && format === "pkcs8") allowed = ["deriveBits"];
  else if (algorithm === "X25519" && format === "spki") allowed = [];
  else if (algorithm === "AES-GCM" && format === "raw") allowed = ["encrypt", "decrypt"];
  else if (["HKDF", "PBKDF2"].includes(algorithm) && format === "raw" && !extractable) allowed = ["deriveBits"];
  else throw new Error("unsupported native key format or extractability");
  if (usages.some((usage) => !allowed.includes(usage)) || (format !== "spki" && usages.length === 0)) throw new Error("key usages do not match algorithm and format");
}

// A deliberately bounded WebCrypto adapter for the existing Rez SDK. Native
// libraries execute primitives; BrowserCryptoProvider remains the RCryptoProvider
// implementation, so no ratchet, signing policy or packet logic is repeated.
export class NativeWebCrypto {
  #client;
  #keys = new WeakMap();
  constructor(client) {
    if (!(client instanceof NativePrimitiveClient)) throw new Error("NativeWebCrypto requires NativePrimitiveClient");
    this.#client = client;
  }
  #call(method, ...args) { return this.#client.call(new NativePrimitiveRequestV1(method, args)); }
  #encode(value) { return this.#call("bytes.base64Encode", JSON.stringify(Array.from(bytes(value))))[0]; }
  #decode(value) { return Uint8Array.from(JSON.parse(this.#call("bytes.base64Decode", value)[0])).buffer; }
  #key(key, usage = null) {
    const stored = this.#keys.get(key);
    if (!stored || (usage && !stored.usages.includes(usage))) throw new Error("invalid key or key usage");
    return stored;
  }
  #make(algorithm, format, material, extractable, usages) {
    checkUsages(algorithm, format, extractable, usages);
    const key = new NativeCryptoKeyV1(algorithm, format, extractable, usages);
    this.#keys.set(key, new NativeCryptoKeyMaterialV1(algorithm, format, material, extractable, usages));
    return key;
  }
  getRandomValues(array) {
    if (!ArrayBuffer.isView(array) || array instanceof DataView || array instanceof Float32Array || array instanceof Float64Array) throw new TypeError("random values require an integer typed array");
    if (array.byteLength > 65536) throw new Error("random byte quota exceeded");
    const target = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
    target.set(new Uint8Array(this.#decode(this.#call("crypto.random", target.length)[0])));
    return array;
  }
  async digest(algorithm, data) { return this.#decode(this.#call("crypto.digest", name(algorithm), this.#encode(data))[0]); }
  async importKey(format, material, algorithm, extractable, usages) {
    const alg = name(algorithm);
    let encoded;
    if (format === "jwk") {
      if (material.kty !== "OKP" || material.crv !== alg || typeof material.x !== "string" || material.d !== undefined) throw new Error("only public OKP JWK import is supported");
      encoded = this.#call("crypto.publicJwk", alg, material.x)[0];
      format = "spki";
    } else {
      encoded = this.#encode(material);
    }
    checkUsages(alg, format, extractable, usages);
    this.#call("crypto.validateKey", alg, format, encoded);
    return this.#make(alg, format, encoded, extractable, usages);
  }
  async exportKey(format, key) {
    const stored = this.#key(key);
    if (!stored.extractable) throw new Error("key is not extractable");
    if (format === "jwk" && (stored.algorithm === "Ed25519" || stored.algorithm === "X25519")) {
      const pair = this.#call("crypto.exportJwk", stored.algorithm, stored.format, stored.material);
      return new NativePublicJwkV1(stored.algorithm, pair[0]);
    }
    if (format !== stored.format) throw new Error("unsupported native key export format");
    return this.#decode(stored.material);
  }
  async generateKey(algorithm, extractable, usages) {
    const alg = name(algorithm);
    const allowed = alg === "Ed25519" ? ["sign", "verify"] : alg === "X25519" ? ["deriveBits"] : [];
    if (!Array.isArray(usages) || !usages.length || usages.some((usage) => !allowed.includes(usage))) throw new Error("unsupported generated key usages");
    const result = this.#call("crypto.generate", alg);
    return new NativeCryptoKeyPairV1(
      this.#make(alg, "spki", result[0], true, alg === "Ed25519" ? usages.filter((v) => v === "verify") : []),
      this.#make(alg, "pkcs8", result[1], extractable, usages.filter((v) => v !== "verify")),
    );
  }
  async sign(algorithm, key, data) {
    const stored = this.#key(key, "sign");
    if (name(algorithm) !== stored.algorithm) throw new Error("key algorithm mismatch");
    return this.#decode(this.#call("crypto.sign", stored.algorithm, stored.material, this.#encode(data))[0]);
  }
  async verify(algorithm, key, signature, data) {
    const stored = this.#key(key, "verify");
    if (name(algorithm) !== stored.algorithm) throw new Error("key algorithm mismatch");
    return this.#call("crypto.verify", stored.algorithm, stored.material, this.#encode(signature), this.#encode(data))[0];
  }
  async deriveBits(algorithm, key, length) {
    const stored = this.#key(key, "deriveBits");
    if (!Number.isSafeInteger(length) || length <= 0 || length % 8 !== 0) throw new Error("invalid derivation length");
    if (algorithm.name !== stored.algorithm) throw new Error("key algorithm mismatch");
    let result;
    if (algorithm.name === "X25519") {
      if (length !== 256) throw new Error("X25519 requires 256 bits");
      const publicKey = this.#key(algorithm.public);
      if (publicKey.algorithm !== "X25519" || publicKey.format !== "spki") throw new Error("invalid DH public key");
      result = this.#call("crypto.dh", stored.material, publicKey.material);
    } else if (algorithm.name === "HKDF") {
      result = this.#call("crypto.hkdf", name(algorithm.hash), stored.material, this.#encode(algorithm.salt), this.#encode(algorithm.info), length / 8);
    } else if (algorithm.name === "PBKDF2") {
      result = this.#call("crypto.pbkdf", name(algorithm.hash), stored.material, this.#encode(algorithm.salt), algorithm.iterations, length / 8);
    } else throw new Error("unsupported native derivation");
    return this.#decode(result[0]);
  }
  async encrypt(algorithm, key, data) { return this.#aead("encrypt", algorithm, key, data); }
  async decrypt(algorithm, key, data) { return this.#aead("decrypt", algorithm, key, data); }
  #aead(operation, algorithm, key, data) {
    const stored = this.#key(key, operation);
    if (algorithm.name !== "AES-GCM" || stored.algorithm !== "AES-GCM" || (algorithm.tagLength !== undefined && algorithm.tagLength !== 128)) throw new Error("unsupported native AEAD");
    return this.#decode(this.#call("crypto." + operation, stored.material, this.#encode(algorithm.iv), this.#encode(data), this.#encode(algorithm.additionalData || new Uint8Array()))[0]);
  }
}
