import { RRecord } from "@rezprotocol/core";

// Platform-only values. No Rez record is decoded by a native host: the opaque
// strings here carry bytes or generic storage values, never domain semantics.
export class NativePrimitiveRequestV1 extends RRecord {
  static type = "sdk.native.primitive.request.v1";
  constructor(method, args = []) {
    super();
    this.method = method;
    this.args = args.slice();
    this._seal();
  }
  validate() {
    this.assert(typeof this.method === "string" && /^[a-z]+\.[a-zA-Z][a-zA-Z0-9]*$/.test(this.method), "invalid native primitive");
    this.assert(this.args.every((v) => typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v))), "native arguments must be scalar");
  }
}

export class NativePrimitiveResultV1 extends RRecord {
  static type = "sdk.native.primitive.result.v1";
  constructor(raw) {
    super();
    this.ok = raw.ok;
    this.values = Array.isArray(raw.values) ? raw.values.slice() : [];
    this.error = typeof raw.error === "string" ? raw.error : "";
    this.code = typeof raw.code === "string" ? raw.code : "NATIVE_PRIMITIVE_FAILED";
    this._seal();
  }
  validate() {
    this.assert(typeof this.ok === "boolean", "native result requires ok");
    this.assert(this.values.every((v) => typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v))), "native results must be scalar");
    this.assert(this.ok || this.error.length > 0, "native failure requires error");
  }
}

export class NativePrimitiveClient {
  #invoke;
  constructor(invoke) {
    if (typeof invoke !== "function") throw new Error("NativePrimitiveClient requires native invoke");
    this.#invoke = invoke;
  }
  call(request) {
    if (!(request instanceof NativePrimitiveRequestV1)) throw new Error("native call requires NativePrimitiveRequestV1");
    const result = new NativePrimitiveResultV1(JSON.parse(this.#invoke(JSON.stringify(request.toJSON()))));
    if (!result.ok) {
      const err = new Error(result.error);
      err.code = result.code;
      throw err;
    }
    return result.values;
  }
}

export class NativeCryptoAlgorithmV1 extends RRecord {
  static type = "sdk.native.crypto.algorithm.v1";
  constructor(name) { super(); this.name = name; this._seal(); }
  validate() { this.assert(["Ed25519", "X25519", "AES-GCM", "HKDF", "PBKDF2"].includes(this.name), "unsupported native key algorithm"); }
}

export class NativeCryptoKeyV1 extends RRecord {
  static type = "sdk.native.crypto.key.v1";
  constructor(algorithm, format, extractable, usages) {
    super();
    this.kind = format === "pkcs8" ? "private" : format === "spki" ? "public" : "secret";
    this.algorithm = new NativeCryptoAlgorithmV1(algorithm);
    this.extractable = extractable === true;
    this.usages = usages.slice();
    this._seal();
  }
  validate() { this.assert(this.usages.every((v) => ["sign", "verify", "deriveBits", "encrypt", "decrypt"].includes(v)), "invalid key usages"); }
}

export class NativeCryptoKeyMaterialV1 extends RRecord {
  static type = "sdk.native.crypto.material.v1";
  constructor(algorithm, format, material, extractable, usages) {
    super();
    this.algorithm = algorithm; this.format = format; this.material = material;
    this.extractable = extractable === true; this.usages = usages.slice();
    this._seal();
  }
  validate() {
    this.assert(["raw", "pkcs8", "spki"].includes(this.format), "unsupported key format");
    this.assert(typeof this.material === "string", "key material must be encoded bytes");
  }
}

export class NativeCryptoKeyPairV1 extends RRecord {
  static type = "sdk.native.crypto.keyPair.v1";
  constructor(publicKey, privateKey) { super(); this.publicKey = publicKey; this.privateKey = privateKey; this._seal(); }
  validate() { this.assert(this.publicKey instanceof NativeCryptoKeyV1 && this.privateKey instanceof NativeCryptoKeyV1, "key pair requires key records"); }
}

export class NativePublicJwkV1 extends RRecord {
  static type = "sdk.native.crypto.publicJwk.v1";
  constructor(crv, x) { super(); this.kty = "OKP"; this.crv = crv; this.x = x; this._seal(); }
  validate() { this.assert(["Ed25519", "X25519"].includes(this.crv) && typeof this.x === "string" && this.x.length > 0, "invalid public JWK"); }
}
