import { RCryptoProvider } from "@rezprotocol/core";

/**
 * RCryptoProvider implementation for browser environments using WebCrypto subtle API.
 * Supports Ed25519 signing, X25519 DH, AES-256-GCM AEAD, and HKDF-SHA256.
 *
 * Requires: Chrome 113+, Firefox 128+, Safari 17.4+ for X25519/Ed25519 support.
 */
export class BrowserCryptoProvider extends RCryptoProvider {
  #subtle;
  #getRandomValues;

  constructor({ subtle = null, getRandomValues = null } = {}) {
    super();
    const cryptoObj = globalThis.crypto;
    this.#subtle = subtle || cryptoObj?.subtle;
    this.#getRandomValues = getRandomValues || (cryptoObj ? (buf) => cryptoObj.getRandomValues(buf) : null);

    if (!this.#subtle || typeof this.#subtle.generateKey !== "function") {
      throw new Error("BrowserCryptoProvider requires WebCrypto subtle API");
    }
    if (typeof this.#getRandomValues !== "function") {
      throw new Error("BrowserCryptoProvider requires getRandomValues");
    }
  }

  randomBytes(len) {
    if (!Number.isInteger(len) || len <= 0) {
      throw new Error("BrowserCryptoProvider.randomBytes(len) requires positive integer");
    }
    const buf = new Uint8Array(len);
    this.#getRandomValues(buf);
    return buf;
  }

  async hashSha256(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new Error("BrowserCryptoProvider.hashSha256(bytes) requires Uint8Array");
    }
    const digest = await this.#subtle.digest("SHA-256", bytes);
    return new Uint8Array(digest);
  }

  async hkdfSha256(ikm, { salt = new Uint8Array(0), info = new Uint8Array(0), length = 32 } = {}) {
    if (!(ikm instanceof Uint8Array) || !(salt instanceof Uint8Array) || !(info instanceof Uint8Array)) {
      throw new Error("BrowserCryptoProvider.hkdfSha256 requires Uint8Array inputs");
    }
    if (!Number.isInteger(length) || length <= 0) {
      throw new Error("BrowserCryptoProvider.hkdfSha256 length must be positive integer");
    }

    const baseKey = await this.#subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    const bits = await this.#subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: salt.length ? salt : new Uint8Array(32),
        info,
      },
      baseKey,
      length * 8,
    );
    return new Uint8Array(bits);
  }

  async aeadEncrypt({ key, nonce, plaintext, aad } = {}) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new Error("BrowserCryptoProvider.aeadEncrypt requires 32-byte key");
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== 12) {
      throw new Error("BrowserCryptoProvider.aeadEncrypt requires 12-byte nonce");
    }
    if (!(plaintext instanceof Uint8Array)) {
      throw new Error("BrowserCryptoProvider.aeadEncrypt requires plaintext Uint8Array");
    }
    if (!(aad instanceof Uint8Array)) {
      throw new Error("BrowserCryptoProvider.aeadEncrypt requires aad Uint8Array");
    }

    const cryptoKey = await this.#subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);
    const ct = await this.#subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      cryptoKey,
      plaintext,
    );
    return new Uint8Array(ct);
  }

  async aeadDecrypt({ key, nonce, ciphertext, aad } = {}) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new Error("BrowserCryptoProvider.aeadDecrypt requires 32-byte key");
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== 12) {
      throw new Error("BrowserCryptoProvider.aeadDecrypt requires 12-byte nonce");
    }
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length < 16) {
      throw new Error("BrowserCryptoProvider.aeadDecrypt requires ciphertext+tag Uint8Array");
    }
    if (!(aad instanceof Uint8Array)) {
      throw new Error("BrowserCryptoProvider.aeadDecrypt requires aad Uint8Array");
    }

    const cryptoKey = await this.#subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
    const pt = await this.#subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      cryptoKey,
      ciphertext,
    );
    return new Uint8Array(pt);
  }

  async sign({ privateKey, msg } = {}) {
    if (!(privateKey instanceof Uint8Array) || !(msg instanceof Uint8Array)) {
      throw new Error("BrowserCryptoProvider.sign requires Uint8Array inputs");
    }
    const key = await this.#subtle.importKey("pkcs8", privateKey, "Ed25519", false, ["sign"]);
    const sig = await this.#subtle.sign("Ed25519", key, msg);
    return new Uint8Array(sig);
  }

  async verify({ publicKey, msg, sig } = {}) {
    if (!(publicKey instanceof Uint8Array) || !(msg instanceof Uint8Array) || !(sig instanceof Uint8Array)) {
      throw new Error("BrowserCryptoProvider.verify requires Uint8Array inputs");
    }
    const key = await this.#subtle.importKey("spki", publicKey, "Ed25519", true, ["verify"]);
    return this.#subtle.verify("Ed25519", key, sig, msg);
  }

  async dhGenerateKeyPair({ alg = "X25519", fmt = "spki" } = {}) {
    const normalized = String(alg).toLowerCase();
    if (normalized !== "x25519") {
      throw new Error(`BrowserCryptoProvider.dhGenerateKeyPair unsupported alg ${alg}`);
    }
    if (fmt !== "spki" && fmt !== "raw") {
      throw new Error("BrowserCryptoProvider.dhGenerateKeyPair requires fmt 'spki' or 'raw'");
    }

    const keyPair = await this.#subtle.generateKey("X25519", true, ["deriveBits"]);
    const publicKey = new Uint8Array(await this.#subtle.exportKey("spki", keyPair.publicKey));
    const privateKey = new Uint8Array(await this.#subtle.exportKey("pkcs8", keyPair.privateKey));
    return { publicKey, privateKey };
  }

  async dhDerive({ privateKey, publicKey, alg = "X25519", fmt = "spki" } = {}) {
    const normalized = String(alg).toLowerCase();
    if (normalized !== "x25519") {
      throw new Error(`BrowserCryptoProvider.dhDerive unsupported alg ${alg}`);
    }
    if (!(privateKey instanceof Uint8Array) || !(publicKey instanceof Uint8Array)) {
      throw new Error("BrowserCryptoProvider.dhDerive requires Uint8Array keys");
    }
    if (fmt !== "spki" && fmt !== "raw") {
      throw new Error("BrowserCryptoProvider.dhDerive requires fmt 'spki' or 'raw'");
    }

    const privKey = await this.#subtle.importKey("pkcs8", privateKey, "X25519", false, ["deriveBits"]);
    const pubKey = await this.#subtle.importKey("spki", publicKey, "X25519", true, []);
    const bits = await this.#subtle.deriveBits({ name: "X25519", public: pubKey }, privKey, 256);
    return new Uint8Array(bits);
  }

  async generateSigningKeyPair() {
    const keyPair = await this.#subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const publicKey = new Uint8Array(await this.#subtle.exportKey("spki", keyPair.publicKey));
    const privateKey = new Uint8Array(await this.#subtle.exportKey("pkcs8", keyPair.privateKey));
    return { publicKey, privateKey };
  }
}
