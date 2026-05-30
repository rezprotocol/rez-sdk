import {
  X3DHService,
  X3DHInitiatorHandshake,
  RatchetService,
  MemorySessionManager,
  EncryptEnvelopeCodec,
  DecryptEnvelopeCodec,
  CodecChain,
  CanonicalizeCodec,
  JsonCodec,
  Envelope,
  Header,
  RatchetKeyPair,
  RCryptoProvider,
  bytesToBase64,
  base64ToBytes,
} from "../index.js";

function logSecureChannelDebug(event, details = {}) {
  try {
    console.info("[rez][e2ee][secure-channel]", event, details);
  } catch {
    // ignore logging failures
  }
}

/**
 * SecureChannelManager orchestrates end-to-end encryption for rez messaging.
 * It wraps X3DH key exchange, Double Ratchet sessions, and envelope encryption/decryption.
 *
 * App-agnostic: any rez SDK app (chat, files, etc.) can use this to encrypt arbitrary payloads.
 */
export class SecureChannelManager {
  #crypto;
  #x3dh;
  #ratchet;
  #sessionManager;
  #encCodec;
  #decCodec;

  constructor({ crypto } = {}) {
    if (!(crypto instanceof RCryptoProvider)) {
      throw new Error("SecureChannelManager requires crypto (RCryptoProvider)");
    }

    this.#crypto = crypto;
    this.#x3dh = new X3DHService({ crypto });
    this.#ratchet = new RatchetService({ crypto });
    this.#sessionManager = new MemorySessionManager({ ratchetService: this.#ratchet, crypto });

    const innerChain = new CodecChain([new CanonicalizeCodec(), new JsonCodec()]);
    this.#encCodec = new EncryptEnvelopeCodec({ innerCodecChain: innerChain, ratchetService: this.#ratchet });
    this.#decCodec = new DecryptEnvelopeCodec({ innerCodecChain: innerChain, ratchetService: this.#ratchet });
  }

  /**
   * Generate an X3DH pre-key bundle for embedding in an invite.
   * @param {{ accountId: string, identityKeyPair: { publicKey: Uint8Array, privateKey: Uint8Array } }} opts
   * @returns {{ bundle: X3DHPreKeyBundle, signedPreKeyPair: { publicKey: Uint8Array, privateKey: Uint8Array } }}
   */
  async generatePreKeyBundle({ accountId, identityKeyPair } = {}) {
    if (!accountId || typeof accountId !== "string") {
      throw new Error("generatePreKeyBundle requires accountId string");
    }
    if (!identityKeyPair || !identityKeyPair.publicKey || !identityKeyPair.privateKey) {
      throw new Error("generatePreKeyBundle requires identityKeyPair with publicKey and privateKey");
    }

    const signedPreKeyPair = await this.#crypto.dhGenerateKeyPair();
    const bundle = await this.#x3dh.createReceiverBundle({
      receiverId: accountId,
      identityKeyPair,
      signedPreKeyKeyPair: signedPreKeyPair,
      oneTimePreKeyPublic: null,
    });

    return { bundle, signedPreKeyPair };
  }

  /**
   * Establish an initiator session (called by invite acceptor).
   * Runs X3DH initiatorCompute and creates a ratchet session.
   * @param {{ peerId: string, receiverBundle: X3DHPreKeyBundle }} opts
   * @returns {{ sid: Uint8Array, handshakeData: object }}
   */
  async establishInitiatorSession({ peerId, receiverBundle } = {}) {
    if (!peerId || typeof peerId !== "string") {
      throw new Error("establishInitiatorSession requires peerId string");
    }
    if (!receiverBundle) {
      throw new Error("establishInitiatorSession requires receiverBundle");
    }

    const { handshake, sharedSecret, ephemeralKeyPair } = await this.#x3dh.initiatorCompute({
      receiverBundle,
    });
    logSecureChannelDebug("establishInitiatorSession.x3dhReady", {
      peerId,
      receiverId: receiverBundle && receiverBundle.receiverId ? receiverBundle.receiverId : null,
      usedOneTimePreKey: handshake && handshake.usedOneTimePreKey === true,
      ephemeralPublicKeyBytes: ephemeralKeyPair && ephemeralKeyPair.publicKey ? ephemeralKeyPair.publicKey.byteLength : null,
    });

    const selfDhKeyPair = await this.#crypto.dhGenerateKeyPair();

    const sid = await this.#sessionManager.createInitiatorSession({
      peerId,
      sharedSecret,
      selfDhKeyPair: new RatchetKeyPair({
        publicKey: selfDhKeyPair.publicKey,
        privateKey: selfDhKeyPair.privateKey,
      }),
      remoteDhPublicKey: receiverBundle.signedPreKeyPublic,
    });

    const handshakeData = {
      ephemeralPublicKeyB64: bytesToBase64(handshake.ephemeralPublicKey),
      usedOneTimePreKey: handshake.usedOneTimePreKey,
      receiverId: handshake.receiverId,
      initiatorDhPublicKeyB64: bytesToBase64(selfDhKeyPair.publicKey),
    };

    logSecureChannelDebug("establishInitiatorSession.created", {
      peerId,
      sidLength: sid ? sid.byteLength : null,
      receiverId: handshakeData.receiverId || null,
      initiatorDhBytes: selfDhKeyPair && selfDhKeyPair.publicKey ? selfDhKeyPair.publicKey.byteLength : null,
    });

    return { sid, handshakeData };
  }

  /**
   * Establish a responder session (called by invite creator upon receiving handshake).
   * Runs X3DH receiverCompute and creates a ratchet session.
   * @param {{ peerId: string, signedPreKeyPrivate: Uint8Array, receiverBundle: X3DHPreKeyBundle, handshakeData: object }} opts
   * @returns {{ sid: Uint8Array }}
   */
  async establishResponderSession({ peerId, signedPreKeyPrivate, receiverBundle, handshakeData } = {}) {
    if (!peerId || typeof peerId !== "string") {
      throw new Error("establishResponderSession requires peerId string");
    }
    if (!(signedPreKeyPrivate instanceof Uint8Array)) {
      throw new Error("establishResponderSession requires signedPreKeyPrivate Uint8Array");
    }
    if (!receiverBundle) {
      throw new Error("establishResponderSession requires receiverBundle");
    }
    if (!handshakeData) {
      throw new Error("establishResponderSession requires handshakeData");
    }

    const initiatorHandshake = new X3DHInitiatorHandshake({
      receiverId: handshakeData.receiverId,
      ephemeralPublicKey: base64ToBytes(handshakeData.ephemeralPublicKeyB64),
      usedOneTimePreKey: Boolean(handshakeData.usedOneTimePreKey),
    });

    const sharedSecret = await this.#x3dh.receiverCompute({
      receiverBundle,
      receiverSignedPreKeyPrivate: signedPreKeyPrivate,
      receiverOneTimePreKeyPrivate: null,
      initiatorHandshake,
    });
    logSecureChannelDebug("establishResponderSession.x3dhReady", {
      peerId,
      receiverId: handshakeData && handshakeData.receiverId ? handshakeData.receiverId : null,
      inviteId: handshakeData && handshakeData.inviteId ? handshakeData.inviteId : null,
      usedOneTimePreKey: handshakeData && handshakeData.usedOneTimePreKey === true,
    });

    const selfDhKeyPair = await this.#crypto.dhGenerateKeyPair();
    const remoteDhPublicKey = base64ToBytes(handshakeData.initiatorDhPublicKeyB64);

    const sid = await this.#sessionManager.createResponderSession({
      peerId,
      sharedSecret,
      selfDhKeyPair: new RatchetKeyPair({
        publicKey: selfDhKeyPair.publicKey,
        privateKey: selfDhKeyPair.privateKey,
      }),
      remoteDhPublicKey,
    });

    // Rotate DH so the responder has includeDh=true and a fresh key pair ready
    // for the first outbound message. This does NOT derive a sending chain yet —
    // that happens lazily in encryptPayload via a ratchet step.
    await this.#sessionManager.rotateDh(peerId);

    logSecureChannelDebug("establishResponderSession.created", {
      peerId,
      sidLength: sid ? sid.byteLength : null,
      remoteDhBytes: remoteDhPublicKey ? remoteDhPublicKey.byteLength : null,
    });

    return { sid };
  }

  /**
   * Encrypt payload bytes for a peer.
   * @param {string} peerId
   * @param {Uint8Array} plaintextBytes
   * @returns {Uint8Array} encrypted envelope JSON bytes
   */
  async encryptPayload(peerId, plaintextBytes) {
    if (!peerId || typeof peerId !== "string") {
      throw new Error("encryptPayload requires peerId string");
    }
    if (!(plaintextBytes instanceof Uint8Array)) {
      throw new Error("encryptPayload requires plaintextBytes Uint8Array");
    }

    const sendCtx = this.#sessionManager.getSendContext(peerId);
    logSecureChannelDebug("encryptPayload.begin", {
      peerId,
      sidLength: sendCtx && sendCtx.sid ? sendCtx.sid.byteLength : null,
      plaintextBytes: plaintextBytes.byteLength,
    });
    let ratchetState = sendCtx.ratchetState;
    let includeDh = sendCtx.includeDh;

    // Responder starts with sendingChain=null. Perform a DH ratchet step to
    // derive a sending chain before the first outbound message.
    if (!ratchetState.sendingChain && ratchetState.remoteDhPublicKey) {
      const step = await this.#ratchet.ratchetStep(ratchetState, ratchetState.remoteDhPublicKey);
      ratchetState = step.newState;
      includeDh = true;
    }

    const header = new Header({ id: `enc-${Date.now()}`, type: "rez.payload", createdAt: Date.now() });
    const envelope = new Envelope({ header, body: { raw: bytesToBase64(plaintextBytes) } });

    const ctx = {
      envelope,
      meta: {
        secureChannel: {
          sid: sendCtx.sid,
          ratchetState,
          includeDh,
        },
      },
    };

    const result = await this.#encCodec.encode(ctx);
    sendCtx.commit(result.meta.secureChannel.ratchetState);
    logSecureChannelDebug("encryptPayload.done", {
      peerId,
      includeDh: result && result.meta && result.meta.secureChannel && result.meta.secureChannel.includeDh === true,
      cipherType: result && result.envelope && result.envelope.header ? result.envelope.header.type : null,
    });

    const outerJson = result.envelope.toJSON();
    return new TextEncoder().encode(JSON.stringify(outerJson));
  }

  /**
   * Decrypt encrypted envelope bytes.
   * @param {Uint8Array} encryptedBytes - JSON bytes of an encrypted envelope
   * @returns {{ plaintextBytes: Uint8Array, peerId: string }} or null if not decryptable
   */
  async decryptPayload(encryptedBytes) {
    if (!(encryptedBytes instanceof Uint8Array)) {
      throw new Error("decryptPayload requires encryptedBytes Uint8Array");
    }

    let outerJson;
    try {
      outerJson = JSON.parse(new TextDecoder().decode(encryptedBytes));
    } catch {
      logSecureChannelDebug("decryptPayload.notJson", {
        bytes: encryptedBytes.byteLength,
      });
      return null;
    }

    if (!outerJson || !outerJson.header || outerJson.header.type !== "rez.encrypted.v1") {
      logSecureChannelDebug("decryptPayload.notEncryptedEnvelope", {
        headerType: outerJson && outerJson.header ? outerJson.header.type : null,
        bytes: encryptedBytes.byteLength,
      });
      return null;
    }

    const envelope = Envelope.fromJSON(outerJson);

    // Extract SID from the encrypted body's header to look up the session
    let sid;
    try {
      const bodyHeader = outerJson.body ? outerJson.body.header : null;
      if (!bodyHeader || !bodyHeader.sid) return null;
      sid = new Uint8Array(bodyHeader.sid);
    } catch {
      logSecureChannelDebug("decryptPayload.sidMissing", {
        bytes: encryptedBytes.byteLength,
      });
      return null;
    }

    let recvCtx;
    try {
      recvCtx = this.#sessionManager.getRecvContext(sid);
    } catch (err) {
      logSecureChannelDebug("decryptPayload.recvContextMissing", {
        sidLength: sid ? sid.byteLength : null,
        error: err && err.message ? err.message : String(err || ""),
      });
      throw err;
    }
    logSecureChannelDebug("decryptPayload.recvContext", {
      sidLength: sid ? sid.byteLength : null,
      peerId: recvCtx && recvCtx.peerId ? recvCtx.peerId : null,
    });

    const ctx = {
      envelope,
      meta: {
        secureChannel: {
          sid,
          ratchetState: recvCtx.ratchetState,
        },
      },
    };

    let result;
    try {
      result = await this.#decCodec.decode(ctx);
    } catch (err) {
      logSecureChannelDebug("decryptPayload.decodeError", {
        sidLength: sid ? sid.byteLength : null,
        peerId: recvCtx && recvCtx.peerId ? recvCtx.peerId : null,
        error: err && err.message ? err.message : String(err || ""),
      });
      throw err;
    }
    recvCtx.commit(result.meta.secureChannel.ratchetState);

    const raw = result.envelope.body ? result.envelope.body.raw : undefined;
    if (!raw || typeof raw !== "string") {
      logSecureChannelDebug("decryptPayload.rawMissing", {
        sidLength: sid ? sid.byteLength : null,
        peerId: recvCtx && recvCtx.peerId ? recvCtx.peerId : null,
      });
      return null;
    }

    logSecureChannelDebug("decryptPayload.done", {
      sidLength: sid ? sid.byteLength : null,
      peerId: recvCtx && recvCtx.peerId ? recvCtx.peerId : null,
      plaintextBytes: raw.length,
    });
    return {
      plaintextBytes: base64ToBytes(raw),
      peerId: recvCtx.peerId,
    };
  }

  /**
   * Check if a session exists for the given peer.
   * @param {string} peerId
   * @returns {boolean}
   */
  hasSession(peerId) {
    try {
      this.#sessionManager.getSendContext(peerId);
      logSecureChannelDebug("hasSession", {
        peerId,
        hasSession: true,
      });
      return true;
    } catch (err) {
      logSecureChannelDebug("hasSession", {
        peerId,
        hasSession: false,
        error: err && err.message ? err.message : String(err || ""),
      });
      return false;
    }
  }

  /**
   * Export underlying ratchet sessions for persistence.
   * @returns {{ v: number, sessions: object|null }}
   */
  exportSnapshot() {
    const sessions = typeof this.#sessionManager.exportSnapshot === "function"
      ? this.#sessionManager.exportSnapshot()
      : null;
    return {
      v: 1,
      sessions,
    };
  }

  /**
   * Restore persisted ratchet sessions.
   * @param {{ sessions?: object }} snapshot
   */
  importSnapshot(snapshot = {}) {
    if (typeof this.#sessionManager.importSnapshot === "function") {
      this.#sessionManager.importSnapshot(snapshot && snapshot.sessions ? snapshot.sessions : {});
    }
  }
}
