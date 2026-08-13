import { SecureChannelManager, X3DHKeyExchange, E2eePacketCodec, DeviceRegistrationV1, bytesToBase64 } from "@rezprotocol/core";
import { runtimeUuid } from "../util/runtimeUuid.js";

const SESSION_STATUS_ACTIVE = "active";

/**
 * DevicePeerSessions — the per-device secure-session machinery for multi-device
 * E2EE (S2.5 Slice 2). Composes the rez-core E2EE primitives (X3DH + double
 * ratchet, reused UNTOUCHED) with the device-aware secure-session store so a
 * peer link holds one INDEPENDENT ratchet session per peer device (Sesame).
 *
 * Per-device isolation comes entirely from separate persisted snapshots: every
 * operation loads exactly one device session's snapshot into a fresh
 * SecureChannelManager, advances it, and writes it back — so advancing one
 * device's ratchet can NEVER touch another's. The crypto primitives are reused
 * verbatim; this layer only routes key material + snapshots.
 *
 * Deliberately NOT here (callers provide it; Slice 0b/3 wire it): generating +
 * persisting + account-chaining the per-device X3DH identity, and DISCOVERING a
 * peer's device bundles. The per-device X3DH identity keypairs (signing + DH)
 * are passed in by the caller — each bound to a device key per S2.5 decision D-a.
 *
 * Record policy (audit P2): this layer invents NO new wire shapes. The
 * WIRE-bound objects it returns/consumes — the prekey `bundleJson`, the X3DH
 * `handshakeData`, the responder `preKeyState` — are produced verbatim by the
 * rez-core `X3DHKeyExchange` primitives (the established, canonical shapes). The
 * persisted session record reuses the EXISTING secure-session record shape (plus
 * the additive `peerDeviceId` field). Method returns (`{ sessionId }`,
 * `{ encryptedPacket }`, `{ plaintextBytes }`, `{ peerDeviceId, ... }`) are
 * internal SDK call results, never serialized to the wire — so no RRecord is
 * required for them. When discovery (Slice 3) introduces genuinely NEW wire
 * shapes (DeviceSetRecordV1 / DevicePrekeyBundleV1), THOSE land as records.
 */
export class DevicePeerSessions {
  #cryptoProvider;
  #peerLinkStorage;
  #clock;
  // Per-(owner, peerLink, peerDevice) async mutex: serializes each
  // load→advance→put so two concurrent ops on the SAME device session can't both
  // advance off one snapshot and clobber each other — the session store is
  // last-write-wins, so an unserialized race would lose a ratchet step (one
  // ciphertext becomes undecryptable / the chains desync). Keyed by DEVICE (audit
  // P2): independent device sessions of one peer link no longer needlessly
  // serialize, so an N-device fan-out runs concurrently. Entries are GC'd once
  // their chain drains (#withLock), so the map tracks only actively-contended
  // sessions instead of growing with peer-link cardinality. Client-side (one
  // process = one instance), so an in-memory mutex is sufficient.
  #locks = new Map();

  constructor({ cryptoProvider, peerLinkStorage, clock } = {}) {
    if (!cryptoProvider) {
      throw new Error("DevicePeerSessions requires cryptoProvider");
    }
    if (!peerLinkStorage || !peerLinkStorage.sessions) {
      throw new Error("DevicePeerSessions requires peerLinkStorage with sessions");
    }
    this.#cryptoProvider = cryptoProvider;
    this.#peerLinkStorage = peerLinkStorage;
    this.#clock = typeof clock === "function" ? clock : () => Date.now();
  }

  #scm(snapshot) {
    const manager = new SecureChannelManager({ crypto: this.#cryptoProvider });
    if (snapshot && typeof snapshot === "object") {
      manager.importSnapshot(snapshot);
    }
    return manager;
  }

  #lockKey(ownerAccountId, peerLinkId, peerDeviceId) {
    return String(ownerAccountId) + "::" + String(peerLinkId) + "::" + String(peerDeviceId);
  }

  // Chain `fn` after the current tail for `key` (runs whether the prior op
  // resolved or rejected); the stored tail never rejects so one failure can't
  // poison the chain. Callers get fn's real result/error via the returned run.
  // Once this tail drains, GC the entry IF nothing newer chained after it (a
  // later #withLock replaces the map value) — bounds the map to live contention.
  #withLock(key, fn) {
    const prev = this.#locks.get(key) || Promise.resolve();
    const run = prev.then(fn, fn);
    const tail = run.then(() => undefined, () => undefined);
    this.#locks.set(key, tail);
    tail.then(() => {
      if (this.#locks.get(key) === tail) {
        this.#locks.delete(key);
      }
    });
    return run;
  }

  /**
   * RESPONDER side: build this device's per-device prekey bundle for a peer to
   * run X3DH against. The device's X3DH identity keypairs (signing + DH) are
   * passed in (bound to the device key by the caller). Returns the serialized
   * bundle (handed to the peer) + the preKeyState the responder must retain to
   * complete the handshake.
   */
  async buildDevicePreKeyBundle({ ownerAccountId, identityKeyPair, identityDhKeyPair } = {}) {
    requireNonEmpty(ownerAccountId, "ownerAccountId");
    requireKeyPair(identityKeyPair, "identityKeyPair");
    requireKeyPair(identityDhKeyPair, "identityDhKeyPair");
    const x3dh = new X3DHKeyExchange({ secureChannelManager: this.#scm() });
    const { binding, preKeyState } = await x3dh.prepareInviteBinding({
      accountId: ownerAccountId,
      identityKeyPair,
      identityDhKeyPair,
    });
    return { bundleJson: binding.x3dh, preKeyState };
  }

  /**
   * INITIATOR side: establish a per-device session against a peer device's
   * bundle and persist it under (owner, peerLinkId, peerDeviceId). MY device's
   * own X3DH identity keypairs (signing + DH) are passed in — they ride the
   * handshake so the peer device can verify them before deriving the shared
   * secret (the anti-substitution binding). Returns the handshakeData the peer
   * device needs to complete its responder session.
   */
  async establishInitiatorDeviceSession({ ownerAccountId, peerAccountId, peerLinkId, peerDeviceId, peerDeviceBundleJson, identityKeyPair, identityDhKeyPair } = {}) {
    requireNonEmpty(ownerAccountId, "ownerAccountId");
    requireNonEmpty(peerAccountId, "peerAccountId");
    requireNonEmpty(peerLinkId, "peerLinkId");
    requireNonEmpty(peerDeviceId, "peerDeviceId");
    requireKeyPair(identityKeyPair, "identityKeyPair");
    requireKeyPair(identityDhKeyPair, "identityDhKeyPair");
    if (!peerDeviceBundleJson || typeof peerDeviceBundleJson !== "object") {
      throw new Error("establishInitiatorDeviceSession requires peerDeviceBundleJson");
    }
    // Bind my device's identity-DH key to my device's X3DH signing key (DH1
    // anti-substitution). The caller's device key vouches for identityKeyPair
    // upstream (Slice 0); here we sign the DH pubkey under it.
    const initiatorIdentityDhSignature = await this.#cryptoProvider.sign({
      privateKey: identityKeyPair.privateKey,
      msg: identityDhKeyPair.publicKey,
    });
    const scm = this.#scm();
    const x3dh = new X3DHKeyExchange({ secureChannelManager: scm });
    const { handshakeData } = await x3dh.processAcceptedInvite({
      inviteBinding: { x3dh: peerDeviceBundleJson },
      peerId: peerAccountId,
      initiatorIdentityKeyPair: identityKeyPair,
      initiatorIdentityDhKeyPair: identityDhKeyPair,
      initiatorIdentityDhSignature,
    });
    const sessionId = await this.#withLock(this.#lockKey(ownerAccountId, peerLinkId, peerDeviceId), () => this.#persistDeviceSession({
      ownerAccountId, peerAccountId, peerLinkId, peerDeviceId, snapshot: scm.exportSnapshot(),
    }));
    return { handshakeData, sessionId };
  }

  /**
   * RESPONDER side completion: given the initiator's handshakeData plus our
   * retained preKeyState + device DH private key, establish + persist our
   * per-device session to that initiator device.
   */
  async establishResponderDeviceSession({ ownerAccountId, peerAccountId, peerLinkId, peerDeviceId, identityDhKeyPair, preKeyState, handshakeData } = {}) {
    requireNonEmpty(ownerAccountId, "ownerAccountId");
    requireNonEmpty(peerAccountId, "peerAccountId");
    requireNonEmpty(peerLinkId, "peerLinkId");
    requireNonEmpty(peerDeviceId, "peerDeviceId");
    requireKeyPair(identityDhKeyPair, "identityDhKeyPair");
    if (!preKeyState || typeof preKeyState !== "object") {
      throw new Error("establishResponderDeviceSession requires preKeyState");
    }
    if (!handshakeData || typeof handshakeData !== "object") {
      throw new Error("establishResponderDeviceSession requires handshakeData");
    }
    const scm = this.#scm();
    const x3dh = new X3DHKeyExchange({ secureChannelManager: scm });
    const { senderIdentitySigningPublicKey } = await x3dh.completeInviteHandshake({
      preKeyState,
      identityDhPrivate: identityDhKeyPair.privateKey,
      handshakeData,
      peerId: peerAccountId,
    });
    // Bind the claimed peerDeviceId to the AUTHENTICATED initiator device key
    // (Audit R2 #1). The X3DH responder verified the initiator's device signing
    // key (the DH-key signature is checked before any secret is derived), and the
    // self-cert deviceId IS sha256(that key). The caller passes peerDeviceId from
    // a PLAINTEXT claim (the in-band handshake's senderDeviceId), so without this
    // check a peer could run a valid handshake with its OWN device key yet claim
    // ANOTHER device's id, poisoning the session map. Refuse the mismatch and
    // persist nothing — the forged first-contact never establishes a session.
    if (!(senderIdentitySigningPublicKey instanceof Uint8Array) || senderIdentitySigningPublicKey.length === 0) {
      const err = new Error("establishResponderDeviceSession: handshake yielded no authenticated device key");
      err.code = "DEVICE_HANDSHAKE_UNAUTHENTICATED";
      throw err;
    }
    const authenticatedDeviceId = DeviceRegistrationV1.deviceIdFor(bytesToBase64(senderIdentitySigningPublicKey));
    if (authenticatedDeviceId !== peerDeviceId) {
      const err = new Error(
        "establishResponderDeviceSession: claimed peerDeviceId does not match the authenticated device key"
        + " (claimed " + peerDeviceId + ", authenticated " + authenticatedDeviceId + ")",
      );
      err.code = "DEVICE_ID_MISMATCH";
      throw err;
    }
    const sessionId = await this.#withLock(this.#lockKey(ownerAccountId, peerLinkId, peerDeviceId), () => this.#persistDeviceSession({
      ownerAccountId, peerAccountId, peerLinkId, peerDeviceId, snapshot: scm.exportSnapshot(),
    }));
    return { sessionId, authenticatedDeviceId };
  }

  /**
   * Encrypt for ONE peer device — advances only that device's ratchet. This is
   * the per-device fan-out primitive Slice 5 calls once per recipient device.
   */
  async encryptForDevice({ ownerAccountId, peerAccountId, peerLinkId, peerDeviceId, plaintextBytes } = {}) {
    requireNonEmpty(ownerAccountId, "ownerAccountId");
    requireNonEmpty(peerAccountId, "peerAccountId");
    requireNonEmpty(peerLinkId, "peerLinkId");
    requireNonEmpty(peerDeviceId, "peerDeviceId");
    if (!(plaintextBytes instanceof Uint8Array) || plaintextBytes.length === 0) {
      throw new Error("encryptForDevice requires non-empty plaintextBytes");
    }
    return this.#withLock(this.#lockKey(ownerAccountId, peerLinkId, peerDeviceId), async () => {
      const sessionRecord = await this.#requireDeviceSession(ownerAccountId, peerLinkId, peerDeviceId);
      const scm = this.#scm(sessionRecord.ratchetSnapshot);
      const codec = new E2eePacketCodec({ secureChannelManager: scm });
      const encryptedPacket = await codec.encryptForPeer({ peerId: peerAccountId, plaintextBytes });
      // ORDERING INVARIANT (Audit R4 #2 — do NOT flip): commit the advanced
      // ratchet snapshot HERE, BEFORE the caller (ServerMessagesService) persists
      // the sealed ciphertext to its fan-out cache. This is the SAFE order:
      //  - crash between this commit and the cache write ⇒ ratchet at N+1, no
      //    cached ciphertext, nothing dispatched. The retry takes the cache-miss
      //    path and RE-ENCRYPTS at the next key (N+1) → the message is delivered
      //    (the receiver simply skips the unused key N). No loss, no reuse.
      //  - the INVERSE order (cache the ciphertext first, commit the ratchet
      //    after) is UNSAFE: a crash between would leave the ratchet at N while a
      //    cached key-N ciphertext exists; the retry replays the cache without
      //    advancing the ratchet, so the NEXT message reuses key N — catastrophic
      //    nonce/key reuse. The fan-out cache is a delivery optimization, never
      //    the ratchet's system of record; the ratchet commit leads.
      await this.#peerLinkStorage.sessions.put({
        ...sessionRecord, ratchetSnapshot: scm.exportSnapshot(), updatedAtMs: this.#clock(),
      });
      return { encryptedPacket, sessionId: sessionRecord.sessionId };
    });
  }

  /**
   * Decrypt a packet known to be from a specific peer device. Throws
   * DECRYPT_FAILED if that device's ratchet cannot decrypt it.
   */
  async decryptFromDevice({ ownerAccountId, peerAccountId, peerLinkId, peerDeviceId, packetBytes } = {}) {
    requireNonEmpty(ownerAccountId, "ownerAccountId");
    requireNonEmpty(peerLinkId, "peerLinkId");
    requireNonEmpty(peerDeviceId, "peerDeviceId");
    // require:true ⇒ a missing session throws THREAD_NOT_READY; a present session
    // that cannot decrypt returns null here → DECRYPT_FAILED (the two distinct
    // failure modes the callers depend on).
    const result = await this.#attemptDeviceDecrypt(ownerAccountId, peerAccountId, peerLinkId, peerDeviceId, packetBytes, { require: true });
    if (!result) {
      const err = new Error("E2EE decryption failed for device " + peerDeviceId);
      err.code = "DECRYPT_FAILED";
      throw err;
    }
    return { plaintextBytes: result.plaintextBytes, sessionId: result.sessionId };
  }

  /**
   * Trial-decrypt an opaque packet across every per-device session under a peer
   * link (mirrors decryptDirectMessageAnyPeer for the device dimension — the
   * receiver does not know which peer device sent the deposit). ONLY the session
   * that decrypts has its advanced snapshot persisted; a failed trial leaves
   * every other device session byte-unchanged. Returns null on no match.
   */
  async trialDecryptAcrossDevices({ ownerAccountId, peerAccountId, peerLinkId, packetBytes } = {}) {
    requireNonEmpty(ownerAccountId, "ownerAccountId");
    requireNonEmpty(peerLinkId, "peerLinkId");
    // Snapshot the candidate device set (a read, not under any single device's
    // lock — keying the whole trial on one coarse peer-link lock is exactly the
    // over-serialization audit P2 flagged). Each attempt then takes ONLY that
    // device's lock and RE-READS the record inside it, so it acts on a fresh
    // snapshot and serializes correctly against a concurrent send to that device.
    const sessions = await this.#peerLinkStorage.sessions.listByPeerLink(ownerAccountId, peerLinkId);
    for (const sessionRecord of sessions) {
      const peerDeviceId = sessionRecord && sessionRecord.peerDeviceId ? sessionRecord.peerDeviceId : null;
      if (!peerDeviceId) continue;
      const result = await this.#attemptDeviceDecrypt(ownerAccountId, peerAccountId, peerLinkId, peerDeviceId, packetBytes, { require: false });
      if (result) {
        return { peerDeviceId, plaintextBytes: result.plaintextBytes, sessionId: result.sessionId };
      }
    }
    return null;
  }

  // --- internals ---

  // Decrypt a packet against ONE device session, holding only that device's lock
  // and reloading the record inside it. Returns { plaintextBytes, sessionId } on
  // success, null on a present-but-non-matching session. With require:true a
  // missing session throws THREAD_NOT_READY; with require:false it returns null
  // (so trial-decrypt can skip to the next device).
  async #attemptDeviceDecrypt(ownerAccountId, peerAccountId, peerLinkId, peerDeviceId, packetBytes, { require }) {
    return this.#withLock(this.#lockKey(ownerAccountId, peerLinkId, peerDeviceId), async () => {
      const sessionRecord = await this.#peerLinkStorage.sessions.getByPeerLinkAndDevice(ownerAccountId, peerLinkId, peerDeviceId);
      if (!sessionRecord || typeof sessionRecord !== "object") {
        if (require) {
          const err = new Error("No secure session for device " + peerDeviceId);
          err.code = "THREAD_NOT_READY";
          throw err;
        }
        return null;
      }
      const result = await this.#tryDecrypt(sessionRecord, peerAccountId || sessionRecord.peerAccountId, packetBytes);
      if (!result.ok) return null;
      return { plaintextBytes: result.plaintextBytes, sessionId: sessionRecord.sessionId };
    });
  }

  async #tryDecrypt(sessionRecord, expectedPeerAccountId, packetBytes) {
    if (!(packetBytes instanceof Uint8Array) || packetBytes.length === 0) {
      throw new Error("decrypt requires non-empty packetBytes");
    }
    const scm = this.#scm(sessionRecord.ratchetSnapshot);
    const codec = new E2eePacketCodec({ secureChannelManager: scm });
    // NO broad catch: a wrong-session packet is NOT a throw — E2eePacketCodec
    // catches the ratchet/AEAD failure internally and returns the structured
    // { encrypted:true, peerId:null } non-match (handled below). Only a MALFORMED
    // packet or an unexpected fault throws here, and those MUST surface — never be
    // silently mislabeled "wrong device" and dropped (the audited swallow bug).
    const result = await codec.decryptIncoming({ packetBytes });
    const decrypted = Boolean(result && result.encrypted === true && result.peerId && !result.handshake);
    if (!decrypted) {
      return { ok: false };
    }
    // The session cryptographically authenticates the real sender; refuse if it
    // is not the peer we were told to expect rather than silently accept a
    // cross-peer mix-up (the previously-dead peerAccountId param, now enforced).
    if (expectedPeerAccountId && result.peerId !== expectedPeerAccountId) {
      return { ok: false };
    }
    // Persist ONLY the matching session's advance (non-matches never write).
    await this.#peerLinkStorage.sessions.put({
      ...sessionRecord, ratchetSnapshot: scm.exportSnapshot(), updatedAtMs: this.#clock(),
    });
    return { ok: true, plaintextBytes: result.plaintextBytes };
  }

  // Persist a device session. Re-establishment for an existing
  // (owner, peerLinkId, peerDeviceId) REUSES the prior sessionId (update in
  // place) instead of minting a new one — otherwise old session RECORDS would
  // accumulate (listByPeerLink scans every record) and stale ratchets could keep
  // trial-decrypting old traffic. One record per device, always.
  async #persistDeviceSession({ ownerAccountId, peerAccountId, peerLinkId, peerDeviceId, snapshot }) {
    const now = this.#clock();
    const existing = await this.#peerLinkStorage.sessions.getByPeerLinkAndDevice(ownerAccountId, peerLinkId, peerDeviceId);
    const hasExisting = existing && typeof existing === "object";
    const sessionId = hasExisting && existing.sessionId ? existing.sessionId : ("pls_" + runtimeUuid());
    const createdAtMs = hasExisting && existing.createdAtMs ? existing.createdAtMs : now;
    const stored = await this.#peerLinkStorage.sessions.put({
      sessionId,
      peerLinkId,
      localAccountId: ownerAccountId,
      peerAccountId,
      peerDeviceId,
      status: SESSION_STATUS_ACTIVE,
      ratchetSnapshot: snapshot,
      createdAtMs,
      updatedAtMs: now,
    });
    return stored.sessionId;
  }

  async #requireDeviceSession(ownerAccountId, peerLinkId, peerDeviceId) {
    const sessionRecord = await this.#peerLinkStorage.sessions.getByPeerLinkAndDevice(ownerAccountId, peerLinkId, peerDeviceId);
    if (!sessionRecord || typeof sessionRecord !== "object") {
      const err = new Error("No secure session for device " + peerDeviceId);
      err.code = "THREAD_NOT_READY";
      throw err;
    }
    return sessionRecord;
  }
}

function requireNonEmpty(value, label) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error("DevicePeerSessions requires " + label);
  }
}

function requireKeyPair(kp, label) {
  if (!kp || !(kp.publicKey instanceof Uint8Array) || !(kp.privateKey instanceof Uint8Array)) {
    throw new Error("DevicePeerSessions requires " + label + " with publicKey/privateKey bytes");
  }
}
