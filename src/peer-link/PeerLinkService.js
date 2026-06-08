import { createHash, randomUUID } from "node:crypto";
import {
  E2eeHandshakeAckV1,
  E2eeHandshakeRejectV1,
  E2eePacketCodec,
  SecureChannelManager,
  X3DHKeyExchange,
  base64ToBytes,
  bytesToBase64,
  buildDurableRecordV1,
  canonicalJSONStringify,
  deriveAccountIdFromPublicKey,
  durableRecordSignableBytes,
  nonEmpty,
  PEERLINK_INVITE_RECORD_KIND,
  requireId,
  signHandshakeEnvelope,
  verifyHandshakeEnvelope,
} from "@rezprotocol/core";
import { canonicalPayloadBytesV1 } from "./inviteCodeV1.js";
import {
  PEER_LINK_STATE,
  SESSION_STATUS,
  isSessionUsable,
  assertTransition,
} from "./PeerLinkStateMachine.js";

const PEER_LINK_INVITE_PREFIX = "app:peer-links:invites/";
const PEER_LINK_INVITE_HASH_PREFIX = "app:peer-links:inviteHash/";
const INVITE_CLAIM_LOCKS = new Map();
const HANDSHAKE_ACK_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const REHANDSHAKE_DECRYPT_FAILURE_THRESHOLD = 3;
// A session that successfully decrypted authenticated traffic within this window
// is treated as HEALTHY: undecryptable packets arriving alongside it are noise
// or replay, NOT a desync, and must NOT arm a destructive re-handshake. Defeats
// "malicious relay injects bad packets to tear down a working link". An idle link
// (no recent success) can still recover — those recoveries are low-harm and are
// further bounded by the chat-layer recovery-invite trigger cooldown and the
// short recovery-invite TTL (a stale/replayed invite auto-expires).
const HEALTHY_SESSION_DECRYPT_GUARD_MS = 30 * 1000;

function asPositiveInt(value, fallback) {
  const num = Number(value);
  if (!Number.isInteger(num) || num < 1) {
    return fallback;
  }
  return num;
}

function stableId(prefix) {
  const digest = createHash("sha256")
    .update(`${Date.now()}:${randomUUID()}:${prefix}`)
    .digest("base64url");
  return `${prefix}_${digest.slice(0, 24)}`;
}

async function withLock(lockKey, fn) {
  const key = String(lockKey || "").trim();
  if (!key) {
    return fn();
  }
  const previous = INVITE_CLAIM_LOCKS.get(key) || Promise.resolve();
  let release;
  const current = new Promise((resolve) => {
    release = resolve;
  });
  const queued = previous.finally(() => current);
  INVITE_CLAIM_LOCKS.set(key, queued);
  await previous;
  try {
    return await fn();
  } finally {
    release();
    if (INVITE_CLAIM_LOCKS.get(key) === queued) {
      INVITE_CLAIM_LOCKS.delete(key);
    }
  }
}

function inviteKey(ownerAccountId, inviteId) {
  return `${PEER_LINK_INVITE_PREFIX}${requireId(ownerAccountId, "ownerAccountId")}/${requireId(inviteId, "inviteId")}`;
}

function inviteHashKey(ownerAccountId, tokenHash) {
  return `${PEER_LINK_INVITE_HASH_PREFIX}${requireId(ownerAccountId, "ownerAccountId")}/${requireId(tokenHash, "tokenHash")}`;
}

function normalizeInviteRecord(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return null;
  }
  const inviteId = nonEmpty(input.inviteId);
  const ownerAccountId = nonEmpty(input.ownerAccountId);
  const tokenHash = nonEmpty(input.tokenHash);
  const kind = nonEmpty(input.kind);
  if (!inviteId || !ownerAccountId || !tokenHash || !kind) {
    return null;
  }
  return {
    inviteId,
    ownerAccountId,
    tokenHash,
    kind,
    status: nonEmpty(input.status) || "active",
    createdAtMs: asPositiveInt(input.createdAtMs, Date.now()),
    updatedAtMs: asPositiveInt(input.updatedAtMs, asPositiveInt(input.createdAtMs, Date.now())),
    expiresAtMs: asPositiveInt(input.expiresAtMs, Date.now()),
    maxUses: asPositiveInt(input.maxUses, 1),
    // Distinct cryptographically-authenticated acceptor accountIds that have
    // been honoured by the handshake responder (the single maxUses
    // enforcement point). Replaces the old `uses` counter: keying on identity
    // makes re-delivered handshakes idempotent and survives inviter restart.
    acceptedAcceptors: Array.isArray(input.acceptedAcceptors)
      ? input.acceptedAcceptors.filter((a) => typeof a === "string" && a.length > 0)
      : [],
    peerLinkId: nonEmpty(input.peerLinkId),
    groupId: nonEmpty(input.groupId),
    envelope: input.envelope && typeof input.envelope === "object" && !Array.isArray(input.envelope) ? input.envelope : null,
    signatureB64: nonEmpty(input.signatureB64),
  };
}

function verifyInviteKind(envelope) {
  const kind = nonEmpty(envelope.kind) || "direct";
  if (kind !== "direct" && kind !== "group") {
    const err = new Error(`unsupported peer-link invite kind: ${kind}`);
    err.code = "PEER_LINK_KIND_UNSUPPORTED";
    throw err;
  }
  return kind;
}

function normalizeBinding(inviteBinding) {
  if (!inviteBinding) {
    return null;
  }
  let base = inviteBinding;
  if (typeof inviteBinding === "function") {
    base = inviteBinding();
  }
  if (!base || typeof base !== "object" || Array.isArray(base)) {
    return null;
  }
  const mailboxId = nonEmpty(base.mailboxId);
  const capabilityId = nonEmpty(base.capabilityId);
  if (!mailboxId || !capabilityId) {
    return null;
  }
  return { mailboxId, capabilityId };
}

function cloneJson(value) {
  if (value === undefined) {
    return undefined;
  }
  return JSON.parse(JSON.stringify(value));
}

function x3dhBindingPayload({ accountId, x3dhIdentityPublicKeyB64, issuedAtMs, expiresAtMs } = {}) {
  return {
    kind: "x3dh-subkey-binding",
    accountId,
    x3dhIdentityPublicKeyB64,
    issuedAtMs,
    expiresAtMs,
  };
}

function signedPayloadBytes(payload) {
  return new TextEncoder().encode(canonicalJSONStringify(payload));
}

function _postCapKey(ownerAccountId, peerLinkId) {
  return "peer-link:post-cap:" + ownerAccountId + ":" + peerLinkId;
}

export class PeerLinkService {
  #decryptFailureCounts;
  // Per-(owner:peer) count of any-peer trial-decrypt total misses. Unlike
  // #decryptFailureCounts (per-peer, set by decryptDirectMessage), this tracks
  // the recipient-side recovery signal for decryptDirectMessageAnyPeer, which
  // cannot attribute a miss to one peer from the packet alone. Cleared on any
  // successful establish/decrypt for the peer.
  #anyPeerMissCounts;
  // Per-(owner:peer) timestamp of the last successful any-peer trial decrypt.
  // Used to protect a demonstrably-healthy session from being torn down by
  // injected/undecryptable noise (HEALTHY_SESSION_DECRYPT_GUARD_MS).
  #anyPeerLastSuccessAt;
  // When true, an untabulated peer-link transition throws instead of being
  // logged-and-allowed. Default false (observe-only) for this ship; flip once
  // the transition table is proven against production telemetry.
  #strictTransitions;

  constructor({
    storageProvider,
    clock = () => Date.now(),
    ownerAccountId = null,
    signer = null,
    verifier = null,
    getInviteAuthority = null,
    inviteBinding = null,
    cryptoProvider = null,
    inboxClaimantSigner = null,
    strictTransitions = false,
  } = {}) {
    if (!storageProvider || typeof storageProvider.getPeerLinkStorage !== "function") {
      throw new Error("PeerLinkService requires storageProvider.getPeerLinkStorage()");
    }
    if (typeof storageProvider.getKeyValueStore !== "function") {
      throw new Error("PeerLinkService requires storageProvider.getKeyValueStore()");
    }
    if (typeof clock !== "function") {
      throw new Error("PeerLinkService requires clock");
    }
    const hasStatic = !!signer
      && typeof signer.sign === "function"
      && typeof signer.getSignerRef === "function"
      && !!verifier
      && typeof verifier.verify === "function";
    const hasProvider = typeof getInviteAuthority === "function";
    if (!hasStatic && !hasProvider) {
      throw new Error("PeerLinkService requires signer+verifier or getInviteAuthority(accountId)");
    }
    this.storageProvider = storageProvider;
    this.peerLinkStorage = storageProvider.getPeerLinkStorage(null);
    this.kv = storageProvider.getKeyValueStore(null);
    this.clock = clock;
    this.ownerAccountId = nonEmpty(ownerAccountId);
    this.signer = signer;
    this.verifier = verifier;
    this.getInviteAuthority = getInviteAuthority;
    this.inviteBinding = normalizeBinding(inviteBinding);
    this.cryptoProvider = cryptoProvider;
    // Optional signer for delegating sub-caps rooted in chat-server's inbox
    // claim. Used by createInvite to attach a bearer post-cap to the invite
    // envelope so the acceptor can deposit to the inviter's mailbox.
    this.inboxClaimantSigner = inboxClaimantSigner;
    this.#decryptFailureCounts = new Map();
    this.#anyPeerMissCounts = new Map();
    this.#anyPeerLastSuccessAt = new Map();
    this.#strictTransitions = strictTransitions === true;
  }

  /**
   * Returns the inviter-signed bearer post-cap stored for this peer-link, or
   * null if none was attached. Callers use this to populate the `capChain`
   * field on outbound mailbox.deposit requests targeting the peer's inbox.
   */
  async getPostCapForPeerLink(ownerAccountId, peerLinkId) {
    if (typeof ownerAccountId !== "string" || ownerAccountId.trim().length === 0) return null;
    if (typeof peerLinkId !== "string" || peerLinkId.trim().length === 0) return null;
    const stored = await this.kv.get(_postCapKey(ownerAccountId.trim(), peerLinkId.trim()));
    return stored && typeof stored === "object" ? stored : null;
  }

  async _resolveAuthority(accountId) {
    if (typeof this.getInviteAuthority === "function") {
      const authority = await Promise.resolve(this.getInviteAuthority(accountId));
      if (!authority || !authority.signer || !authority.verifier) {
        throw new Error("getInviteAuthority must return { signer, verifier }");
      }
      return authority;
    }
    return {
      signer: this.signer,
      verifier: this.verifier,
    };
  }

  async _saveInviteRecord(record) {
    const normalized = normalizeInviteRecord(record);
    if (!normalized) {
      throw new Error("invalid peer-link invite record");
    }
    await this.kv.set(inviteKey(normalized.ownerAccountId, normalized.inviteId), normalized);
    await this.kv.set(inviteHashKey(normalized.ownerAccountId, normalized.tokenHash), normalized.inviteId);
    return cloneJson(normalized);
  }

  async _getInviteRecord(ownerAccountId, inviteId) {
    const stored = await this.kv.get(inviteKey(ownerAccountId, inviteId));
    return normalizeInviteRecord(stored);
  }

  async _getInviteRecordByHash(ownerAccountId, tokenHash) {
    const inviteId = await this.kv.get(inviteHashKey(ownerAccountId, tokenHash));
    if (typeof inviteId !== "string" || !inviteId) {
      return null;
    }
    return this._getInviteRecord(ownerAccountId, inviteId);
  }

  async _appendPeerLinkEvent({ ownerAccountId = this.ownerAccountId, peerLinkId, type, summary, details, atMs } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    const eventRecord = {
      ownerAccountId: owner,
      eventId: stableId("pev"),
      peerLinkId: requireId(peerLinkId, "peerLinkId"),
      type: requireId(type, "type"),
      atMs: asPositiveInt(atMs, this.clock()),
      summary: nonEmpty(summary) || null,
      details: details && typeof details === "object" && !Array.isArray(details) ? cloneJson(details) : {},
    };
    const stored = await this.peerLinkStorage.events.append(eventRecord);
    return stored;
  }

  _createSecureChannelManager(snapshot) {
    if (!this.cryptoProvider) {
      throw new Error("PeerLinkService requires cryptoProvider for secure session operations");
    }
    const manager = new SecureChannelManager({ crypto: this.cryptoProvider });
    if (snapshot && typeof snapshot === "object") {
      manager.importSnapshot(snapshot);
    }
    return manager;
  }

  // Observe-only reporter for an illegal peer-link transition. Wired into
  // #commitSession (and the acceptInvite/reject updates) via assertTransition so
  // every state write is validated against the SSOT transition table without
  // changing behavior. See PeerLinkStateMachine.
  #logIllegalTransition(result, peerLinkId) {
    // eslint-disable-next-line no-console
    console.warn(
      "[PLTRACE] illegal peer-link transition "
      + (result && result.from ? result.from : "<none>")
      + " -> " + (result && result.to ? result.to : "<none>")
      + " peerLinkId=" + (peerLinkId || "<unknown>"),
    );
  }

  // Validate (and log-or-throw on) a peer-link state transition using the
  // service's strict flag and the shared reporter. Returns the check result.
  #checkPeerLinkTransition(fromState, toState, peerLinkId) {
    return assertTransition(fromState, toState, {
      onIllegal: (r) => this.#logIllegalTransition(r, peerLinkId),
      strict: this.#strictTransitions,
    });
  }

  // X3DH responder derivation used by handleIncomingHandshakePacket. Completes
  // the invite handshake against our stored pre-key state and returns the secured
  // channel manager (the caller persists it via #commitSession).
  async #establishAsResponder({ ownerAccountId, preKeyState, handshakeData, peerId }) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    const remote = requireId(peerId, "peerId");
    const secureChannelManager = this._createSecureChannelManager();
    const x3dh = new X3DHKeyExchange({ secureChannelManager });
    const { identityDhKeyPair } = await this._requireBoundX3dhIdentity(owner);
    await x3dh.completeInviteHandshake({
      preKeyState,
      identityDhPrivate: identityDhKeyPair.privateKey,
      handshakeData,
      peerId: remote,
    });
    return { secureChannelManager };
  }

  // The single peer-link/session state-writer. EVERY establishment path that
  // moves a peer link toward (or confirms) a session routes its persistence
  // through here so the lifecycle is written in exactly one place:
  //   1. resolve session identity/version (reuse existingSession when given),
  //   2. export the ratchet snapshot (or reuse the stored one for ack flips),
  //   3. sessions.put,
  //   4. validate + apply the peerLinks.update transition,
  //   5. append the lifecycle event,
  //   6. clear stale decrypt/recovery counters for the peer.
  // The caller passes its live peerLinkRecord so the optimistic-lock `version`
  // flows through unchanged; #commitSession never re-reads the record. A
  // peerLinks version mismatch propagates to the caller (the ack path wraps it
  // to recover from a duplicate ack).
  async #commitSession({
    ownerAccountId,
    peerLinkRecord,
    peerAccountId,
    secureChannelManager = null,
    sessionStatus,
    peerLinkState,
    existingSession = null,
    resetSessionCreatedAt = false,
    peerInboxId,
    eventType,
    eventSummary = null,
    eventDetails = {},
    atMs = null,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    const remote = requireId(peerAccountId, "peerAccountId");
    if (!peerLinkRecord || typeof peerLinkRecord !== "object") {
      throw new Error("#commitSession requires peerLinkRecord");
    }
    const peerLinkId = requireId(peerLinkRecord.peerLinkId, "peerLinkId");
    const now = asPositiveInt(atMs, this.clock());

    // 1-3. Persist the session, unless this is a pure state write with neither a
    // fresh ratchet nor a stored snapshot to carry (the ack path tolerates a
    // missing session: it then only advances the peer-link state).
    let storedSession = null;
    let ratchetSnapshot = null;
    if (secureChannelManager) {
      ratchetSnapshot = secureChannelManager.exportSnapshot();
    } else if (existingSession && existingSession.ratchetSnapshot) {
      ratchetSnapshot = existingSession.ratchetSnapshot;
    }
    if (ratchetSnapshot) {
      const sessionId = existingSession && existingSession.sessionId ? existingSession.sessionId : stableId("pls");
      const createdAtMs = (!resetSessionCreatedAt && existingSession && existingSession.createdAtMs)
        ? existingSession.createdAtMs
        : now;
      const sessionVersion = existingSession && existingSession.version ? existingSession.version : 1;
      storedSession = await this.peerLinkStorage.sessions.put({
        ...(existingSession && typeof existingSession === "object" ? existingSession : {}),
        sessionId,
        peerLinkId,
        localAccountId: owner,
        peerAccountId: remote,
        status: sessionStatus,
        ratchetSnapshot,
        createdAtMs,
        updatedAtMs: now,
        version: sessionVersion,
      });
    }

    // 4. Validate (log-and-allow) then apply the peer-link state transition.
    this.#checkPeerLinkTransition(peerLinkRecord.state, peerLinkState, peerLinkId);
    const nextActiveSessionId = storedSession ? storedSession.sessionId : peerLinkRecord.activeSessionId;
    const nextPeerInboxId = peerInboxId === undefined ? peerLinkRecord.peerInboxId : peerInboxId;
    const nextPeerLinkRecord = await this.peerLinkStorage.peerLinks.update({
      ...peerLinkRecord,
      state: peerLinkState,
      activeSessionId: nextActiveSessionId,
      peerInboxId: nextPeerInboxId,
      lastStateChangeAtMs: now,
      lastErrorCode: null,
      lastErrorMessage: null,
    }, peerLinkRecord.version);

    // 5. Append the lifecycle event. peerAccountId + sessionId are common to
    //    every establish event, so they are merged in here; the caller passes
    //    only the extras (inviteId / requestId). Caller keys win on collision.
    const event = await this._appendPeerLinkEvent({
      ownerAccountId: owner,
      peerLinkId: nextPeerLinkRecord.peerLinkId,
      type: eventType,
      summary: eventSummary,
      details: {
        peerAccountId: remote,
        sessionId: storedSession ? storedSession.sessionId : null,
        ...(eventDetails && typeof eventDetails === "object" && !Array.isArray(eventDetails) ? eventDetails : {}),
      },
      atMs: now,
    });

    // 6. A successful establish clears stale decrypt/recovery accounting AND
    // marks the link healthy (an X3DH establish is authenticated traffic). This
    // is load-bearing for recovery convergence: when a desynced link is re-keyed
    // by re-invite, the messages the peer already sent against the OLD (now dead)
    // session are still buffered and keep failing to decrypt — without this they
    // would immediately re-arm recovery and the two sides would chase each other
    // re-keying (the live churn that defeated the first cut). Treating the fresh
    // session as healthy for HEALTHY_SESSION_DECRYPT_GUARD_MS lets the new session
    // prove itself (the peer's next real message decrypts) before any residual
    // miss can trigger another recovery.
    const counterKey = owner + ":" + remote;
    this.#decryptFailureCounts.delete(counterKey);
    this.#anyPeerMissCounts.delete(counterKey);
    this.#anyPeerLastSuccessAt.set(counterKey, now);

    return {
      snapshot: await this._buildSnapshot(nextPeerLinkRecord),
      event,
      sessionRecord: storedSession,
      peerLinkRecord: nextPeerLinkRecord,
    };
  }

  _normalizeStoredAccountKeyRecord(stored) {
    const material = stored && typeof stored === "object"
      ? (
          stored.x3dhKeyMaterial && typeof stored.x3dhKeyMaterial === "object"
            ? stored.x3dhKeyMaterial
            : stored
        )
      : null;
    const publicKeyB64 = material && typeof material === "object" ? nonEmpty(material.publicKeyB64) : null;
    const privateKeyB64 = material && typeof material === "object" ? nonEmpty(material.privateKeyB64) : null;
    const dhMaterial = stored && typeof stored === "object" && stored.x3dhIdentityDhKeyMaterial && typeof stored.x3dhIdentityDhKeyMaterial === "object"
      ? stored.x3dhIdentityDhKeyMaterial
      : null;
    const dhPublicKeyB64 = dhMaterial ? nonEmpty(dhMaterial.publicKeyB64) : null;
    const dhPrivateKeyB64 = dhMaterial ? nonEmpty(dhMaterial.privateKeyB64) : null;
    const identityDhSignatureB64 = stored && typeof stored === "object" ? nonEmpty(stored.identityDhSignatureB64) : null;
    const accountBinding = stored && typeof stored === "object" && stored.accountBinding && typeof stored.accountBinding === "object"
      ? {
          accountId: nonEmpty(stored.accountBinding.accountId),
          accountIdentityPublicKeyB64: nonEmpty(stored.accountBinding.accountIdentityPublicKeyB64),
          x3dhIdentityPublicKeyB64: nonEmpty(stored.accountBinding.x3dhIdentityPublicKeyB64),
          issuedAtMs: Number.isFinite(Number(stored.accountBinding.issuedAtMs)) ? Number(stored.accountBinding.issuedAtMs) : null,
          expiresAtMs: Number.isFinite(Number(stored.accountBinding.expiresAtMs)) ? Number(stored.accountBinding.expiresAtMs) : null,
          accountBindingSigB64: nonEmpty(stored.accountBinding.accountBindingSigB64),
        }
      : null;
    return {
      x3dhKeyMaterial: {
        publicKeyB64,
        privateKeyB64,
      },
      x3dhIdentityDhKeyMaterial: {
        publicKeyB64: dhPublicKeyB64,
        privateKeyB64: dhPrivateKeyB64,
      },
      identityDhSignatureB64,
      accountBinding,
    };
  }

  async _loadAccountKeyRecord(accountId) {
    const owner = requireId(accountId, "accountId");
    const stored = await this.peerLinkStorage.keys.getAccountIdentity(owner);
    const normalized = this._normalizeStoredAccountKeyRecord(stored);
    const hasSigning = normalized.x3dhKeyMaterial.publicKeyB64 && normalized.x3dhKeyMaterial.privateKeyB64;
    const hasDh = normalized.x3dhIdentityDhKeyMaterial.publicKeyB64
      && normalized.x3dhIdentityDhKeyMaterial.privateKeyB64
      && normalized.identityDhSignatureB64;
    if (hasSigning && hasDh) {
      const persistMissing = !stored
        || !stored.x3dhKeyMaterial
        || !stored.x3dhIdentityDhKeyMaterial
        || !stored.identityDhSignatureB64
        || stored.accountBinding === undefined;
      if (persistMissing) {
        await this.peerLinkStorage.keys.putAccountIdentity(owner, normalized);
      }
      return normalized;
    }
    if (typeof this.cryptoProvider.generateSigningKeyPair !== "function") {
      throw new Error("PeerLinkService cryptoProvider.generateSigningKeyPair() required");
    }
    let signingPublicKeyB64 = normalized.x3dhKeyMaterial.publicKeyB64;
    let signingPrivateKeyB64 = normalized.x3dhKeyMaterial.privateKeyB64;
    if (!hasSigning) {
      const generated = await this.cryptoProvider.generateSigningKeyPair();
      if (!generated || !(generated.publicKey instanceof Uint8Array) || !(generated.privateKey instanceof Uint8Array)) {
        throw new Error("cryptoProvider.generateSigningKeyPair() returned invalid key pair");
      }
      signingPublicKeyB64 = bytesToBase64(generated.publicKey);
      signingPrivateKeyB64 = bytesToBase64(generated.privateKey);
    }
    // Generate the long-term identity DH key (X25519) and sign its pubkey with
    // the X3DH identity signing key. This binds the DH key to the identity so
    // that DH1 in X3DH cryptographically requires possession of the identity
    // signing privkey — closing the impersonation gap from SECURITY_AUDIT.md
    // CRITICAL-1.
    const dhPair = await this.cryptoProvider.dhGenerateKeyPair();
    if (!dhPair || !(dhPair.publicKey instanceof Uint8Array) || !(dhPair.privateKey instanceof Uint8Array)) {
      throw new Error("cryptoProvider.dhGenerateKeyPair() returned invalid key pair");
    }
    const identityDhSignature = await this.cryptoProvider.sign({
      privateKey: base64ToBytes(signingPrivateKeyB64),
      msg: dhPair.publicKey,
    });
    if (!(identityDhSignature instanceof Uint8Array)) {
      throw new Error("cryptoProvider.sign() returned invalid signature");
    }
    const record = {
      x3dhKeyMaterial: {
        publicKeyB64: signingPublicKeyB64,
        privateKeyB64: signingPrivateKeyB64,
      },
      x3dhIdentityDhKeyMaterial: {
        publicKeyB64: bytesToBase64(dhPair.publicKey),
        privateKeyB64: bytesToBase64(dhPair.privateKey),
      },
      identityDhSignatureB64: bytesToBase64(identityDhSignature),
      accountBinding: hasSigning && stored && stored.accountBinding ? stored.accountBinding : null,
    };
    await this.peerLinkStorage.keys.putAccountIdentity(owner, record);
    return record;
  }

  async _ensureIdentityKeyPair(accountId) {
    const record = await this._loadAccountKeyRecord(accountId);
    return {
      publicKey: base64ToBytes(record.x3dhKeyMaterial.publicKeyB64),
      privateKey: base64ToBytes(record.x3dhKeyMaterial.privateKeyB64),
    };
  }

  async getOrCreateAccountBindingChallenge({ ownerAccountId = this.ownerAccountId } = {}) {
    return this._primeAccountBindingChallenge(ownerAccountId);
  }

  async _primeAccountBindingChallenge(ownerAccountId) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    const record = await this._loadAccountKeyRecord(owner);
    return { x3dhIdentityPublicKeyB64: record.x3dhKeyMaterial.publicKeyB64 };
  }

  async upsertAccountBinding({ ownerAccountId = this.ownerAccountId, accountBinding } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    const binding = accountBinding && typeof accountBinding === "object" ? cloneJson(accountBinding) : null;
    if (!binding) {
      throw new Error("accountBinding is required");
    }
    const record = await this._loadAccountKeyRecord(owner);
    record.accountBinding = binding;
    await this.peerLinkStorage.keys.putAccountIdentity(owner, record);
    return cloneJson(record.accountBinding);
  }

  async _requireBoundX3dhIdentity(accountId) {
    const owner = requireId(accountId, "accountId");
    const record = await this._loadAccountKeyRecord(owner);
    await this._primeAccountBindingChallenge(owner);
    const binding = record.accountBinding && typeof record.accountBinding === "object"
      ? record.accountBinding
      : null;
    if (!binding) {
      const err = new Error("peer-link X3DH binding missing");
      err.code = "REAUTH_REQUIRED";
      throw err;
    }
    if (binding.accountId !== owner) {
      const err = new Error("peer-link X3DH binding account mismatch");
      err.code = "REAUTH_REQUIRED";
      throw err;
    }
    if (binding.x3dhIdentityPublicKeyB64 !== record.x3dhKeyMaterial.publicKeyB64) {
      const err = new Error("peer-link X3DH binding stale");
      err.code = "REAUTH_REQUIRED";
      throw err;
    }
    if (!Number.isFinite(Number(binding.expiresAtMs)) || Number(binding.expiresAtMs) <= this.clock()) {
      const err = new Error("peer-link X3DH binding expired");
      err.code = "REAUTH_REQUIRED";
      throw err;
    }
    return {
      keyPair: {
        publicKey: base64ToBytes(record.x3dhKeyMaterial.publicKeyB64),
        privateKey: base64ToBytes(record.x3dhKeyMaterial.privateKeyB64),
      },
      identityDhKeyPair: {
        publicKey: base64ToBytes(record.x3dhIdentityDhKeyMaterial.publicKeyB64),
        privateKey: base64ToBytes(record.x3dhIdentityDhKeyMaterial.privateKeyB64),
      },
      identityDhSignature: base64ToBytes(record.identityDhSignatureB64),
      accountBinding: cloneJson(binding),
    };
  }

  async _verifyInviteX3dhBinding({ ownerAccountId, inviteBinding } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    const x3dh = inviteBinding && inviteBinding.x3dh ? inviteBinding.x3dh : null;
    if (!x3dh || typeof x3dh !== "object") {
      const err = new Error("peer-link invite X3DH binding missing");
      err.code = "INVITE_SIGNATURE_INVALID";
      throw err;
    }
    const accountIdentityPublicKeyB64 = nonEmpty(x3dh.accountIdentityPublicKeyB64);
    const accountBindingSigB64 = nonEmpty(x3dh.accountBindingSigB64);
    const accountBindingExpiresAtMs = Number(x3dh.accountBindingExpiresAtMs);
    const x3dhIdentityPublicKeyB64 = nonEmpty(x3dh.identitySigningPublicKeyB64);
    if (!accountIdentityPublicKeyB64 || !accountBindingSigB64 || !x3dhIdentityPublicKeyB64 || !Number.isFinite(accountBindingExpiresAtMs)) {
      const err = new Error("peer-link invite X3DH binding invalid");
      err.code = "INVITE_SIGNATURE_INVALID";
      throw err;
    }
    let accountIdentityPublicKey;
    let accountBindingSig;
    try {
      accountIdentityPublicKey = base64ToBytes(accountIdentityPublicKeyB64);
      accountBindingSig = base64ToBytes(accountBindingSigB64);
    } catch {
      const err = new Error("peer-link invite X3DH binding invalid");
      err.code = "INVITE_SIGNATURE_INVALID";
      throw err;
    }
    if (deriveAccountIdFromPublicKey(accountIdentityPublicKey) !== owner) {
      const err = new Error("peer-link invite X3DH binding account mismatch");
      err.code = "INVITE_SIGNATURE_INVALID";
      throw err;
    }
    if (accountBindingExpiresAtMs <= this.clock()) {
      const err = new Error("peer-link invite X3DH binding expired");
      err.code = "INVITE_SIGNATURE_INVALID";
      throw err;
    }
    const verified = await this.cryptoProvider.verify({
      publicKey: accountIdentityPublicKey,
      msg: signedPayloadBytes(x3dhBindingPayload({
        accountId: owner,
        x3dhIdentityPublicKeyB64,
        issuedAtMs: Number(x3dh.accountBindingIssuedAtMs) || 0,
        expiresAtMs: accountBindingExpiresAtMs,
      })),
      sig: accountBindingSig,
    });
    if (verified !== true) {
      const err = new Error("peer-link invite X3DH binding invalid");
      err.code = "INVITE_SIGNATURE_INVALID";
      throw err;
    }
  }

  async _expireHandshakeIfStale(record) {
    if (!record || record.state !== "handshake_sent") return record;
    const elapsed = this.clock() - Number(record.lastStateChangeAtMs || 0);
    if (elapsed < HANDSHAKE_ACK_TIMEOUT_MS) return record;
    const nowMs = this.clock();
    try {
      const updated = await this.peerLinkStorage.peerLinks.update({
        ...record,
        state: "failed",
        lastStateChangeAtMs: nowMs,
        lastErrorCode: "HANDSHAKE_ACK_TIMEOUT",
        lastErrorMessage: "Handshake timed out — connection could not be established",
      }, record.version);
      await this._appendPeerLinkEvent({
        ownerAccountId: record.localAccountId,
        peerLinkId: record.peerLinkId,
        type: "handshake_expired",
        summary: "Handshake timed out",
        details: {
          elapsedMs: elapsed,
          peerAccountId: record.peerAccountId,
        },
        atMs: nowMs,
      });
      return updated;
    } catch {
      // Version mismatch — the ack likely arrived concurrently. Re-read.
      const fresh = await this.peerLinkStorage.peerLinks.getById(record.localAccountId, record.peerLinkId);
      return fresh || record;
    }
  }

  async _buildSnapshot(peerLinkRecord) {
    if (!peerLinkRecord) {
      return null;
    }
    const owner = requireId(peerLinkRecord.localAccountId, "localAccountId");
    const session = await this.peerLinkStorage.sessions.getByPeerLinkId(owner, peerLinkRecord.peerLinkId);
    const eventPage = await this.peerLinkStorage.events.listByPeerLinkId(owner, peerLinkRecord.peerLinkId, { limit: 20 });
    // Peer-link snapshots are pure crypto/transport projections — no
    // application-layer fields (e.g. groupId) leak through. Group
    // membership is signaled by the chat-layer `member.join` op.
    return {
      peerLinkId: peerLinkRecord.peerLinkId,
      state: peerLinkRecord.state,
      localAccountId: peerLinkRecord.localAccountId,
      peerAccountId: peerLinkRecord.peerAccountId,
      sessionState: session ? nonEmpty(session.status) || "active" : "pending",
      activeInviteId: peerLinkRecord.activeInviteId,
      activeSessionId: peerLinkRecord.activeSessionId,
      peerInboxId: peerLinkRecord.peerInboxId,
      lastErrorCode: peerLinkRecord.lastErrorCode || null,
      lastErrorMessage: peerLinkRecord.lastErrorMessage || null,
      updatedAtMs: peerLinkRecord.lastStateChangeAtMs,
      events: Array.isArray(eventPage.items) ? eventPage.items : [],
    };
  }

  async encryptDirectMessage({
    ownerAccountId = this.ownerAccountId,
    peerAccountId,
    plaintextBytes,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    const remote = requireId(peerAccountId, "peerAccountId");
    if (!(plaintextBytes instanceof Uint8Array) || plaintextBytes.length === 0) {
      throw new Error("encryptDirectMessage requires non-empty plaintextBytes");
    }
    const peerLinkRecord = await this.peerLinkStorage.peerLinks.getByPair(owner, remote);
    if (!peerLinkRecord) {
      const noPeerLink = new Error("No peer link exists for this contact");
      noPeerLink.code = "THREAD_NOT_READY";
      throw noPeerLink;
    }
    const sessionRecord = await this.peerLinkStorage.sessions.getByPeerLinkId(owner, peerLinkRecord.peerLinkId);
    if (!sessionRecord || typeof sessionRecord !== "object") {
      const missingSession = new Error("Secure session is not ready yet");
      missingSession.code = "THREAD_NOT_READY";
      throw missingSession;
    }
    const canSend = isSessionUsable(sessionRecord.status);
    if (!canSend) {
      const unavailableSession = new Error("Secure session is not ready yet");
      unavailableSession.code = "THREAD_NOT_READY";
      throw unavailableSession;
    }

    const secureChannelManager = this._createSecureChannelManager(sessionRecord.ratchetSnapshot);
    const codec = new E2eePacketCodec({ secureChannelManager });
    const encryptedPacket = await codec.encryptForPeer({
      peerId: remote,
      plaintextBytes,
    });
    const sessionSnapshot = secureChannelManager.exportSnapshot();
    const storedSession = await this.peerLinkStorage.sessions.put({
      ...sessionRecord,
      localAccountId: owner,
      peerAccountId: remote,
      ratchetSnapshot: sessionSnapshot,
      updatedAtMs: this.clock(),
    });

    return {
      peerLinkId: peerLinkRecord.peerLinkId,
      sessionId: storedSession.sessionId,
      encryptedPacket,
      sessionState: storedSession.status,
    };
  }

  async decryptDirectMessage({
    ownerAccountId = this.ownerAccountId,
    peerAccountId,
    packetBytes,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    const remote = requireId(peerAccountId, "peerAccountId");
    if (!(packetBytes instanceof Uint8Array) || packetBytes.length === 0) {
      throw new Error("decryptDirectMessage requires non-empty packetBytes");
    }
    const peerLinkRecord = await this.peerLinkStorage.peerLinks.getByPair(owner, remote);
    if (!peerLinkRecord) {
      const missingPeerLink = new Error("Secure session is not ready yet");
      missingPeerLink.code = "THREAD_NOT_READY";
      throw missingPeerLink;
    }
    const sessionRecord = await this.peerLinkStorage.sessions.getByPeerLinkId(owner, peerLinkRecord.peerLinkId);
    if (!sessionRecord || typeof sessionRecord !== "object") {
      const missingSession = new Error("Secure session is not ready yet");
      missingSession.code = "THREAD_NOT_READY";
      throw missingSession;
    }
    const sessionStatus = nonEmpty(sessionRecord.status) || "pending";
    const canDecrypt = isSessionUsable(sessionStatus);
    if (!canDecrypt) {
      const unavailableSession = new Error("Secure session is not ready yet");
      unavailableSession.code = "THREAD_NOT_READY";
      throw unavailableSession;
    }

    const secureChannelManager = this._createSecureChannelManager(sessionRecord.ratchetSnapshot);
    const codec = new E2eePacketCodec({ secureChannelManager });
    const result = await codec.decryptIncoming({ packetBytes });

    // Reject plaintext packets when a secure session exists — accepting them
    // would let an attacker bypass E2EE by injecting unencrypted deposits.
    // Handshake control messages are allowed through (they are always plaintext).
    if (!result.encrypted && !result.handshake) {
      const downgradeErr = new Error("Plaintext packet rejected — secure session exists");
      downgradeErr.code = "PLAINTEXT_REJECTED";
      throw downgradeErr;
    }

    // Detect decryption failure: encrypted packet but no peerId means the ratchet
    // could not decrypt. Return still-encrypted bytes would leak garbled data to
    // the app layer. Track the failure and throw instead.
    if (result.encrypted && !result.peerId && !result.handshake) {
      const failKey = owner + ":" + remote;
      const prevCount = this.#decryptFailureCounts.get(failKey) || 0;
      this.#decryptFailureCounts.set(failKey, prevCount + 1);
      const decryptErr = new Error("E2EE decryption failed — possible ratchet desync for peer " + remote);
      decryptErr.code = "DECRYPT_FAILED";
      decryptErr.peerAccountId = remote;
      decryptErr.peerLinkId = peerLinkRecord.peerLinkId;
      decryptErr.consecutiveFailures = prevCount + 1;
      decryptErr.rehandshakeNeeded = (prevCount + 1) >= REHANDSHAKE_DECRYPT_FAILURE_THRESHOLD;
      throw decryptErr;
    }

    // Successful decrypt — reset failure/recovery counters for this peer.
    const successKey = owner + ":" + remote;
    this.#decryptFailureCounts.delete(successKey);
    this.#anyPeerMissCounts.delete(successKey);

    const nextSessionStatus = sessionStatus === "pending_remote_confirm" ? "active" : sessionStatus;
    // A first successful decrypt confirms the session (and any pending_remote_confirm
    // → active flip); route that establishment write through the single
    // #commitSession path. Steady-state decrypts (already established, no status
    // change) only persist the advanced ratchet — no peer-link write/event.
    if (peerLinkRecord.state !== "session_established" || nextSessionStatus !== sessionStatus) {
      const commit = await this.#commitSession({
        ownerAccountId: owner,
        peerLinkRecord,
        peerAccountId: remote,
        secureChannelManager,
        sessionStatus: nextSessionStatus,
        peerLinkState: PEER_LINK_STATE.SESSION_ESTABLISHED,
        existingSession: sessionRecord,
        eventType: "session_established",
        eventSummary: "Secure session confirmed",
        eventDetails: { sessionId: sessionRecord.sessionId, peerAccountId: remote },
        atMs: this.clock(),
      });
      return {
        plaintextBytes: result.plaintextBytes,
        encrypted: result.encrypted === true,
        snapshot: commit.snapshot,
        event: commit.event,
      };
    }

    const sessionSnapshot = secureChannelManager.exportSnapshot();
    await this.peerLinkStorage.sessions.put({
      ...sessionRecord,
      localAccountId: owner,
      peerAccountId: remote,
      status: nextSessionStatus,
      ratchetSnapshot: sessionSnapshot,
      updatedAtMs: this.clock(),
    });

    return {
      plaintextBytes: result.plaintextBytes,
      encrypted: result.encrypted === true,
      snapshot: await this._buildSnapshot(peerLinkRecord),
      event: null,
    };
  }

  /**
   * Decrypt an incoming E2EE packet by trying active peer sessions.
   * The protocol layer knows only the recipient inbox and opaque packet bytes.
   */
  async decryptDirectMessageAnyPeer({
    ownerAccountId = this.ownerAccountId,
    packetBytes,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    if (!(packetBytes instanceof Uint8Array) || packetBytes.length === 0) {
      throw new Error("decryptDirectMessageAnyPeer requires non-empty packetBytes");
    }
    const rows = await this.peerLinkStorage.peerLinks.listByOwner(owner);
    const trace = process.env.REZ_PEERLINK_TRACE === "1";
    const tried = [];
    // Links with a usable session that nonetheless failed to decrypt this packet
    // ("should have decrypted but didn't") — the recovery-attribution candidates.
    const candidates = [];

    for (const row of rows) {
      if (!row || !row.peerAccountId) continue;
      const sessionRecord = await this.peerLinkStorage.sessions.getByPeerLinkId(owner, row.peerLinkId);
      if (!sessionRecord || typeof sessionRecord !== "object") {
        if (trace) tried.push(row.peerAccountId + ":no-session");
        continue;
      }
      const sessionStatus = nonEmpty(sessionRecord.status) || "pending";
      const canDecrypt = isSessionUsable(sessionStatus);
      if (!canDecrypt) {
        if (trace) tried.push(row.peerAccountId + ":status=" + sessionStatus);
        continue;
      }

      const secureChannelManager = this._createSecureChannelManager(sessionRecord.ratchetSnapshot);
      const codec = new E2eePacketCodec({ secureChannelManager });
      const result = await codec.decryptIncoming({ packetBytes });

      // Wrong session — SID mismatch returns peerId null, no state mutation.
      // This link had a usable session yet did not decrypt the packet, so it is
      // a recovery candidate (see total-miss handling below).
      if (!result.encrypted || !result.peerId) {
        if (trace) tried.push(row.peerAccountId + ":no-match(enc=" + (result.encrypted ? 1 : 0) + ",pid=" + (result.peerId ? 1 : 0) + ")");
        candidates.push(row);
        continue;
      }

      // Successful trial decrypt — reset counters, persist ratchet, confirm link.
      const successKey = owner + ":" + row.peerAccountId;
      this.#decryptFailureCounts.delete(successKey);
      this.#anyPeerMissCounts.delete(successKey);
      // Mark the session healthy: it just decrypted authenticated traffic. Used
      // to refuse a destructive re-handshake armed by undecryptable noise.
      this.#anyPeerLastSuccessAt.set(successKey, this.clock());

      const nextSessionStatus = sessionStatus === "pending_remote_confirm" ? "active" : sessionStatus;
      // First successful trial decrypt confirms the session — route that
      // establishment write through the single #commitSession path. Steady-state
      // trial decrypts only persist the advanced ratchet (no peer-link write).
      if (row.state !== "session_established" || nextSessionStatus !== sessionStatus) {
        const commit = await this.#commitSession({
          ownerAccountId: owner,
          peerLinkRecord: row,
          peerAccountId: row.peerAccountId,
          secureChannelManager,
          sessionStatus: nextSessionStatus,
          peerLinkState: PEER_LINK_STATE.SESSION_ESTABLISHED,
          existingSession: sessionRecord,
          eventType: "session_established",
          eventSummary: "Secure session confirmed",
          eventDetails: { sessionId: sessionRecord.sessionId, peerAccountId: row.peerAccountId },
          atMs: this.clock(),
        });
        return {
          plaintextBytes: result.plaintextBytes,
          encrypted: result.encrypted === true,
          snapshot: commit.snapshot,
          event: commit.event,
        };
      }

      const sessionSnapshot = secureChannelManager.exportSnapshot();
      await this.peerLinkStorage.sessions.put({
        ...sessionRecord,
        localAccountId: owner,
        peerAccountId: row.peerAccountId,
        status: nextSessionStatus,
        ratchetSnapshot: sessionSnapshot,
        updatedAtMs: this.clock(),
      });

      return {
        plaintextBytes: result.plaintextBytes,
        encrypted: result.encrypted === true,
        snapshot: await this._buildSnapshot(row),
        event: null,
      };
    }

    if (trace) {
      // eslint-disable-next-line no-console
      console.log("[PLTRACE] decryptAnyPeer owner=" + owner + " NO MATCH; links tried=[" + tried.join(", ") + "] (rows=" + rows.length + ")");
    }
    // Recovery attribution. We cannot read the sender from an opaque packet, so
    // a total miss against usable sessions means one of those links may carry a
    // desynced/one-sided session. Increment a per-link miss counter and surface
    // the candidates on the error; the caller (chat-server) triggers a single
    // rehandshake only when EXACTLY ONE candidate has crossed the threshold —
    // ambiguous or zero candidates are left to retry, never guessed.
    const err = new Error("No peer link could decrypt packet");
    err.code = "THREAD_NOT_READY";
    const nowMs = this.clock();
    err.recoveryCandidates = candidates.map((row) => {
      const key = owner + ":" + row.peerAccountId;
      const misses = (this.#anyPeerMissCounts.get(key) || 0) + 1;
      this.#anyPeerMissCounts.set(key, misses);
      // Healthy-session guard (Layer 3): if this link successfully decrypted
      // authenticated traffic within the guard window, the undecryptable packets
      // are noise/replay — refuse to arm a destructive re-handshake. Protects an
      // actively-used link from a malicious relay injecting bad packets. A link
      // with no recent success (idle/genuinely dead) can still recover.
      const lastSuccessAt = this.#anyPeerLastSuccessAt.get(key) || 0;
      const sessionHealthy = lastSuccessAt > 0 && (nowMs - lastSuccessAt) < HEALTHY_SESSION_DECRYPT_GUARD_MS;
      return {
        peerAccountId: row.peerAccountId,
        peerLinkId: row.peerLinkId,
        consecutiveMisses: misses,
        rehandshakeNeeded: misses >= REHANDSHAKE_DECRYPT_FAILURE_THRESHOLD && !sessionHealthy,
      };
    });
    throw err;
  }

  async decryptDirectMessageByThreadId({
    ownerAccountId = this.ownerAccountId,
    packetBytes,
  } = {}) {
    return this.decryptDirectMessageAnyPeer({ ownerAccountId, packetBytes });
  }

  async createInvite({
    ownerAccountId = this.ownerAccountId,
    creatorDisplayName = null,
    kind = "direct",
    groupId = null,
    groupCreatedBy = null,
    groupSalt = null,
    title = null,
    maxUses = 1,
    expiresAtMs = null,
    peerInboxId = null,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    const nowMs = this.clock();
    const authority = await this._resolveAuthority(owner);
    const inviteId = stableId("plinv");
    const expires = expiresAtMs == null ? nowMs + 7 * 24 * 60 * 60 * 1000 : asPositiveInt(expiresAtMs, nowMs + 7 * 24 * 60 * 60 * 1000);
    const secureChannelManager = this._createSecureChannelManager();
    const x3dh = new X3DHKeyExchange({ secureChannelManager });
    const { keyPair: identityKeyPair, identityDhKeyPair, accountBinding } = await this._requireBoundX3dhIdentity(owner);
    const resolvedBindingTarget = nonEmpty(peerInboxId)
      || nonEmpty(this.inviteBinding && this.inviteBinding.capabilityId)
      || nonEmpty(this.inviteBinding && this.inviteBinding.mailboxId);
    // Fail loud: an invite with no reply binding is ALWAYS broken — the acceptor
    // has nowhere to route the handshake back, so acceptInvite degrades. Rather
    // than silently emit one, require the binding to resolve (from the service's
    // configured inviteBinding or an explicit peerInboxId override). This turns a
    // forgotten anchor into an immediate, attributable error at construction time.
    if (!resolvedBindingTarget) {
      const err = new Error("createInvite requires a reply binding: configure PeerLinkService inviteBinding (capabilityId/mailboxId) or pass peerInboxId");
      err.code = "INVITE_BINDING_REQUIRED";
      throw err;
    }
    const inviteBindingState = await x3dh.prepareInviteBinding({
      accountId: owner,
      identityKeyPair,
      identityDhKeyPair,
      accountBinding,
      existingBinding: {
        ...(this.inviteBinding || {}),
        ...(resolvedBindingTarget
          ? {
              mailboxId: resolvedBindingTarget,
              capabilityId: resolvedBindingTarget,
            }
          : {}),
      },
    });
    const resolvedKind = kind === "group" ? "group" : "direct";
    const resolvedGroupId = resolvedKind === "group" && typeof groupId === "string" && groupId.trim().length > 0
      ? groupId.trim() : null;
    const resolvedTitle = resolvedKind === "group" && typeof title === "string" && title.trim().length > 0
      ? title.trim() : null;
    // Mint a bearer post-cap rooted in the inviter's inbox claim, so the
    // acceptor can deposit to the inviter's mailbox. The cap is included in
    // the envelope (and thus signature-bound to the invite). Bearer cap is
    // fine here because the invite code itself is the secret carrier — anyone
    // who got the invite code already had post rights by virtue of "being
    // invited." Pubkey-blocklist on the relay revokes per-session.
    let postCapJson = null;
    if (this.inboxClaimantSigner && typeof this.inboxClaimantSigner.signPostBearerCap === "function") {
      const postCap = await this.inboxClaimantSigner.signPostBearerCap({
        actions: ["post"],
        constraints: { expiresAt: expires },
      });
      postCapJson = typeof postCap.toJSON === "function" ? postCap.toJSON() : postCap;
    }
    const envelope = {
      inviteId,
      kind: resolvedKind,
      groupId: resolvedGroupId,
      // The group's TRUE founder (group.createdBy), carried so the acceptor
      // does not have to infer it from the inviter. Without this the inviter
      // was stamped as createdBy on the acceptor's side and the founder rule
      // granted them permanent admin (audit pass 5, H2). Signed as part of the
      // envelope, so the inviter cannot silently alter it after the fact.
      groupCreatedBy: resolvedKind === "group" ? (nonEmpty(groupCreatedBy) || owner) : null,
      // Per-group salt binding groupCreatedBy to groupId (verified on accept).
      // Opaque to the SDK; the chat layer derives + checks it.
      groupSalt: resolvedKind === "group" ? nonEmpty(groupSalt) : null,
      title: resolvedTitle,
      creatorAccountId: owner,
      creatorDisplayName: nonEmpty(creatorDisplayName),
      createdAtMs: nowMs,
      expiresAtMs: expires,
      maxUses: asPositiveInt(maxUses, 1),
      binding: inviteBindingState.binding,
      postCap: postCapJson,
      signerRef: authority.signer.getSignerRef(),
    };
    const canonicalPayloadBytes = canonicalPayloadBytesV1(envelope);
    const signatureBytes = await authority.signer.sign(canonicalPayloadBytes);
    const signatureB64 = Buffer.from(signatureBytes).toString("base64");
    const tokenHash = createHash("sha256").update(canonicalPayloadBytes).digest("hex");
    await this._saveInviteRecord({
      inviteId,
      ownerAccountId: owner,
      tokenHash,
      kind: resolvedKind,
      groupId: resolvedGroupId,
      status: "active",
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
      expiresAtMs: expires,
      maxUses: asPositiveInt(maxUses, 1),
      acceptedAcceptors: [],
      peerLinkId: null,
      envelope,
      signatureB64,
    });
    await this.peerLinkStorage.keys.putInvitePreKey(owner, inviteId, inviteBindingState.preKeyState);

    // Build + sign the durable record that carries this signed envelope to
    // the DHT, so an acceptor can fetch it without the inviter online. The
    // record is signed by the SAME invite authority (so its publisher key
    // equals the envelope's signer and the v3 invite code's commitment), and
    // the node verifies it with the same Ed25519/DER-SPKI primitives. The
    // chat-server layer (which owns the transport) publishes it.
    const publisherPublicKeyB64 = authority.signer.getSignerRef().signerPublicKeyB64;
    const recordPayloadB64 = bytesToBase64(
      new TextEncoder().encode(JSON.stringify({ envelope, signatureB64 })),
    );
    const durableRecord = buildDurableRecordV1({
      recordKind: PEERLINK_INVITE_RECORD_KIND,
      recordId: inviteId,
      publisherPublicKeyB64,
      payloadB64: recordPayloadB64,
      issuedAtMs: nowMs,
      expiresAtMs: expires,
    });
    const recordSignatureBytes = await authority.signer.sign(durableRecordSignableBytes(durableRecord));
    durableRecord.sigB64 = bytesToBase64(recordSignatureBytes);

    return {
      peerLinkId: null,
      inviteId,
      state: "invite_issued",
      expiresAtMs: expires,
      maxUses: asPositiveInt(maxUses, 1),
      createdAtMs: nowMs,
      publisherPublicKeyB64,
      durableRecord,
    };
  }

  async getStoredInviteEnvelope(ownerAccountId, inviteId) {
    const owner = String(ownerAccountId || "").trim();
    const id = String(inviteId || "").trim();
    if (!owner || !id) return null;
    const record = await this._getInviteRecord(owner, id);
    if (!record || record.status !== "active") return null;
    if (!record.envelope) return null;
    return { envelope: record.envelope, signatureB64: record.signatureB64 || null };
  }

  /**
   * Authorize a group-join against the stored invite ledger — the same
   * `acceptedAcceptors`/`maxUses`/expiry rules the handshake responder enforces
   * (single source of truth). Used by the chat layer to gate a `member.join`
   * self-announce: it is the ONLY place maxUses can be checked when the joiner
   * already has an established peer-link (so no fresh handshake runs).
   *
   * Runs under the per-invite lock and consumes a slot for a first-time joiner;
   * a joiner already recorded in `acceptedAcceptors` is idempotent (no double
   * spend). Returns `{ authorized, reason }`.
   *
   * @param {{ ownerAccountId?: string, inviteId: string, joinerAccountId: string, nowMs?: number }} opts
   */
  async authorizeInviteJoin({
    ownerAccountId = this.ownerAccountId,
    inviteId,
    joinerAccountId,
    nowMs = null,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    const id = requireId(inviteId, "inviteId");
    const joiner = requireId(joinerAccountId, "joinerAccountId");
    const at = Number.isFinite(Number(nowMs)) ? Number(nowMs) : this.clock();
    return withLock(`${owner}:${id}`, async () => {
      const fresh = await this._getInviteRecord(owner, id);
      if (!fresh || fresh.status !== "active") {
        return { authorized: false, reason: "INVITE_NOT_FOUND" };
      }
      if (at >= fresh.expiresAtMs) {
        return { authorized: false, reason: "INVITE_EXPIRED" };
      }
      const accepted = Array.isArray(fresh.acceptedAcceptors) ? fresh.acceptedAcceptors : [];
      if (accepted.includes(joiner)) {
        // Already a recorded acceptor (e.g. the handshake responder counted
        // them) — idempotent, no slot consumed.
        return { authorized: true, reason: "ALREADY_ACCEPTED" };
      }
      if (accepted.length >= fresh.maxUses) {
        return { authorized: false, reason: "INVITE_USED_UP" };
      }
      await this._saveInviteRecord({
        ...fresh,
        acceptedAcceptors: [...accepted, joiner],
        updatedAtMs: at,
      });
      return { authorized: true, reason: "CONSUMED" };
    });
  }

  async acceptInvite({
    envelope: envelopeArg,
    signatureB64: signatureB64Arg,
    acceptorAccountId = this.ownerAccountId,
    acceptorDisplayName = null,
    sendHandshake = null,
    senderInboxId = null,
    forceReestablish = false,
  } = {}) {
    const acceptor = requireId(acceptorAccountId, "acceptorAccountId");
    if (!envelopeArg || typeof envelopeArg !== "object") {
      const err = new Error("acceptInvite requires envelope object");
      err.code = "INVITE_INVALID_FORMAT";
      throw err;
    }
    if (!signatureB64Arg || typeof signatureB64Arg !== "string") {
      const err = new Error("acceptInvite requires signatureB64 string");
      err.code = "INVITE_INVALID_FORMAT";
      throw err;
    }
    const envelope = envelopeArg;
    const signatureBytes = new Uint8Array(Buffer.from(signatureB64Arg, "base64"));
    const canonicalPayloadBytes = canonicalPayloadBytesV1(envelope);
    verifyInviteKind(envelope);
    const inviterAccountId = requireId(envelope.creatorAccountId, "creatorAccountId");
    const nowMs = this.clock();
    const authority = await this._resolveAuthority(inviterAccountId);
    const verified = await authority.verifier.verify({
      signerRef: envelope.signerRef,
      bytes: canonicalPayloadBytes,
      sigBytes: signatureBytes,
    });
    if (verified !== true) {
      const err = new Error("peer-link invite signature invalid");
      err.code = "INVITE_SIGNATURE_INVALID";
      throw err;
    }
    if (nowMs >= asPositiveInt(envelope.expiresAtMs, nowMs)) {
      const err = new Error("peer-link invite expired");
      err.code = "INVITE_EXPIRED";
      throw err;
    }

    const existing = await this.peerLinkStorage.peerLinks.getByPair(acceptor, inviterAccountId);
    // A peer-link in a terminal dead state (the inviter rejected the handshake,
    // or a prior handshake send failed) carries no usable session. The store
    // has no delete — state transitions are the idiom — so a fresh invite from
    // the same inviter must re-drive the handshake by reusing this record
    // rather than short-circuiting as idempotent. Live or establishing links
    // (accept_committed / handshake_sent / handshake_received /
    // session_established / degraded) normally stay idempotent.
    //
    // `forceReestablish` (used by automated link RECOVERY — re-inviting a known
    // contact whose ratchet desynced) opts an established link into the reattempt
    // path so a fresh X3DH session replaces the broken one. It re-keys the SAME
    // peerLinkId and overwrites the SAME session row (see existingSessionForCommit
    // below) — history is untouched (messages persist independently of the
    // ratchet). Only `invite_issued` (a not-yet-accepted link) is excluded.
    const reattempt = Boolean(existing) && (
      existing.state === "rejected"
      || existing.state === "failed"
      || (forceReestablish === true && existing.state !== "invite_issued")
    );
    if (existing && !reattempt) {
      // Peer-link records are pure cryptographic channels; they carry no
      // group context. Group membership is signaled by the chat-layer
      // `member.join` op authorized against the invite envelope's
      // signed groupId — the SDK does not need to know about groups.
      const eventRecord = await this._appendPeerLinkEvent({
        ownerAccountId: acceptor,
        peerLinkId: existing.peerLinkId,
        type: "invite_accept_idempotent",
        summary: "Peer link already exists",
        details: {
          inviteId: envelope.inviteId,
          acceptorAccountId: acceptor,
        },
        atMs: nowMs,
      });
      return {
        snapshot: await this._buildSnapshot(existing),
        event: eventRecord,
      };
    }

    // maxUses is enforced lazily on the inviter side, in
    // `handleIncomingHandshakePacket` (the single enforcement point — it runs
    // whenever the inviter is online and the acceptor is cryptographically
    // authenticated). Accept is optimistic here: we resolve the local invite
    // record only to back-link `peerLinkId` onto it (same-node case), never to
    // spend it.
    const tokenHashHex = createHash("sha256").update(canonicalPayloadBytes).digest("hex");
    const localInviteIdForLink = await this._getInviteRecordByHash(inviterAccountId, tokenHashHex);

    // Reuse the existing peer-link id when re-driving a terminal dead link so
    // the pair stays a single record (getByPair is per-pair); a first accept
    // mints a new id.
    const peerLinkId = reattempt ? existing.peerLinkId : stableId("pl");
    // Persist the inviter-signed post-cap so subsequent deposits to this peer
    // attach it. Bearer cap; pubkey blocklist gates per-session-pubkey.
    const inviterPostCapJson = envelope.postCap && typeof envelope.postCap === "object" ? envelope.postCap : null;

    // Persist the inviter's X3DH identity signing pubkey on the peer-link.
    // It was verified by `_verifyInviteX3dhBinding` above as bound to the
    // inviter's account identity key, so it's the right thing to verify the
    // handshake-ack signature against later (MED-1). See
    // docs/SECURITY_AUDIT.md MED-1.
    const inviterIdentitySigningPubKeyB64 = nonEmpty(
      envelope.binding && envelope.binding.x3dh ? envelope.binding.x3dh.identitySigningPublicKeyB64 : null,
    );
    if (!inviterIdentitySigningPubKeyB64) {
      const err = new Error("invite envelope missing x3dh.identitySigningPublicKeyB64");
      err.code = "INVITE_SIGNATURE_INVALID";
      throw err;
    }
    const peerInboxIdForLink = envelope.binding && typeof envelope.binding === "object" ? nonEmpty(envelope.binding.capabilityId) : null;
    let peerLinkRecord;
    if (reattempt) {
      // Transition the terminal dead link back into an active accept. A prior
      // reject already deleted its session + post-cap, and its handshake
      // attempts were marked terminal, so there is nothing stale to carry over
      // beyond the row identity itself. Clear the error fields and re-bind the
      // new invite.
      peerLinkRecord = await this.peerLinkStorage.peerLinks.update({
        ...existing,
        remoteIdentitySigningPublicKeyB64: inviterIdentitySigningPubKeyB64,
        state: "accept_committed",
        activeInviteId: requireId(envelope.inviteId, "inviteId"),
        activeSessionId: null,
        peerInboxId: peerInboxIdForLink,
        lastStateChangeAtMs: nowMs,
        lastErrorCode: null,
        lastErrorMessage: null,
      }, existing.version);
    } else {
      peerLinkRecord = await this.peerLinkStorage.peerLinks.create({
        peerLinkId,
        localAccountId: acceptor,
        peerAccountId: inviterAccountId,
        remoteIdentitySigningPublicKeyB64: inviterIdentitySigningPubKeyB64,
        state: "accept_committed",
        activeInviteId: requireId(envelope.inviteId, "inviteId"),
        activeSessionId: null,
        peerInboxId: peerInboxIdForLink,
        lastStateChangeAtMs: nowMs,
        lastErrorCode: null,
        lastErrorMessage: null,
        version: 1,
      });
    }
    if (inviterPostCapJson) {
      await this.kv.set(_postCapKey(acceptor, peerLinkId), inviterPostCapJson);
    }
    let handshakeAttempt = await this.peerLinkStorage.handshakeAttempts.create({
      handshakeAttemptId: stableId("hs"),
      peerLinkId,
      ownerAccountId: acceptor,
      direction: "initiator",
      status: "pending",
      inviteId: requireId(envelope.inviteId, "inviteId"),
      sessionId: null,
      packetMessageId: null,
      lastTriedAtMs: nowMs,
      retryCount: 0,
      lastErrorCode: null,
      lastErrorMessage: null,
      version: 1,
    });
    // Re-read the invite record before back-linking peerLinkId: the handshake
    // responder may have updated it concurrently (same-node case), so the
    // in-memory copy from before this method may be stale. Re-reading honours
    // the "persist first, never patch in-memory snapshots" rule.
    if (localInviteIdForLink) {
      const fresh = await this._getInviteRecord(
        localInviteIdForLink.ownerAccountId,
        localInviteIdForLink.inviteId,
      );
      if (fresh) {
        await this._saveInviteRecord({
          ...fresh,
          peerLinkId,
          updatedAtMs: nowMs,
        });
      }
    }
    await this._appendPeerLinkEvent({
      ownerAccountId: acceptor,
      peerLinkId,
      type: "invite_accepted",
      summary: "Peer link acceptance committed",
      details: {
        inviteId: envelope.inviteId,
        acceptorAccountId: acceptor,
        acceptorDisplayName: nonEmpty(acceptorDisplayName),
        handshakeAttemptId: handshakeAttempt.handshakeAttemptId,
      },
      atMs: nowMs,
    });
    const secureChannelManager = this._createSecureChannelManager();
    const x3dh = new X3DHKeyExchange({ secureChannelManager });
    await this._verifyInviteX3dhBinding({
      ownerAccountId: inviterAccountId,
      inviteBinding: envelope.binding,
    });
    const {
      keyPair: acceptorIdentityKeyPair,
      identityDhKeyPair: acceptorIdentityDhKeyPair,
      identityDhSignature: acceptorIdentityDhSignature,
    } = await this._requireBoundX3dhIdentity(acceptor);
    const acceptedInvite = await x3dh.processAcceptedInvite({
      inviteBinding: envelope.binding,
      peerId: inviterAccountId,
      initiatorIdentityKeyPair: acceptorIdentityKeyPair,
      initiatorIdentityDhKeyPair: acceptorIdentityDhKeyPair,
      initiatorIdentityDhSignature: acceptorIdentityDhSignature,
    });
    // Persist the unilaterally-derived initiator session (pending the inviter's
    // confirm) through the single #commitSession path. The peer-link stays in
    // accept_committed here (a self-transition); the send branches below drive
    // it to handshake_sent / degraded / session_established.
    //
    // On a reattempt that re-establishes an EXISTING session (forceReestablish
    // recovery of a live link), reuse the current session row so the fresh
    // ratchet OVERWRITES it in place rather than leaving the old row orphaned in
    // the store. For rejected/failed reattempts the session was already removed,
    // so getByPeerLinkId returns null and a new row is minted as before.
    const existingSessionForCommit = reattempt
      ? await this.peerLinkStorage.sessions.getByPeerLinkId(acceptor, peerLinkId)
      : null;
    const commit = await this.#commitSession({
      ownerAccountId: acceptor,
      peerLinkRecord,
      peerAccountId: inviterAccountId,
      secureChannelManager,
      sessionStatus: SESSION_STATUS.PENDING_REMOTE_CONFIRM,
      peerLinkState: PEER_LINK_STATE.ACCEPT_COMMITTED,
      existingSession: existingSessionForCommit,
      resetSessionCreatedAt: reattempt,
      eventType: "handshake_pending",
      eventSummary: "Handshake state created",
      eventDetails: { inviteId: envelope.inviteId },
      atMs: nowMs,
    });
    peerLinkRecord = commit.peerLinkRecord;
    const sessionRecord = commit.sessionRecord;
    let eventRecord = commit.event;
    if (typeof sendHandshake === "function") {
      // Include the acceptor's account binding so the inviter can verify
      // that senderAccountId actually controls the X3DH identity key used
      // in the handshake. Without this, a malicious client could claim any
      // senderAccountId while performing a valid X3DH exchange.
      const acceptorKeyRecord = await this._loadAccountKeyRecord(acceptor);
      const acceptorBinding = acceptorKeyRecord.accountBinding;
      if (!acceptorBinding || typeof acceptorBinding !== "object") {
        const err = new Error("Acceptor account binding is required for handshake authentication");
        err.code = "REAUTH_REQUIRED";
        throw err;
      }
      // Generate a random nonce to bind the ack to this specific handshake.
      // The inviter must echo this nonce in the ack; the acceptor verifies it.
      const ackNonce = randomUUID();
      const handshakeData = {
        ...acceptedInvite.handshakeData,
        inviteId: requireId(envelope.inviteId, "inviteId"),
        senderDisplayName: typeof acceptorDisplayName === "string" ? acceptorDisplayName : "",
        senderInboxId: nonEmpty(senderInboxId) || nonEmpty(this.inviteBinding && this.inviteBinding.capabilityId ? this.inviteBinding.capabilityId : null) || null,
        senderAccountBinding: cloneJson(acceptorBinding),
        ackNonce,
        createdAtMs: nowMs,
      };
      const handshakeSignatureB64 = await signHandshakeEnvelope({
        handshake: handshakeData,
        crypto: this.cryptoProvider,
        signingPrivateKey: acceptorIdentityKeyPair.privateKey,
      });
      const handshakePacket = E2eePacketCodec.createHandshakePacket({
        handshakeData,
        signatureB64: handshakeSignatureB64,
      });
      // Store the nonce so handleIncomingHandshakeAck can verify it
      const nonceKey = "peer-link:ack-nonce:" + acceptor + ":" + peerLinkId;
      await this.kv.set(nonceKey, ackNonce);
      try {
        const sendResult = await sendHandshake({
          deliverInboxId: requireId(peerLinkRecord.peerInboxId, "deliverInboxId"),
          handshakePacket,
          peerAccountId: inviterAccountId,
        });
        // Re-read after async sendHandshake — the ack may have arrived during
        // the send and already advanced the record to session_established.
        const freshAfterSend = await this.peerLinkStorage.peerLinks.getById(acceptor, peerLinkId);
        if (freshAfterSend && freshAfterSend.state === "session_established") {
          peerLinkRecord = freshAfterSend;
        } else {
          handshakeAttempt = await this.peerLinkStorage.handshakeAttempts.update({
            ...handshakeAttempt,
            status: "sent",
            packetMessageId: sendResult && sendResult.packetId ? String(sendResult.packetId) : null,
            sessionId: sessionRecord.sessionId,
            lastTriedAtMs: nowMs,
            lastErrorCode: null,
            lastErrorMessage: null,
          }, handshakeAttempt.version);
          const currentForUpdate = freshAfterSend || peerLinkRecord;
          this.#checkPeerLinkTransition(currentForUpdate.state, PEER_LINK_STATE.HANDSHAKE_SENT, currentForUpdate.peerLinkId);
          peerLinkRecord = await this.peerLinkStorage.peerLinks.update({
            ...currentForUpdate,
            state: PEER_LINK_STATE.HANDSHAKE_SENT,
            lastStateChangeAtMs: nowMs,
            lastErrorCode: null,
            lastErrorMessage: null,
          }, currentForUpdate.version);
          eventRecord = await this._appendPeerLinkEvent({
            ownerAccountId: acceptor,
            peerLinkId,
            type: "handshake_sent",
            summary: "Handshake sent",
            details: {
              handshakeAttemptId: handshakeAttempt.handshakeAttemptId,
              sessionId: sessionRecord.sessionId,
              deliverInboxId: peerLinkRecord.peerInboxId,
            },
            atMs: nowMs,
          });
        }
      } catch (err) {
        // Re-read before marking degraded — the ack may have arrived and
        // already advanced the record past the state we're trying to set.
        const freshAfterErr = await this.peerLinkStorage.peerLinks.getById(acceptor, peerLinkId);
        if (freshAfterErr && freshAfterErr.state === "session_established") {
          peerLinkRecord = freshAfterErr;
        } else {
          const errorCode = nonEmpty(err && err.code) || "HANDSHAKE_SEND_FAILED";
          const errorMessage = nonEmpty(err && err.message) || "handshake send failed";
          const currentForErr = freshAfterErr || peerLinkRecord;
          try {
            handshakeAttempt = await this.peerLinkStorage.handshakeAttempts.update({
              ...handshakeAttempt,
              status: "failed",
              sessionId: sessionRecord.sessionId,
              lastTriedAtMs: nowMs,
              retryCount: Number(handshakeAttempt.retryCount || 0) + 1,
              lastErrorCode: errorCode,
              lastErrorMessage: errorMessage,
            }, handshakeAttempt.version);
          } catch (attemptUpdateErr) {
            // Attempt-record update is best-effort (it may also hit a version
            // conflict), but we never swallow silently: surface it so a broken
            // diagnostic trail is visible while still degrading the peer link.
            console.warn(
              "[PeerLinkService] handshake-attempt failure update conflicted for "
                + peerLinkId + ": "
                + (attemptUpdateErr && attemptUpdateErr.message
                  ? attemptUpdateErr.message
                  : String(attemptUpdateErr))
            );
          }
          this.#checkPeerLinkTransition(currentForErr.state, PEER_LINK_STATE.DEGRADED, currentForErr.peerLinkId);
          peerLinkRecord = await this.peerLinkStorage.peerLinks.update({
            ...currentForErr,
            state: PEER_LINK_STATE.DEGRADED,
            lastStateChangeAtMs: nowMs,
            lastErrorCode: errorCode,
            lastErrorMessage: errorMessage,
          }, currentForErr.version);
          eventRecord = await this._appendPeerLinkEvent({
            ownerAccountId: acceptor,
            peerLinkId,
            type: "handshake_failed",
            summary: "Handshake send failed",
            details: {
              handshakeAttemptId: handshakeAttempt.handshakeAttemptId,
              errorCode,
              errorMessage,
            },
            atMs: nowMs,
          });
        }
      }
    }
    const snapshot = await this._buildSnapshot(peerLinkRecord);
    return {
      snapshot,
      event: eventRecord,
    };
  }

  async getPeerLink({
    ownerAccountId = this.ownerAccountId,
    peerLinkId,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    const id = requireId(peerLinkId, "peerLinkId");
    let record = await this.peerLinkStorage.peerLinks.getById(owner, id);
    if (!record) {
      return null;
    }
    record = await this._expireHandshakeIfStale(record);
    return this._buildSnapshot(record);
  }

  async handleIncomingHandshakePacket({
    ownerAccountId = this.ownerAccountId,
    packetBytes,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    if (!(packetBytes instanceof Uint8Array) || packetBytes.length === 0) {
      throw new Error("packetBytes must be a non-empty Uint8Array");
    }
    const packetText = new TextDecoder().decode(packetBytes);
    const packet = JSON.parse(packetText);
    if (!packet || typeof packet !== "object" || Array.isArray(packet)
      || Object.hasOwn(packet, "__proto__") || Object.hasOwn(packet, "constructor") || Object.hasOwn(packet, "prototype")) {
      return null;
    }
    if (packet.e2ee !== 1 || packet.type !== "x3dh.handshake.v2" || !packet.handshake || typeof packet.handshake !== "object") {
      return null;
    }
    if (typeof packet.signatureB64 !== "string" || packet.signatureB64.length === 0) {
      const err = new Error("Handshake packet missing signatureB64");
      err.code = "HANDSHAKE_SIGNATURE_INVALID";
      throw err;
    }
    const handshakeData = cloneJson(packet.handshake);
    // Verify the envelope signature BEFORE doing anything else with the
    // handshake contents. This is the cryptographic proof that the handshake
    // was authored by the holder of senderIdentitySigningPubKeyB64.
    const envelopeVerified = await verifyHandshakeEnvelope({
      handshake: handshakeData,
      signatureB64: packet.signatureB64,
      crypto: this.cryptoProvider,
    });
    if (!envelopeVerified) {
      const err = new Error("Handshake envelope signature did not verify");
      err.code = "HANDSHAKE_SIGNATURE_INVALID";
      throw err;
    }
    const inviteId = requireId(handshakeData.inviteId, "inviteId");
    const remoteDisplayName = typeof handshakeData.senderDisplayName === "string" ? handshakeData.senderDisplayName : "";
    const remoteInboxId = nonEmpty(handshakeData.senderInboxId) || null;

    // Verify the acceptor's account binding. The envelope signature proved
    // possession of the X3DH identity signing key; the binding chains that
    // key back to the accountIdentityPublicKey, which derives the accountId.
    // Sender no longer transmits senderAccountId in plaintext.
    const senderBinding = handshakeData.senderAccountBinding;
    if (!senderBinding || typeof senderBinding !== "object") {
      const err = new Error("Handshake missing senderAccountBinding — cannot authenticate acceptor identity");
      err.code = "HANDSHAKE_AUTH_FAILED";
      throw err;
    }
    // The binding's x3dhIdentityPublicKeyB64 MUST equal the handshake's
    // senderIdentitySigningPubKeyB64 — the envelope-signed key and the
    // account-bound key must be the same key, or the chain is broken.
    if (nonEmpty(senderBinding.x3dhIdentityPublicKeyB64) !== nonEmpty(handshakeData.senderIdentitySigningPubKeyB64)) {
      const err = new Error("Handshake account binding does not cover the X3DH identity that signed the envelope");
      err.code = "HANDSHAKE_AUTH_FAILED";
      throw err;
    }
    const peerAccountId = deriveAccountIdFromPublicKey(base64ToBytes(nonEmpty(senderBinding.accountIdentityPublicKeyB64)));
    await this._verifyInviteX3dhBinding({
      ownerAccountId: peerAccountId,
      inviteBinding: {
        x3dh: {
          accountIdentityPublicKeyB64: nonEmpty(senderBinding.accountIdentityPublicKeyB64),
          accountBindingSigB64: nonEmpty(senderBinding.accountBindingSigB64),
          identitySigningPublicKeyB64: nonEmpty(senderBinding.x3dhIdentityPublicKeyB64),
          accountBindingExpiresAtMs: Number(senderBinding.expiresAtMs),
          accountBindingIssuedAtMs: Number(senderBinding.issuedAtMs),
        },
      },
    });

    // Look up the invite (for the inviter's display name + lazy maxUses).
    const inviteRecord = await this._getInviteRecord(owner, inviteId);
    const localDisplayName = inviteRecord
      && inviteRecord.envelope
      && typeof inviteRecord.envelope.creatorDisplayName === "string"
      ? inviteRecord.envelope.creatorDisplayName
      : "";

    // Lazy maxUses enforcement — the single enforcement point. The inviter is
    // by definition online here, which is exactly where distinct acceptors
    // become observable. Count distinct, cryptographically-authenticated
    // `peerAccountId`s under the invite lock: a re-delivered handshake from an
    // acceptor already accounted for is idempotent (proceeds, re-establishes),
    // and two different acceptors racing a single-use invite are serialized
    // (first wins, second rejected). `acceptedAcceptors` persists on the
    // invite record, so the count survives inviter restart.
    //
    // This runs BEFORE the pre-key gate so an over-limit acceptor gets a clean
    // signed reject even after the shared invite pre-key was cleared by the
    // exhausting acceptor. `inviteExhausted` drives pre-key retention below:
    // the shared pre-key must survive every distinct acceptor for maxUses>1, so
    // it is only deleted once the last slot is filled. If we hold no invite
    // record we cannot enforce, so we proceed and fall back to the old
    // delete-on-first-handshake behaviour.
    let inviteExhausted = !inviteRecord;
    if (inviteRecord) {
      const verdict = await withLock(`${owner}:${inviteId}`, async () => {
        const fresh = await this._getInviteRecord(owner, inviteId);
        if (!fresh) return { action: "proceed", exhausted: true };
        const at = this.clock();
        if (at >= fresh.expiresAtMs) return { action: "reject", reason: "INVITE_EXPIRED" };
        const accepted = Array.isArray(fresh.acceptedAcceptors) ? fresh.acceptedAcceptors : [];
        if (accepted.includes(peerAccountId)) {
          return { action: "proceed", exhausted: accepted.length >= fresh.maxUses };
        }
        if (accepted.length >= fresh.maxUses) return { action: "reject", reason: "INVITE_USED_UP" };
        const nextAccepted = [...accepted, peerAccountId];
        await this._saveInviteRecord({
          ...fresh,
          acceptedAcceptors: nextAccepted,
          updatedAtMs: at,
        });
        return { action: "proceed", exhausted: nextAccepted.length >= fresh.maxUses };
      });
      if (verdict.action === "reject") {
        return {
          rejected: true,
          reason: verdict.reason,
          ackNonce: nonEmpty(handshakeData.ackNonce) || null,
          acceptorInboxId: remoteInboxId,
          peerAccountId,
        };
      }
      inviteExhausted = Boolean(verdict.exhausted);
    }

    const preKeyState = await this.peerLinkStorage.keys.getInvitePreKey(owner, inviteId);
    if (!preKeyState || typeof preKeyState !== "object") {
      const missingPreKey = new Error("peer-link invite pre-key not found");
      missingPreKey.code = "PEER_LINK_PREKEY_MISSING";
      throw missingPreKey;
    }

    const nowMs = this.clock();
    const existing = await this.peerLinkStorage.peerLinks.getByPair(owner, peerAccountId);
    let peerLinkRecord = existing;
    if (!peerLinkRecord) {
      peerLinkRecord = await this.peerLinkStorage.peerLinks.create({
        peerLinkId: stableId("pl"),
        localAccountId: owner,
        peerAccountId,
        state: "handshake_received",
        activeInviteId: inviteId,
        activeSessionId: null,
        peerInboxId: remoteInboxId,
        lastStateChangeAtMs: nowMs,
        lastErrorCode: null,
        lastErrorMessage: null,
        version: 1,
      });
    }
    const { secureChannelManager } = await this.#establishAsResponder({
      ownerAccountId: owner,
      preKeyState,
      handshakeData,
      peerId: peerAccountId,
    });
    const existingSession = await this.peerLinkStorage.sessions.getByPeerLinkId(owner, peerLinkRecord.peerLinkId);
    const commit = await this.#commitSession({
      ownerAccountId: owner,
      peerLinkRecord,
      peerAccountId,
      secureChannelManager,
      sessionStatus: SESSION_STATUS.ACTIVE,
      peerLinkState: PEER_LINK_STATE.SESSION_ESTABLISHED,
      existingSession,
      // Write-once routing: keep an already-recorded peer inbox rather than
      // letting a handshake-declared senderInboxId overwrite it (the ack path
      // applies the same no-hijack guard). A genuine inbox change is delivered
      // through the explicit rehandshake flow, not a stray handshake packet.
      // For a freshly-created link peerInboxId already equals remoteInboxId.
      peerInboxId: nonEmpty(peerLinkRecord.peerInboxId) || remoteInboxId,
      eventType: "handshake_received",
      eventSummary: "Handshake received and session established",
      eventDetails: { inviteId },
      atMs: nowMs,
    });
    peerLinkRecord = commit.peerLinkRecord;
    const sessionRecord = commit.sessionRecord;
    await this.peerLinkStorage.handshakeAttempts.create({
      handshakeAttemptId: stableId("hs"),
      peerLinkId: peerLinkRecord.peerLinkId,
      ownerAccountId: owner,
      direction: "responder",
      status: "completed",
      inviteId,
      sessionId: sessionRecord.sessionId,
      packetMessageId: null,
      lastTriedAtMs: nowMs,
      retryCount: 0,
      lastErrorCode: null,
      lastErrorMessage: null,
      version: 1,
    });
    // Only clear the shared invite pre-key once the invite is exhausted, so
    // every distinct acceptor of a maxUses>1 invite can still complete X3DH.
    if (inviteExhausted) {
      await this.peerLinkStorage.keys.deleteInvitePreKey(owner, inviteId);
    }
    return {
      snapshot: commit.snapshot,
      event: commit.event,
      ackNonce: nonEmpty(handshakeData.ackNonce) || null,
      remoteDisplayName,
      localDisplayName,
    };
  }

  /**
   * Build a signed handshake-ack envelope. Called by the inviter side after
   * `handleIncomingHandshakePacket` resolves; the returned bytes are deposited
   * unchanged to the acceptor's inbox. Signed with the inviter's X3DH
   * identity signing private key so the acceptor can verify the ack against
   * the inviter's `remoteIdentitySigningPublicKeyB64` it persisted at
   * `acceptInvite` time. Closes MED-1.
   *
   * @param {{ ownerAccountId?: string, ownerInboxId: string|null, ownerDisplayName: string, ackNonce: string }} opts
   * @returns {Promise<{ ackBytes: Uint8Array }>}
   */
  async createSignedHandshakeAck({
    ownerAccountId = this.ownerAccountId,
    ownerInboxId = null,
    ownerDisplayName = "",
    ackNonce,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    if (typeof ackNonce !== "string" || ackNonce.length === 0) {
      throw new Error("createSignedHandshakeAck requires ackNonce string");
    }
    const { keyPair: identityKeyPair } = await this._requireBoundX3dhIdentity(owner);
    const senderIdentitySigningPubKeyB64 = bytesToBase64(identityKeyPair.publicKey);
    const ackPayload = {
      senderIdentitySigningPubKeyB64,
      senderAccountId: owner,
      senderInboxId: typeof ownerInboxId === "string" && ownerInboxId.length > 0 ? ownerInboxId : null,
      senderDisplayName: typeof ownerDisplayName === "string" ? ownerDisplayName : "",
      ackNonce,
      createdAtMs: this.clock(),
    };
    const signatureB64 = await signHandshakeEnvelope({
      handshake: ackPayload,
      crypto: this.cryptoProvider,
      signingPrivateKey: identityKeyPair.privateKey,
    });
    const ack = new E2eeHandshakeAckV1({ ...ackPayload, signatureB64 });
    return { ackBytes: ack.toBytes() };
  }

  /**
   * Handle an incoming handshake acknowledgement from the inviter. Verifies
   * the ack signature against the persisted `remoteIdentitySigningPublicKeyB64`
   * on the peer-link record, then transitions
   * "handshake_sent" → "session_established".
   *
   * @param {{ ownerAccountId?: string, ackPacketBytes: Uint8Array }} opts
   */
  async handleIncomingHandshakeAck({
    ownerAccountId = this.ownerAccountId,
    ackPacketBytes,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    if (!(ackPacketBytes instanceof Uint8Array) || ackPacketBytes.length === 0) {
      return null;
    }
    let ack;
    try {
      ack = E2eeHandshakeAckV1.fromBytes(ackPacketBytes);
    } catch {
      return null;
    }
    const remote = ack.senderAccountId;
    const peerLinkRecord = await this.peerLinkStorage.peerLinks.getByPair(owner, remote);
    if (!peerLinkRecord) {
      return null;
    }
    // Only accept ack if we're waiting for confirmation
    if (peerLinkRecord.state !== "handshake_sent" && peerLinkRecord.state !== "accept_committed") {
      return null;
    }
    // The peer-link MUST already carry the inviter's X3DH identity signing
    // pubkey (persisted at acceptInvite time). The ack's embedded pubkey
    // must match it exactly — that's the binding from "this is the ack
    // for this peer-link" to "this is who signed the ack".
    const expectedPubKeyB64 = nonEmpty(peerLinkRecord.remoteIdentitySigningPublicKeyB64);
    if (!expectedPubKeyB64 || expectedPubKeyB64 !== ack.senderIdentitySigningPubKeyB64) {
      return null;
    }
    // Verify the ack envelope signature using the embedded pubkey (which we
    // just confirmed matches the trusted-on-record pubkey).
    const sigOk = await verifyHandshakeEnvelope({
      handshake: ack.toAckPayload(),
      signatureB64: ack.signatureB64,
      crypto: this.cryptoProvider,
    });
    if (!sigOk) {
      return null;
    }

    // Verify the ack nonce matches the one we sent in the handshake.
    // This proves the ack came from whoever received our handshake packet —
    // and now we know that "whoever" is the legitimate inviter.
    const nonceKey = "peer-link:ack-nonce:" + owner + ":" + peerLinkRecord.peerLinkId;
    const storedNonce = await this.kv.get(nonceKey);
    if (storedNonce) {
      if (String(ack.ackNonce) !== String(storedNonce)) {
        return null;
      }
      // Clean up the nonce after successful verification
      await this.kv.delete(nonceKey);
    }
    const remoteDisplayName = typeof ack.senderDisplayName === "string" ? ack.senderDisplayName : "";

    const nowMs = this.clock();

    // Confirm the session: flip pending_remote_confirm → active and advance the
    // peer link to session_established through the single #commitSession path
    // (no ratchet derivation — only the status flip). peerInboxId is never taken
    // from the ack (routing-hijack guard). A peerLinks version mismatch means a
    // duplicate ack arrived via multiple relays, or acceptInvite already
    // advanced the record — re-read and treat an established link as success.
    const existingSession = await this.peerLinkStorage.sessions.getByPeerLinkId(owner, peerLinkRecord.peerLinkId);
    let commit;
    try {
      commit = await this.#commitSession({
        ownerAccountId: owner,
        peerLinkRecord,
        peerAccountId: remote,
        sessionStatus: SESSION_STATUS.ACTIVE,
        peerLinkState: PEER_LINK_STATE.SESSION_ESTABLISHED,
        existingSession,
        peerInboxId: peerLinkRecord.peerInboxId,
        eventType: "handshake_ack_received",
        eventSummary: "Handshake acknowledged — session established",
        atMs: nowMs,
      });
    } catch (err) {
      const fresh = await this.peerLinkStorage.peerLinks.getByPair(owner, remote);
      if (fresh && fresh.state === "session_established") {
        return { snapshot: await this._buildSnapshot(fresh), event: null };
      }
      // Genuinely unexpected — surface as a version conflict.
      throw new Error(`Peer link version conflict for ${peerLinkRecord.peerLinkId}`);
    }

    return {
      snapshot: commit.snapshot,
      event: commit.event,
      remoteDisplayName: typeof remoteDisplayName === "string" ? remoteDisplayName : "",
    };
  }

  /**
   * Build a signed handshake-reject envelope (inviter → acceptor). Mirrors
   * `createSignedHandshakeAck`: signed with the inviter's X3DH identity signing
   * private key so the acceptor authenticates it against the
   * `remoteIdentitySigningPublicKeyB64` it persisted at accept time, and bound
   * to the acceptor's `ackNonce` so a stale reject can't tear down a later
   * attempt. Sent when the handshake responder declines (invite used up /
   * expired) so the acceptor can roll back its optimistic peer-link.
   *
   * @param {{ ownerAccountId?: string, reason: string, ackNonce: string }} opts
   * @returns {Promise<{ rejectBytes: Uint8Array }>}
   */
  async createSignedHandshakeReject({
    ownerAccountId = this.ownerAccountId,
    reason,
    ackNonce,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    if (typeof reason !== "string" || reason.length === 0) {
      throw new Error("createSignedHandshakeReject requires reason string");
    }
    if (typeof ackNonce !== "string" || ackNonce.length === 0) {
      throw new Error("createSignedHandshakeReject requires ackNonce string");
    }
    const { keyPair: identityKeyPair } = await this._requireBoundX3dhIdentity(owner);
    const rejectPayload = {
      senderIdentitySigningPubKeyB64: bytesToBase64(identityKeyPair.publicKey),
      senderAccountId: owner,
      reason,
      ackNonce,
      createdAtMs: this.clock(),
    };
    const signatureB64 = await signHandshakeEnvelope({
      handshake: rejectPayload,
      crypto: this.cryptoProvider,
      signingPrivateKey: identityKeyPair.privateKey,
    });
    const reject = new E2eeHandshakeRejectV1({ ...rejectPayload, signatureB64 });
    return { rejectBytes: reject.toBytes() };
  }

  /**
   * Handle an authenticated handshake-reject from the inviter (acceptor side).
   * Rolls back the optimistic peer-link created at `acceptInvite`: tears down
   * the pending session + post-cap, marks the handshake attempt and peer-link
   * "rejected", and returns a snapshot so the chat layer can drop the
   * optimistic thread/contact. No-op if the link already reached
   * "session_established" (an ack beat the reject) — an established session is
   * never torn down by a reject.
   *
   * Authentication mirrors `handleIncomingHandshakeAck` (pubkey-on-record +
   * envelope signature + nonce), so a relay cannot forge a reject.
   *
   * @param {{ ownerAccountId?: string, rejectPacketBytes: Uint8Array }} opts
   */
  async handleHandshakeReject({
    ownerAccountId = this.ownerAccountId,
    rejectPacketBytes,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    if (!(rejectPacketBytes instanceof Uint8Array) || rejectPacketBytes.length === 0) {
      return null;
    }
    let reject;
    try {
      reject = E2eeHandshakeRejectV1.fromBytes(rejectPacketBytes);
    } catch {
      return null;
    }
    const remote = reject.senderAccountId;
    const peerLinkRecord = await this.peerLinkStorage.peerLinks.getByPair(owner, remote);
    if (!peerLinkRecord) {
      return null;
    }
    // Only roll back a link still awaiting confirmation. If a session was
    // already established (ack won the race), the reject is stale — ignore it.
    if (peerLinkRecord.state !== "accept_committed" && peerLinkRecord.state !== "handshake_sent") {
      return null;
    }
    // Authenticate: the reject's signing pubkey must match the one we trusted
    // on-record at accept time, and the envelope signature must verify.
    const expectedPubKeyB64 = nonEmpty(peerLinkRecord.remoteIdentitySigningPublicKeyB64);
    if (!expectedPubKeyB64 || expectedPubKeyB64 !== reject.senderIdentitySigningPubKeyB64) {
      return null;
    }
    const sigOk = await verifyHandshakeEnvelope({
      handshake: reject.toRejectPayload(),
      signatureB64: reject.signatureB64,
      crypto: this.cryptoProvider,
    });
    if (!sigOk) {
      return null;
    }
    // Bind to the acceptor's stored nonce so a replayed/stale reject from an
    // earlier attempt cannot tear down a fresh one.
    const nonceKey = "peer-link:ack-nonce:" + owner + ":" + peerLinkRecord.peerLinkId;
    const storedNonce = await this.kv.get(nonceKey);
    if (storedNonce) {
      if (String(reject.ackNonce) !== String(storedNonce)) {
        return null;
      }
      await this.kv.delete(nonceKey);
    }

    const reason = nonEmpty(reject.reason) || "INVITE_REJECTED";
    const nowMs = this.clock();

    // Tear down the optimistic pending session + post-cap.
    const session = await this.peerLinkStorage.sessions.getByPeerLinkId(owner, peerLinkRecord.peerLinkId);
    if (session && session.sessionId) {
      await this.peerLinkStorage.sessions.delete(owner, session.sessionId);
    }
    await this.kv.delete(_postCapKey(owner, peerLinkRecord.peerLinkId));

    // Mark the initiator handshake attempt(s) rejected (diagnostic trail).
    const attempts = await this.peerLinkStorage.handshakeAttempts.listByPeerLinkId(owner, peerLinkRecord.peerLinkId);
    for (const attempt of Array.isArray(attempts) ? attempts : []) {
      if (attempt.status === "completed" || attempt.status === "rejected") continue;
      await this.peerLinkStorage.handshakeAttempts.update({
        ...attempt,
        status: "rejected",
        lastTriedAtMs: nowMs,
        lastErrorCode: reason,
        lastErrorMessage: "handshake rejected by inviter",
      }, attempt.version);
    }

    // Transition the peer-link to the terminal "rejected" state. The store has
    // no delete (state transitions are the idiom), and a terminal state is the
    // signal the chat layer tears the optimistic thread/contact down on.
    this.#checkPeerLinkTransition(peerLinkRecord.state, PEER_LINK_STATE.REJECTED, peerLinkRecord.peerLinkId);
    const rejectedRecord = await this.peerLinkStorage.peerLinks.update({
      ...peerLinkRecord,
      state: PEER_LINK_STATE.REJECTED,
      activeSessionId: null,
      lastStateChangeAtMs: nowMs,
      lastErrorCode: reason,
      lastErrorMessage: "handshake rejected by inviter",
    }, peerLinkRecord.version);

    const eventRecord = await this._appendPeerLinkEvent({
      ownerAccountId: owner,
      peerLinkId: rejectedRecord.peerLinkId,
      type: "handshake_rejected",
      summary: "Handshake rejected by inviter — peer link rolled back",
      details: {
        peerAccountId: remote,
        reason,
      },
      atMs: nowMs,
    });

    return {
      snapshot: await this._buildSnapshot(rejectedRecord),
      event: eventRecord,
      reason,
    };
  }

  async listPeerLinks({
    ownerAccountId = this.ownerAccountId,
  } = {}) {
    const owner = requireId(ownerAccountId, "ownerAccountId");
    const rows = await this.peerLinkStorage.peerLinks.listByOwner(owner);
    const items = [];
    for (let row of rows) {
      row = await this._expireHandshakeIfStale(row);
      const snapshot = await this._buildSnapshot(row);
      if (snapshot) items.push(snapshot);
    }
    items.sort((left, right) => Number(right.updatedAtMs || 0) - Number(left.updatedAtMs || 0));
    return { items };
  }

}
