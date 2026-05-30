import {
  Identity,
  bytesToBase64,
  base64ToBytes,
  canonicalJSONStringify,
  CapabilitySigner,
  RCapability,
} from "@rezprotocol/core";

const STORE_KEY = "sdk:inbox:claims:v1";
const INBOX_ID_RANDOM_BYTES = 12;

/**
 * Client-side store of inbox claims the SDK has issued.
 *
 * Per docs/CAPABILITY_MODEL.md, the SDK is the trust root for each inbox it
 * claims. This store holds the per-inbox claimant keypair (private + public),
 * the original claim record, and the locally-derived root capability. None of
 * this material ever flows to the node except as proofs (signatures over
 * specific bytes) — the private key in particular MUST stay in SDK storage.
 *
 * Storage shape (KV at STORE_KEY):
 *   {
 *     claims: [
 *       {
 *         inboxId,
 *         claimantPublicKeyB64,
 *         claimantPrivateKeyB64,
 *         claimedAtMs,
 *         claimSignatureB64,
 *         rootCap: <RCapability JSON>,
 *       },
 *       ...
 *     ]
 *   }
 */
export class InboxClaimStore {
  #kv;
  #crypto;
  #signer;
  #claims;
  #hydrated;

  constructor({ storageProvider, cryptoProvider } = {}) {
    if (!storageProvider || typeof storageProvider.getKeyValueStore !== "function") {
      throw new Error("InboxClaimStore requires storageProvider.getKeyValueStore()");
    }
    if (!cryptoProvider) {
      throw new Error("InboxClaimStore requires cryptoProvider");
    }
    this.#kv = storageProvider.getKeyValueStore(null);
    this.#crypto = cryptoProvider;
    this.#signer = new CapabilitySigner({ crypto: cryptoProvider });
    /** @type {Map<string, object>} */
    this.#claims = new Map();
    this.#hydrated = false;
  }

  async hydrate() {
    if (this.#hydrated) return;
    const stored = await this.#kv.get(STORE_KEY);
    const entries = Array.isArray(stored && stored.claims) ? stored.claims : [];
    for (const entry of entries) {
      const normalized = this.#normalizeStored(entry);
      if (normalized) this.#claims.set(normalized.inboxId, normalized);
    }
    this.#hydrated = true;
  }

  /**
   * Generate a fresh inbox claim: random inboxId, signed payload, and a
   * locally-stored root capability covering the new inbox.
   *
   * If `identity` is supplied (publicKeyB64 + privateKeyB64), it is used as
   * the claimant keypair — this is how the chat-server binds its session
   * identity to its inbox claim with a single keypair. Otherwise a fresh
   * keypair is generated.
   *
   * Does NOT yet send the wire op or persist the claim — call `persist()`
   * after the node confirms acceptance.
   */
  async createClaim({ clock = () => Date.now(), identity = null } = {}) {
    this.#requireHydrated("createClaim");
    let publicKey;
    let privateKey;
    if (identity && typeof identity.publicKeyB64 === "string" && typeof identity.privateKeyB64 === "string") {
      publicKey = base64ToBytes(identity.publicKeyB64);
      privateKey = base64ToBytes(identity.privateKeyB64);
    } else {
      const generated = await Identity.generate({ cryptoProvider: this.#crypto });
      publicKey = generated.getPublicKeyBytes();
      privateKey = generated.getPrivateKeyBytes();
    }
    const claimantPublicKeyB64 = bytesToBase64(publicKey);
    const claimantPrivateKeyB64 = bytesToBase64(privateKey);
    const inboxId = this.#generateInboxId();
    const claimedAtMs = Number(clock());

    const signedPayload = canonicalJSONStringify({
      inboxId,
      claimantPublicKeyB64,
      claimedAtMs,
    });
    const sigBytes = await this.#crypto.sign({
      privateKey,
      msg: new TextEncoder().encode(signedPayload),
    });
    const claimSignatureB64 = bytesToBase64(sigBytes);

    // Locally-derived root cap. The SDK is the signing authority for inbox-
    // scoped caps from now on; the claimant pubkey is the trust root that the
    // node will verify against (see InboxClaimRegistry).
    // inboxIds are formatted "inbox:<random>" — they already carry the
    // `inbox:` prefix, which matches the RResource kind. So the resource
    // string is just the inboxId verbatim.
    const rootCap = await this.#signer.createRootCapability({
      resource: inboxId,
      actions: ["admin", "grant", "read", "write"],
      constraints: {},
      signerPublicKeyB64: claimantPublicKeyB64,
      privateKeyBytes: privateKey,
    });

    return {
      inboxId,
      claimantPublicKeyB64,
      claimantPrivateKeyB64,
      claimedAtMs,
      claimSignatureB64,
      rootCap,
    };
  }

  /**
   * Re-attest an existing claim against a node — produces a fresh signed
   * claim record using the stored claimant keypair. Used on reconnect when
   * the SDK needs to prove ownership of its existing inboxes to the node's
   * InboxClaimRegistry (idempotent re-claim path).
   */
  async createReattestation(inboxId, { clock = () => Date.now() } = {}) {
    this.#requireHydrated("createReattestation");
    const record = this.#claims.get(inboxId);
    if (!record) {
      throw new Error("InboxClaimStore.createReattestation: no claim for " + inboxId);
    }
    const claimantPublicKeyB64 = record.claimantPublicKeyB64;
    const privateKey = base64ToBytes(record.claimantPrivateKeyB64);
    const claimedAtMs = Number(clock());
    const sigBytes = await this.#crypto.sign({
      privateKey,
      msg: new TextEncoder().encode(canonicalJSONStringify({
        inboxId,
        claimantPublicKeyB64,
        claimedAtMs,
      })),
    });
    return {
      inboxId,
      claimantPublicKeyB64,
      claimedAtMs,
      claimSignatureB64: bytesToBase64(sigBytes),
    };
  }

  /**
   * Sign a node-delegation: authorizes the named node to advertise this
   * claimed inbox to the relay mesh. The delegation is verified by every
   * relay along the routing path against the embedded claimant pubkey, and
   * binds the claim to a specific node identity so a delegation cannot be
   * replayed by a different node.
   *
   * The signed payload mirrors `claimantNodeDelegationPayload` on the node
   * side (rez-node/src/relay/InboxRouter.js) — those two payload shapes
   * MUST stay in lockstep.
   */
  async createNodeDelegation({
    inboxId,
    nodeKeyId,
    nodePublicKeyB64,
    relayKeyId,
    ttlMs = 7 * 24 * 60 * 60 * 1000,
    clock = () => Date.now(),
  } = {}) {
    this.#requireHydrated("createNodeDelegation");
    if (typeof inboxId !== "string" || !inboxId.trim()) {
      throw new Error("createNodeDelegation requires inboxId");
    }
    if (typeof nodeKeyId !== "string" || !nodeKeyId.trim()) {
      throw new Error("createNodeDelegation requires nodeKeyId");
    }
    if (typeof nodePublicKeyB64 !== "string" || !nodePublicKeyB64.trim()) {
      throw new Error("createNodeDelegation requires nodePublicKeyB64");
    }
    if (typeof relayKeyId !== "string" || !relayKeyId.trim()) {
      throw new Error("createNodeDelegation requires relayKeyId");
    }
    const record = this.#claims.get(inboxId.trim());
    if (!record) {
      throw new Error("createNodeDelegation: no claim for " + inboxId);
    }
    const claimantPublicKeyB64 = record.claimantPublicKeyB64;
    const privateKey = base64ToBytes(record.claimantPrivateKeyB64);
    const issuedAtMs = Number(clock());
    const expiresAtMs = issuedAtMs + Number(ttlMs);
    const payload = {
      kind: "inbox-node-delegation",
      inboxId: inboxId.trim(),
      claimantPublicKeyB64,
      nodeKeyId: nodeKeyId.trim(),
      nodePublicKeyB64: nodePublicKeyB64.trim(),
      relayKeyId: relayKeyId.trim(),
      issuedAtMs,
      expiresAtMs,
    };
    const sigBytes = await this.#crypto.sign({
      privateKey,
      msg: new TextEncoder().encode(canonicalJSONStringify(payload)),
    });
    return {
      inboxId: payload.inboxId,
      claimantPublicKeyB64,
      nodeKeyId: payload.nodeKeyId,
      nodePublicKeyB64: payload.nodePublicKeyB64,
      relayKeyId: payload.relayKeyId,
      issuedAtMs,
      expiresAtMs,
      delegationSigB64: bytesToBase64(sigBytes),
    };
  }

  /**
   * Persist a claim record to storage. Called after the node confirms the
   * claim with INBOX_CLAIM_RES.
   */
  async persist(claim) {
    this.#requireHydrated("persist");
    const normalized = this.#normalizeStored(claim);
    if (!normalized) {
      throw new Error("InboxClaimStore.persist: invalid claim record");
    }
    this.#claims.set(normalized.inboxId, normalized);
    try {
      await this.#persistAll();
    } catch (err) {
      this.#claims.delete(normalized.inboxId);
      throw err;
    }
    return normalized;
  }

  /**
   * Returns the stored claim for an inbox, including the private key. Callers
   * MUST treat the result as sensitive (never logged, never serialized to the
   * wire).
   */
  get(inboxId) {
    this.#requireHydrated("get");
    if (typeof inboxId !== "string" || !inboxId.trim()) return null;
    const record = this.#claims.get(inboxId.trim());
    return record ? cloneClaim(record) : null;
  }

  /**
   * Returns metadata for all stored claims with private keys redacted — safe
   * for logging or exposure to higher app layers that only need to know
   * "which inboxes do I own?".
   */
  listRedacted() {
    this.#requireHydrated("listRedacted");
    const out = [];
    for (const record of this.#claims.values()) {
      out.push({
        inboxId: record.inboxId,
        claimantPublicKeyB64: record.claimantPublicKeyB64,
        claimedAtMs: record.claimedAtMs,
      });
    }
    return out;
  }

  size() {
    this.#requireHydrated("size");
    return this.#claims.size;
  }

  has(inboxId) {
    this.#requireHydrated("has");
    if (typeof inboxId !== "string" || !inboxId.trim()) return false;
    return this.#claims.has(inboxId.trim());
  }

  #generateInboxId() {
    const bytes = this.#crypto.randomBytes(INBOX_ID_RANDOM_BYTES);
    let hex = "";
    for (const b of bytes) hex += b.toString(16).padStart(2, "0");
    return "inbox:" + hex;
  }

  async #persistAll() {
    const claims = [];
    for (const record of this.#claims.values()) {
      claims.push({
        inboxId: record.inboxId,
        claimantPublicKeyB64: record.claimantPublicKeyB64,
        claimantPrivateKeyB64: record.claimantPrivateKeyB64,
        claimedAtMs: record.claimedAtMs,
        claimSignatureB64: record.claimSignatureB64,
        rootCap: record.rootCap && typeof record.rootCap.toJSON === "function"
          ? record.rootCap.toJSON()
          : record.rootCap,
      });
    }
    await this.#kv.set(STORE_KEY, { claims });
  }

  #requireHydrated(method) {
    if (!this.#hydrated) {
      throw new Error("InboxClaimStore." + method + " called before hydrate()");
    }
  }

  #normalizeStored(record) {
    if (!record || typeof record !== "object") return null;
    const inboxId = typeof record.inboxId === "string" ? record.inboxId.trim() : "";
    const claimantPublicKeyB64 = typeof record.claimantPublicKeyB64 === "string" ? record.claimantPublicKeyB64.trim() : "";
    const claimantPrivateKeyB64 = typeof record.claimantPrivateKeyB64 === "string" ? record.claimantPrivateKeyB64.trim() : "";
    const claimedAtMs = Number(record.claimedAtMs);
    const claimSignatureB64 = typeof record.claimSignatureB64 === "string" ? record.claimSignatureB64.trim() : "";
    if (!inboxId || !claimantPublicKeyB64 || !claimantPrivateKeyB64 || !claimSignatureB64) return null;
    if (!Number.isFinite(claimedAtMs) || claimedAtMs <= 0) return null;
    const rootCap = record.rootCap instanceof RCapability
      ? record.rootCap
      : (record.rootCap ? new RCapability(record.rootCap) : null);
    if (!rootCap) return null;
    return {
      inboxId,
      claimantPublicKeyB64,
      claimantPrivateKeyB64,
      claimedAtMs,
      claimSignatureB64,
      rootCap,
    };
  }
}

function cloneClaim(record) {
  return {
    inboxId: record.inboxId,
    claimantPublicKeyB64: record.claimantPublicKeyB64,
    claimantPrivateKeyB64: record.claimantPrivateKeyB64,
    claimedAtMs: record.claimedAtMs,
    claimSignatureB64: record.claimSignatureB64,
    rootCap: record.rootCap,
  };
}
