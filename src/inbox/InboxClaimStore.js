import {
  Identity,
  bytesToBase64,
  base64ToBytes,
  canonicalJSONStringify,
  CapabilitySigner,
  RCapability,
  INBOX_ID_RANDOM_BYTES,
  requireCanonicalInboxId,
  validateRelayIdentityBinding,
  signTerminalInboxClose,
  claimLeasePresence,
  canonicalInboxClaimPayload,
  canonicalNodeDelegationPayload,
} from "@rezprotocol/core";

const STORE_KEY = "sdk:inbox:claims:v1";

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
  async createClaim({ clock = () => Date.now(), identity = null, inboxId = null } = {}) {
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
    // Portable inbox lease L1 (plans/PORTABLE_INBOX_LEASE_SPEC.md §2): every
    // new claim carries a CLOSE keypair — random per inbox, NEVER derived —
    // and a generation. Compromise semantics: the claim key can renew, the
    // close key can kill, neither can do both. The close PRIVATE key is
    // account-custody material: it lives in this client-side store (above
    // the provider boundary) and its only sanctioned use is
    // createTerminalClose().
    const closeIdentity = await Identity.generate({ cryptoProvider: this.#crypto });
    const closePublicKeyB64 = bytesToBase64(closeIdentity.getPublicKeyBytes());
    const closePrivateKeyB64 = bytesToBase64(closeIdentity.getPrivateKeyBytes());
    const generation = 1;
    // P1#2 L3.5: a device-link ceremony pre-registers a SPECIFIC inbox (the one the new
    // device device-signed a binding for + the home's device.add recorded), so the linked
    // device must claim THAT exact inbox, never a freshly-minted one. An explicit inboxId
    // is validated to the ONE canonical shape (SSOT @rezprotocol/core requireCanonicalInboxId:
    // "inbox:" + 24 lowercase hex) that this store and the requester both mint; the fresh-claim
    // path (no inboxId) is unchanged.
    inboxId = typeof inboxId === "string" && inboxId.trim().length > 0
      ? requireCanonicalInboxId(inboxId.trim())
      : this.#generateInboxId();
    const claimedAtMs = Number(clock());

    // Lease-bearing claim payload: the close key and generation are INSIDE
    // the signed bytes, so a provider cannot strip or substitute them. The
    // shape is built by the rez-core SSOT (canonicalInboxClaimPayload) — the
    // same builder every verifier uses, so signer and verifiers cannot drift.
    const signedPayload = canonicalJSONStringify(canonicalInboxClaimPayload({
      inboxId,
      claimantPublicKeyB64,
      closePublicKeyB64,
      generation,
      claimedAtMs,
    }));
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
      closePublicKeyB64,
      closePrivateKeyB64,
      generation,
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
    // A lease-bearing claim re-attests with the SAME extended payload shape
    // and fields — the node refuses a downgraded (legacy-shaped)
    // reattestation of a lease-bearing claim, and refuses an in-place upgrade
    // of a legacy one. Legacy records keep the legacy shape untouched. The
    // shape itself comes from the rez-core SSOT builder.
    const carriesLease = claimLeasePresence(record) === "all";
    const payload = canonicalInboxClaimPayload({
      inboxId,
      claimantPublicKeyB64,
      claimedAtMs,
      closePublicKeyB64: carriesLease ? record.closePublicKeyB64 : undefined,
      generation: carriesLease ? record.generation : undefined,
    });
    const sigBytes = await this.#crypto.sign({
      privateKey,
      msg: new TextEncoder().encode(canonicalJSONStringify(payload)),
    });
    const attestation = {
      inboxId,
      claimantPublicKeyB64,
      claimedAtMs,
      claimSignatureB64: bytesToBase64(sigBytes),
    };
    if (carriesLease) {
      attestation.closePublicKeyB64 = record.closePublicKeyB64;
      attestation.generation = record.generation;
    }
    return attestation;
  }

  /**
   * Build a signed TerminalInboxClose for a stored v2 claim — the ONLY
   * sanctioned use of the close private key. The record authorizes itself;
   * ship it over any session via inbox.close. Throws for a legacy claim
   * (no close key: not closable-by-record; the lease simply lapses).
   */
  async createTerminalClose(inboxId, { clock = () => Date.now() } = {}) {
    this.#requireHydrated("createTerminalClose");
    const record = this.#claims.get(typeof inboxId === "string" ? inboxId.trim() : "");
    if (!record) {
      throw new Error("InboxClaimStore.createTerminalClose: no claim for " + inboxId);
    }
    if (typeof record.closePublicKeyB64 !== "string" || record.closePublicKeyB64.length === 0
      || typeof record.closePrivateKeyB64 !== "string" || record.closePrivateKeyB64.length === 0
      || !Number.isInteger(record.generation)) {
      const err = new Error("InboxClaimStore.createTerminalClose: legacy claim has no close key — not closable by record");
      err.code = "INBOX_NOT_CLOSABLE";
      throw err;
    }
    return signTerminalInboxClose({
      inboxId: record.inboxId,
      finalGeneration: record.generation,
      closedAtMs: Number(clock()),
      closePublicKeyB64: record.closePublicKeyB64,
      crypto: this.#crypto,
      closePrivateKey: base64ToBytes(record.closePrivateKeyB64),
    });
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
    // Lease L2: the claimant SELECTS a retention class; the provider's policy
    // fixes what each class means (grace windows etc.). "transient" is the
    // legacy-identical default. Ignored for legacy claims (no lease fields).
    retentionClass = "transient",
    clock = () => Date.now(),
  } = {}) {
    if (retentionClass !== "transient" && retentionClass !== "standard") {
      throw new Error("createNodeDelegation: unknown retentionClass " + retentionClass);
    }
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
    // ADR-RELAY-IDENTITY: never sign a delegation to a relay identity that is
    // not the self-certifying identity of the node key it names.
    const identityBinding = validateRelayIdentityBinding({
      relayKeyId: relayKeyId.trim(),
      nodeKeyId: nodeKeyId.trim(),
      nodePublicKeyB64: nodePublicKeyB64.trim(),
    });
    if (identityBinding.ok !== true) {
      throw new Error("createNodeDelegation relay identity binding invalid: " + identityBinding.reason);
    }
    const record = this.#claims.get(inboxId.trim());
    if (!record) {
      throw new Error("createNodeDelegation: no claim for " + inboxId);
    }
    const claimantPublicKeyB64 = record.claimantPublicKeyB64;
    const privateKey = base64ToBytes(record.claimantPrivateKeyB64);
    const issuedAtMs = Number(clock());
    const expiresAtMs = issuedAtMs + Number(ttlMs);
    // For a lease-bearing claim the delegation IS the lease — generation
    // binds it to the claim's lineage (a pre-close lease can never resurrect
    // a closed generation) and retentionClass selects provider retention
    // policy. Both are INSIDE the signed bytes, whose shape comes from the
    // rez-core SSOT builder. Legacy claims keep the legacy payload.
    const carriesLease = Number.isInteger(record.generation);
    const payload = canonicalNodeDelegationPayload({
      inboxId: inboxId.trim(),
      claimantPublicKeyB64,
      nodeKeyId: nodeKeyId.trim(),
      nodePublicKeyB64: nodePublicKeyB64.trim(),
      relayKeyId: relayKeyId.trim(),
      issuedAtMs,
      expiresAtMs,
      generation: carriesLease ? record.generation : undefined,
      retentionClass: carriesLease ? retentionClass : undefined,
    });
    const sigBytes = await this.#crypto.sign({
      privateKey,
      msg: new TextEncoder().encode(canonicalJSONStringify(payload)),
    });
    const out = {
      inboxId: payload.inboxId,
      claimantPublicKeyB64,
      nodeKeyId: payload.nodeKeyId,
      nodePublicKeyB64: payload.nodePublicKeyB64,
      relayKeyId: payload.relayKeyId,
      issuedAtMs,
      expiresAtMs,
      delegationSigB64: bytesToBase64(sigBytes),
    };
    if (carriesLease) {
      out.generation = payload.generation;
      out.retentionClass = payload.retentionClass;
    }
    return out;
  }

  /**
   * M6 (rez-chat plans/MOBILE_LIFECYCLE_ADAPTER_PLAN.md §7e): re-mint the
   * NEXT generation of a reclaimed inbox lifetime — same inboxId, same
   * claimant key (peers' delivery bindings survive), FRESH random close
   * keypair, generation = finalGeneration + 1, freshly signed claim payload.
   * The stored lease is dropped (the dead lifetime's window means nothing);
   * recordAcceptedLease repopulates it when the provider accepts the new
   * claim.
   *
   * Provider evidence is REQUIRED, never local arithmetic: the caller passes
   * the finalGeneration from the provider's typed INBOX_CLOSED detail, and
   * this method refuses unless it matches the stored generation exactly —
   * a mismatch is a conflict to surface, not a reason to guess. Terminal
   * closures never reach here (caller policy; and the provider refuses the
   * lineage anyway).
   */
  async remintGeneration({ inboxId, finalGeneration, clock = () => Date.now() } = {}) {
    this.#requireHydrated("remintGeneration");
    const id = typeof inboxId === "string" ? inboxId.trim() : "";
    const record = this.#claims.get(id);
    if (!record) {
      throw new Error("InboxClaimStore.remintGeneration: no claim for " + inboxId);
    }
    if (!Number.isInteger(record.generation)) {
      const err = new Error("InboxClaimStore.remintGeneration: legacy claim carries no generation — nothing to re-mint");
      err.code = "INBOX_NOT_REMINTABLE";
      throw err;
    }
    if (!Number.isInteger(finalGeneration) || finalGeneration < 1) {
      throw new Error("InboxClaimStore.remintGeneration requires the provider's finalGeneration");
    }
    if (record.generation !== finalGeneration) {
      const err = new Error("InboxClaimStore.remintGeneration: generation conflict — stored "
        + record.generation + ", provider tombstone says " + finalGeneration
        + "; refusing to guess");
      err.code = "REMINT_GENERATION_CONFLICT";
      throw err;
    }
    const closeIdentity = await Identity.generate({ cryptoProvider: this.#crypto });
    const closePublicKeyB64 = bytesToBase64(closeIdentity.getPublicKeyBytes());
    const closePrivateKeyB64 = bytesToBase64(closeIdentity.getPrivateKeyBytes());
    const generation = finalGeneration + 1;
    const claimedAtMs = Number(clock());
    const privateKey = base64ToBytes(record.claimantPrivateKeyB64);
    const signedPayload = canonicalJSONStringify(canonicalInboxClaimPayload({
      inboxId: id,
      claimantPublicKeyB64: record.claimantPublicKeyB64,
      closePublicKeyB64,
      generation,
      claimedAtMs,
    }));
    const sigBytes = await this.#crypto.sign({
      privateKey,
      msg: new TextEncoder().encode(signedPayload),
    });
    const previous = { ...record };
    record.closePublicKeyB64 = closePublicKeyB64;
    record.closePrivateKeyB64 = closePrivateKeyB64;
    record.generation = generation;
    record.claimedAtMs = claimedAtMs;
    record.claimSignatureB64 = bytesToBase64(sigBytes);
    delete record.lease;
    try {
      await this.#persistAll();
    } catch (err) {
      this.#claims.set(id, previous);
      throw err;
    }
    return { inboxId: id, fromGeneration: finalGeneration, toGeneration: generation };
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
    // M3: the lease is STORE-OWNED state recorded from the acceptance seam
    // (recordAcceptedLease), not part of the claim material callers build —
    // a re-persist of claim material must not silently drop it.
    const existing = this.#claims.get(normalized.inboxId);
    if (!normalized.lease && existing && existing.lease) {
      normalized.lease = { ...existing.lease };
    }
    this.#claims.set(normalized.inboxId, normalized);
    try {
      await this.#persistAll();
    } catch (err) {
      // Roll back to what durably existed: restore the previous record for
      // an update, remove the entry for a brand-new claim.
      if (existing) this.#claims.set(normalized.inboxId, existing);
      else this.#claims.delete(normalized.inboxId);
      throw err;
    }
    return normalized;
  }

  /**
   * M3 (rez-chat plans/MOBILE_LIFECYCLE_ADAPTER_PLAN.md §7c pin 1): record
   * the lease the provider ACTUALLY ACCEPTED. Called from the claim path
   * strictly AFTER the INBOX_CLAIM round-trip succeeds, with the exact
   * delegation fields that were sent — never with a draft delegation built
   * before the wire op. A failed renewal therefore never advances the
   * client's view of its own lease (pin 3): the previous durable state stays
   * intact and the next wake still derives "due".
   */
  async recordAcceptedLease({ inboxId, issuedAtMs, expiresAtMs, retentionClass = "transient" } = {}) {
    this.#requireHydrated("recordAcceptedLease");
    const id = typeof inboxId === "string" ? inboxId.trim() : "";
    const record = this.#claims.get(id);
    if (!record) {
      throw new Error("InboxClaimStore.recordAcceptedLease: no claim for " + inboxId);
    }
    const issued = Number(issuedAtMs);
    const expires = Number(expiresAtMs);
    if (!Number.isFinite(issued) || issued <= 0 || !Number.isFinite(expires) || expires <= issued) {
      throw new Error("InboxClaimStore.recordAcceptedLease: invalid lease window issuedAtMs=" + issuedAtMs + " expiresAtMs=" + expiresAtMs);
    }
    if (retentionClass !== "transient" && retentionClass !== "standard") {
      throw new Error("InboxClaimStore.recordAcceptedLease: unknown retentionClass " + retentionClass);
    }
    const previous = record.lease ? { ...record.lease } : null;
    record.lease = { issuedAtMs: issued, expiresAtMs: expires, retentionClass };
    try {
      await this.#persistAll();
    } catch (err) {
      // Roll back the in-memory view so it never claims a durability the
      // store does not have (same discipline as persist()).
      if (previous) record.lease = previous;
      else delete record.lease;
      throw err;
    }
    return { ...record.lease };
  }

  /**
   * The last ACCEPTED lease for an inbox, or null when none was ever
   * recorded. Wake-time renewal derives "due or not" from this + now —
   * absence means the caller should renew (the safe direction), never that
   * the lease is healthy.
   */
  leaseState(inboxId) {
    this.#requireHydrated("leaseState");
    if (typeof inboxId !== "string" || !inboxId.trim()) return null;
    const record = this.#claims.get(inboxId.trim());
    return record && record.lease ? { ...record.lease } : null;
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
      const row = {
        inboxId: record.inboxId,
        claimantPublicKeyB64: record.claimantPublicKeyB64,
        claimantPrivateKeyB64: record.claimantPrivateKeyB64,
        claimedAtMs: record.claimedAtMs,
        claimSignatureB64: record.claimSignatureB64,
        rootCap: record.rootCap && typeof record.rootCap.toJSON === "function"
          ? record.rootCap.toJSON()
          : record.rootCap,
      };
      if (Number.isInteger(record.generation)) {
        row.closePublicKeyB64 = record.closePublicKeyB64;
        row.closePrivateKeyB64 = record.closePrivateKeyB64;
        row.generation = record.generation;
      }
      if (record.lease) {
        row.lease = { ...record.lease };
      }
      claims.push(row);
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
    const out = {
      inboxId,
      claimantPublicKeyB64,
      claimantPrivateKeyB64,
      claimedAtMs,
      claimSignatureB64,
      rootCap,
    };
    // Lease L1 fields: ALL-OR-NONE. A record carrying only part of the v2
    // triple is corrupt — treat it as invalid rather than half-adopting it.
    const hasClosePub = typeof record.closePublicKeyB64 === "string" && record.closePublicKeyB64.trim().length > 0;
    const hasClosePriv = typeof record.closePrivateKeyB64 === "string" && record.closePrivateKeyB64.trim().length > 0;
    const hasGeneration = Number.isInteger(Number(record.generation)) && Number(record.generation) >= 1;
    if (hasClosePub || hasClosePriv || hasGeneration) {
      if (!(hasClosePub && hasClosePriv && hasGeneration)) return null;
      out.closePublicKeyB64 = record.closePublicKeyB64.trim();
      out.closePrivateKeyB64 = record.closePrivateKeyB64.trim();
      out.generation = Number(record.generation);
    }
    // M3: the last-accepted lease window. A malformed lease sub-record is
    // treated as ABSENT rather than invalidating the claim (the claimant keys
    // above are irreplaceable; the lease is re-derivable) — and absence fails
    // toward RENEWAL at the next wake, never toward a false "seven more
    // days", so nothing is silently trusted.
    if (record.lease && typeof record.lease === "object") {
      const issued = Number(record.lease.issuedAtMs);
      const expires = Number(record.lease.expiresAtMs);
      const cls = record.lease.retentionClass;
      if (Number.isFinite(issued) && issued > 0 && Number.isFinite(expires) && expires > issued
        && (cls === "transient" || cls === "standard")) {
        out.lease = { issuedAtMs: issued, expiresAtMs: expires, retentionClass: cls };
      }
    }
    return out;
  }
}

function cloneClaim(record) {
  const out = {
    inboxId: record.inboxId,
    claimantPublicKeyB64: record.claimantPublicKeyB64,
    claimantPrivateKeyB64: record.claimantPrivateKeyB64,
    claimedAtMs: record.claimedAtMs,
    claimSignatureB64: record.claimSignatureB64,
    rootCap: record.rootCap,
  };
  if (Number.isInteger(record.generation)) {
    out.closePublicKeyB64 = record.closePublicKeyB64;
    out.closePrivateKeyB64 = record.closePrivateKeyB64;
    out.generation = record.generation;
  }
  if (record.lease) {
    out.lease = { ...record.lease };
  }
  return out;
}
