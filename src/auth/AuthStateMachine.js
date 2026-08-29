import { SDK_EVENTS } from "../events/SdkEvents.js";
import { AuthFailure } from "../errors/index.js";
import { signPayload, verifyPayload } from "./signing.js";
import { permitsAccountModeAuth } from "../relay/DowngradePolicy.js";
import { CONTRACT_VERSION, REZ_CONTRACT_TYPES, validateRelayIdentityBinding } from "@rezprotocol/core";

export const AUTH_MODES = Object.freeze({ ACCOUNT: "account", CLAIMANT: "claimant" });

const T = REZ_CONTRACT_TYPES;
const SESSION_CHALLENGE_TYPE = T.SESSION_CHALLENGE;
const SESSION_AUTHENTICATE_TYPE = T.SESSION_AUTHENTICATE;

export const AUTH_STATES = Object.freeze({
  UNAUTHENTICATED: "unauthenticated",
  HELLO_SENT: "helloSent",
  CHALLENGE_RECEIVED: "challengeReceived",
  AUTHENTICATING: "authenticating",
  AUTHENTICATED: "authenticated",
  FAILED: "failed",
});

function wsPathFromUrl(url) {
  try {
    const parsed = new URL(String(url || ""));
    return parsed.pathname || "/ws";
  } catch {
    return "/ws";
  }
}

/**
 * Auth state machine — challenge-response handshake against a node.
 *
 * The SDK identifies itself by its account-identity public key only. Accounts
 * are a chat-app concept; the relay does not see them. An inbox is associated
 * with the session via a separate inbox.claim op after session.ready.
 *
 * 1. Send session.hello with the SDK's public key
 * 2. Receive session.challenge (with the node's identity)
 * 3. Sign the challenge with the SDK's private key
 * 4. Send session.authenticate
 * 5. Receive session.ready
 */
export class AuthStateMachine {
  #state = AUTH_STATES.UNAUTHENTICATED;
  #identity;
  #eventBus;
  #sessionInfo = null;
  #sessionHello;
  #clientVersion;
  #expectedNodePublicKeyB64;
  // SESSION_AUTH_V5: which principal mode this machine authenticates as.
  // Fixed at construction — there is deliberately NO path from a claimant
  // machine to an account-mode attempt (no automatic identity-disclosure
  // fallback, Phase 0 §7); a different mode is a different machine.
  #mode;
  #claimantIdentity = null;
  // SESSION_AUTH_V5 2B: optional { store, enforce } — records the verified
  // relay's contract floor after AUTHENTICATED and, ONLY when the embedder
  // opted into enforcement and pinned the relay identity, refuses to start an
  // identity-bearing account-mode handshake toward a known-v5 relay.
  #relayContractFloor = null;

  /**
   * @param {object} opts
   * @param {object} opts.identity — { publicKeyB64, privateKeyB64, deviceId? }
   * @param {object} opts.eventBus
   * @param {object} [opts.sessionHello]
   * @param {string} [opts.clientVersion]
   * @param {string} [opts.expectedNodePublicKeyB64] — if provided, the SDK
   *   refuses to authenticate against any node whose challenge does not carry
   *   this exact pubkey. Required for safe operation against an untrusted
   *   network (see docs/SECURITY_AUDIT.md CRITICAL-2); leaving it empty
   *   reduces to trust-on-first-use semantics — the SDK still verifies the
   *   challenge's self-signature, but accepts whichever node identity the
   *   challenge claims.
   */
  constructor({ identity, claimantIdentity, eventBus, sessionHello = {}, clientVersion = "rez-sdk/2.0", expectedNodePublicKeyB64 = "", relayContractFloor = null } = {}) {
    // SESSION_AUTH_V5: exactly ONE mode per machine. Supplying both identity
    // forms is a construction error, not a preference order.
    if (claimantIdentity && identity) {
      throw new Error("AuthStateMachine takes identity (account) OR claimantIdentity (claimant), never both");
    }
    if (relayContractFloor !== null) {
      if (!relayContractFloor.store || typeof relayContractFloor.store.recordObserved !== "function"
        || typeof relayContractFloor.store.floorFor !== "function") {
        throw new Error("relayContractFloor requires a RelayContractFloorStore-shaped store");
      }
      this.#relayContractFloor = {
        store: relayContractFloor.store,
        enforce: relayContractFloor.enforce === true,
      };
    }
    if (claimantIdentity) {
      if (!claimantIdentity.claimantPublicKeyB64 || !claimantIdentity.privateKeyB64) {
        throw new Error("AuthStateMachine claimant mode requires claimantIdentity.claimantPublicKeyB64 and privateKeyB64");
      }
      if (!eventBus) throw new Error("AuthStateMachine requires eventBus");
      this.#mode = AUTH_MODES.CLAIMANT;
      this.#claimantIdentity = {
        claimantPublicKeyB64: String(claimantIdentity.claimantPublicKeyB64).trim(),
        privateKeyB64: String(claimantIdentity.privateKeyB64),
      };
      this.#identity = null;
      this.#eventBus = eventBus;
      this.#clientVersion = String(clientVersion || "rez-sdk/2.0");
      this.#expectedNodePublicKeyB64 = typeof expectedNodePublicKeyB64 === "string" ? expectedNodePublicKeyB64.trim() : "";
      this.#sessionHello = {
        requestType: String((sessionHello && sessionHello.requestType) || T.SESSION_HELLO),
        responseType: String((sessionHello && sessionHello.responseType) || T.SESSION_READY),
        body: {},
      };
      return;
    }
    this.#mode = AUTH_MODES.ACCOUNT;
    if (!identity || !identity.publicKeyB64) {
      throw new Error("AuthStateMachine requires identity with publicKeyB64");
    }
    // Dual-mode (S2.5 S7): a PRIMARY device authenticates with the account root
    // key (privateKeyB64 = B-sign). A DELEGATED device holds no B-sign private
    // key — it signs with its per-device key C and presents an account→device
    // capability chain (identity.deviceKey + identity.certChain). One must exist.
    const delegationDeviceKey = identity.deviceKey && typeof identity.deviceKey === "object" ? identity.deviceKey : null;
    const delegationCertChain = Array.isArray(identity.certChain) ? identity.certChain : null;
    const hasDelegation = Boolean(
      delegationDeviceKey && delegationDeviceKey.publicKeyB64 && delegationDeviceKey.privateKeyB64
        && delegationCertChain && delegationCertChain.length > 0,
    );
    if (!identity.privateKeyB64 && !hasDelegation) {
      throw new Error(
        "AuthStateMachine requires identity.privateKeyB64 (primary) or identity.deviceKey + certChain (delegated)",
      );
    }
    if (!eventBus) throw new Error("AuthStateMachine requires eventBus");
    this.#identity = identity;
    this.#eventBus = eventBus;
    this.#clientVersion = String(clientVersion || "rez-sdk/2.0");
    this.#expectedNodePublicKeyB64 = typeof expectedNodePublicKeyB64 === "string" ? expectedNodePublicKeyB64.trim() : "";
    this.#sessionHello = {
      requestType: String(sessionHello.requestType || T.SESSION_HELLO),
      responseType: String(sessionHello.responseType || T.SESSION_READY),
      body: sessionHello.body && typeof sessionHello.body === "object" ? sessionHello.body : {},
    };
  }

  get state() {
    return this.#state;
  }

  get sessionInfo() {
    return this.#sessionInfo ? { ...this.#sessionInfo } : null;
  }

  get mode() {
    return this.#mode;
  }

  /**
   * Shared challenge intake: response-type check, field extraction,
   * completeness, ADR-RELAY-IDENTITY binding, expiry, and the CRITICAL-2
   * pinned-node check. Mode-specific work (which payload the self-signature
   * covers, which key signs back) stays with each mode's flow.
   */
  #parseAndValidateChallenge(helloResponse) {
    const responseType = String((helloResponse && helloResponse.t) || "");
    if (responseType !== SESSION_CHALLENGE_TYPE) {
      throw new AuthFailure(`unexpected response type: ${responseType || "unknown"}`);
    }
    this.#transition(AUTH_STATES.CHALLENGE_RECEIVED);
    const challengeBody = helloResponse && helloResponse.body && typeof helloResponse.body === "object"
      ? helloResponse.body
      : {};
    const challenge = {
      challengeId: String(challengeBody.challengeId || ""),
      nonceB64: String(challengeBody.nonceB64 || ""),
      nodeKeyId: String(challengeBody.nodeKeyId || ""),
      nodePublicKeyB64: String(challengeBody.nodePublicKeyB64 || ""),
      relayKeyId: String(challengeBody.relayKeyId || ""),
      issuedAtMs: Number(challengeBody.issuedAtMs),
      expiresAtMs: Number(challengeBody.expiresAtMs),
      wsPath: String(challengeBody.wsPath || ""),
      signatureB64: String(challengeBody.signatureB64 || ""),
    };
    if (!challenge.challengeId || !challenge.nonceB64 || !challenge.nodeKeyId || !challenge.nodePublicKeyB64
      || !challenge.relayKeyId || !Number.isFinite(challenge.issuedAtMs) || !Number.isFinite(challenge.expiresAtMs)
      || !challenge.wsPath || !challenge.signatureB64) {
      throw new AuthFailure("session challenge incomplete");
    }
    // ADR-RELAY-IDENTITY: the node's relayKeyId must be the self-certifying
    // identity of the node key it authenticates with. The client refuses to
    // proceed against a node presenting a free-string or stolen relay id.
    const identityBinding = validateRelayIdentityBinding({
      relayKeyId: challenge.relayKeyId,
      nodeKeyId: challenge.nodeKeyId,
      nodePublicKeyB64: challenge.nodePublicKeyB64,
    });
    if (identityBinding.ok !== true) {
      throw new AuthFailure("session challenge relay identity invalid: " + identityBinding.reason);
    }
    if (Date.now() > challenge.expiresAtMs) {
      throw new AuthFailure("session challenge expired");
    }
    // CRITICAL-2 defense: if the SDK was configured with an expected node
    // pubkey, reject any challenge whose nodePublicKeyB64 doesn't match.
    // This prevents a MITM from relaying a different node's challenge.
    if (this.#expectedNodePublicKeyB64
      && this.#expectedNodePublicKeyB64 !== challenge.nodePublicKeyB64) {
      throw new AuthFailure(
        "session challenge from unexpected node — refusing to sign. "
        + "Configured expectedNodePublicKeyB64 does not match the challenge.",
      );
    }
    return challenge;
  }

  /**
   * SESSION_AUTH_V5 2B: record the verified relay's contract floor after a
   * successful authentication; surface a downgrade CONDITION (observation,
   * never an automatic reaction) when this session's contract is below the
   * recorded floor.
   */
  #recordContractFloor({ nodePublicKeyB64, contractVersion }) {
    if (!this.#relayContractFloor) return;
    const result = this.#relayContractFloor.store.recordObserved({
      relayIdentityB64: nodePublicKeyB64,
      contractVersion,
    });
    if (result.downgrade === true) {
      this.#eventBus.emit(SDK_EVENTS.AUTH_DOWNGRADE_CONDITION, {
        relayIdentityB64: nodePublicKeyB64,
        floor: result.floor,
        observedCurrent: result.observedCurrent,
      });
    }
  }

  async authenticate(transport) {
    if (this.#mode === AUTH_MODES.CLAIMANT) {
      return this.#authenticateClaimant(transport);
    }
    this.#sessionInfo = null;
    this.#transition(AUTH_STATES.UNAUTHENTICATED);

    // SESSION_AUTH_V5 2B (opt-in enforcement only): an account-mode handshake
    // DISCLOSES identity in the hello, so a refusal must happen BEFORE any
    // frame — which is only possible against a PINNED relay identity. With
    // enforcement off (the default) this always permits; recording still
    // happens post-auth either way.
    if (this.#relayContractFloor && this.#expectedNodePublicKeyB64) {
      const verdict = permitsAccountModeAuth({
        relayIdentityB64: this.#expectedNodePublicKeyB64,
        floorStore: this.#relayContractFloor.store,
        enforce: this.#relayContractFloor.enforce,
      });
      if (verdict.permitted !== true) {
        const failure = new AuthFailure("account-mode auth refused before hello: " + verdict.reason);
        failure.serverCode = "DOWNGRADE_REFUSED";
        this.#transition(AUTH_STATES.FAILED, { error: failure.message });
        throw failure;
      }
    }

    try {
      // Step 1: Send session.hello
      this.#transition(AUTH_STATES.HELLO_SENT);
      const helloResponse = await transport.sendRequest({
        type: this.#sessionHello.requestType,
        body: {
          ...this.#sessionHello.body,
          clientName: "rez-sdk",
          clientVersion: this.#clientVersion,
          deviceId: this.#identity.deviceId || "",
          accountIdentityPublicKeyB64: this.#identity.publicKeyB64,
        },
        expectedResponseType: null,
        timeoutMs: 5000,
      });

      // Step 2: Expect session.challenge (shared intake + validation)
      const challenge = this.#parseAndValidateChallenge(helloResponse);
      const {
        challengeId, nonceB64, nodeKeyId, nodePublicKeyB64, relayKeyId,
        issuedAtMs, expiresAtMs,
        wsPath: challengeWsPath, signatureB64: challengeSignatureB64,
      } = challenge;

      // Verify the challenge's self-signature so the SDK only signs back
      // against a node that genuinely holds nodeKeyId's privkey.
      const sdkWsPath = wsPathFromUrl(transport.url || "");
      const normalizedDeviceId = this.#identity.deviceId || "";
      const challengeVerified = await verifyPayload({
        publicKeyB64: nodePublicKeyB64,
        signatureB64: challengeSignatureB64,
        payload: {
          kind: "session-challenge",
          challengeId,
          nonceB64,
          issuedAtMs,
          expiresAtMs,
          nodeKeyId,
          nodePublicKeyB64,
          relayKeyId,
          accountIdentityPublicKeyB64: this.#identity.publicKeyB64,
          sessionDeviceId: normalizedDeviceId,
          wsPath: challengeWsPath,
        },
      });
      if (!challengeVerified) {
        throw new AuthFailure("session challenge signature did not verify");
      }
      // Note: wsPath is included in the signed payloads (server signs the
      // challenge over it; we sign session-auth over it). We do NOT enforce
      // equality between the server-claimed wsPath and our own URL-derived
      // path — the primary cross-node-replay defense is the nodeKeyId/
      // nodePublicKeyB64 binding above; wsPath equality would over-trigger
      // on proxies/path-rewrites without adding meaningful security.
      void sdkWsPath;

      // Step 3: Sign the challenge. A PRIMARY device signs with the account root
      // key (B-sign); a DELEGATED device signs with its per-device key C and
      // presents the capability chain. The signed payload is IDENTICAL in both
      // modes (it binds the claimed account + deviceId) — only the signing key
      // and the extra authenticate-body fields differ.
      this.#transition(AUTH_STATES.AUTHENTICATING);

      const delegated = !this.#identity.privateKeyB64;
      const signingPrivateKeyB64 = delegated ? this.#identity.deviceKey.privateKeyB64 : this.#identity.privateKeyB64;
      const signatureB64 = await signPayload({
        privateKeyB64: signingPrivateKeyB64,
        payload: {
          kind: "session-auth",
          challengeId,
          nonceB64,
          nodeKeyId,
          nodePublicKeyB64,
          relayKeyId,
          publicKeyB64: this.#identity.publicKeyB64,
          deviceId: normalizedDeviceId,
          wsPath: challengeWsPath,
        },
      });

      const authBody = { challengeId, signatureB64 };
      if (delegated) {
        authBody.signerPublicKeyB64 = this.#identity.deviceKey.publicKeyB64;
        authBody.certChain = this.#identity.certChain;
      }

      // Step 4: Send session.authenticate
      const readyResponse = await transport.sendRequest({
        type: SESSION_AUTHENTICATE_TYPE,
        body: authBody,
        expectedResponseType: this.#sessionHello.responseType || null,
        timeoutMs: 5000,
      });

      // Step 5: Store session info
      const readyType = String((readyResponse && readyResponse.t) || "");
      if (this.#sessionHello.responseType && readyType !== this.#sessionHello.responseType) {
        throw new AuthFailure(`unexpected ready type: ${readyType || "unknown"}`);
      }

      const readyBody = readyResponse && typeof readyResponse.body === "object" && readyResponse.body !== null
        ? readyResponse.body
        : {};
      this.#sessionInfo = {
        ...readyBody,
        // SESSION_AUTH_V5: the verified tuple the relay-contract floor keys on
        // — node identity proven by the challenge self-signature above.
        contractVersion: CONTRACT_VERSION,
        authMode: AUTH_MODES.ACCOUNT,
        nodeKeyId,
        nodePublicKeyB64,
        relayKeyId,
      };
      this.#transition(AUTH_STATES.AUTHENTICATED);
      this.#recordContractFloor({ nodePublicKeyB64, contractVersion: CONTRACT_VERSION });
      this.#eventBus.emit(SDK_EVENTS.AUTH_AUTHENTICATED, {
        publicKeyB64: this.#identity.publicKeyB64,
        deviceId: normalizedDeviceId,
        nodeKeyId,
        nodePublicKeyB64,
        relayKeyId,
      });

      return this.#sessionInfo;
    } catch (err) {
      this.#transition(AUTH_STATES.FAILED, { error: err && err.message });
      if (err instanceof AuthFailure) throw err;
      const failure = new AuthFailure((err && err.message) || "auth failed", { cause: err });
      // Carry the node's own error code forward. AuthFailure's `code` is fixed at
      // AUTH_FAILURE by contract, so without this the reason the node gave is
      // reduced to a message string — and callers that need to distinguish "wrong
      // credentials" from "this home structurally cannot serve you" are left
      // parsing prose (rez-node#2). Kept as a separate field so AuthFailure's
      // existing shape is unchanged.
      const serverCode = err && typeof err.code === "string" ? err.code.trim() : "";
      if (serverCode) failure.serverCode = serverCode;
      throw failure;
    }
  }

  /**
   * SESSION_AUTH_V5: claimant-mode handshake (contract 5). Proves possession
   * of ONE claimant key; carries no account identity and no deviceId (a
   * deviceId here would smuggle correlation metadata back into the
   * privacy-preserving path — the node rejects it as malformed). Both signed
   * payloads are domain-separated from the account kinds so signatures can
   * never be replayed across modes. Any failure is FINAL for this machine:
   * there is no account-mode retry path, by construction (Phase 0 §7).
   */
  async #authenticateClaimant(transport) {
    this.#sessionInfo = null;
    this.#transition(AUTH_STATES.UNAUTHENTICATED);
    const claimantPublicKeyB64 = this.#claimantIdentity.claimantPublicKeyB64;

    try {
      this.#transition(AUTH_STATES.HELLO_SENT);
      const helloResponse = await transport.sendRequest({
        type: this.#sessionHello.requestType,
        body: {
          contractVersion: 5,
          authMode: AUTH_MODES.CLAIMANT,
          clientName: "rez-sdk",
          clientVersion: this.#clientVersion,
          claimantPublicKeyB64,
        },
        expectedResponseType: null,
        timeoutMs: 5000,
      });

      const challenge = this.#parseAndValidateChallenge(helloResponse);

      const challengeVerified = await verifyPayload({
        publicKeyB64: challenge.nodePublicKeyB64,
        signatureB64: challenge.signatureB64,
        payload: {
          kind: "session-challenge-claimant",
          challengeId: challenge.challengeId,
          nonceB64: challenge.nonceB64,
          issuedAtMs: challenge.issuedAtMs,
          expiresAtMs: challenge.expiresAtMs,
          nodeKeyId: challenge.nodeKeyId,
          nodePublicKeyB64: challenge.nodePublicKeyB64,
          relayKeyId: challenge.relayKeyId,
          claimantPublicKeyB64,
          wsPath: challenge.wsPath,
        },
      });
      if (!challengeVerified) {
        throw new AuthFailure("session challenge signature did not verify");
      }

      this.#transition(AUTH_STATES.AUTHENTICATING);
      const signatureB64 = await signPayload({
        privateKeyB64: this.#claimantIdentity.privateKeyB64,
        payload: {
          kind: "session-auth-claimant",
          challengeId: challenge.challengeId,
          nonceB64: challenge.nonceB64,
          nodeKeyId: challenge.nodeKeyId,
          nodePublicKeyB64: challenge.nodePublicKeyB64,
          relayKeyId: challenge.relayKeyId,
          claimantPublicKeyB64,
          wsPath: challenge.wsPath,
        },
      });

      const readyResponse = await transport.sendRequest({
        type: SESSION_AUTHENTICATE_TYPE,
        body: { challengeId: challenge.challengeId, signatureB64 },
        expectedResponseType: this.#sessionHello.responseType || null,
        timeoutMs: 5000,
      });

      const readyType = String((readyResponse && readyResponse.t) || "");
      if (this.#sessionHello.responseType && readyType !== this.#sessionHello.responseType) {
        throw new AuthFailure(`unexpected ready type: ${readyType || "unknown"}`);
      }
      const readyBody = readyResponse && typeof readyResponse.body === "object" && readyResponse.body !== null
        ? readyResponse.body
        : {};
      this.#sessionInfo = {
        ...readyBody,
        contractVersion: 5,
        authMode: AUTH_MODES.CLAIMANT,
        nodeKeyId: challenge.nodeKeyId,
        nodePublicKeyB64: challenge.nodePublicKeyB64,
        relayKeyId: challenge.relayKeyId,
      };
      this.#transition(AUTH_STATES.AUTHENTICATED);
      this.#recordContractFloor({ nodePublicKeyB64: challenge.nodePublicKeyB64, contractVersion: 5 });
      this.#eventBus.emit(SDK_EVENTS.AUTH_AUTHENTICATED, {
        claimantPublicKeyB64,
        nodeKeyId: challenge.nodeKeyId,
        nodePublicKeyB64: challenge.nodePublicKeyB64,
        relayKeyId: challenge.relayKeyId,
      });
      return this.#sessionInfo;
    } catch (err) {
      // FINAL — never retried as account-mode by this machine or any code it calls.
      this.#transition(AUTH_STATES.FAILED, { error: err && err.message });
      if (err instanceof AuthFailure) throw err;
      const failure = new AuthFailure((err && err.message) || "auth failed", { cause: err });
      const serverCode = err && typeof err.code === "string" ? err.code.trim() : "";
      if (serverCode) failure.serverCode = serverCode;
      throw failure;
    }
  }

  async reauthenticate(transport) {
    return this.authenticate(transport);
  }

  reset() {
    this.#state = AUTH_STATES.UNAUTHENTICATED;
    this.#sessionInfo = null;
  }

  #transition(newState, detail = {}) {
    const prev = this.#state;
    this.#state = newState;
    this.#eventBus.emit(SDK_EVENTS.AUTH_STATE_CHANGED, { prev, state: newState, ...detail });
  }
}
