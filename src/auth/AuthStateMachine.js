import { SDK_EVENTS } from "../events/SdkEvents.js";
import { AuthFailure } from "../errors/index.js";
import { signPayload, verifyPayload } from "./signing.js";
import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";

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
  constructor({ identity, eventBus, sessionHello = {}, clientVersion = "rez-sdk/2.0", expectedNodePublicKeyB64 = "" } = {}) {
    if (!identity || !identity.publicKeyB64 || !identity.privateKeyB64) {
      throw new Error("AuthStateMachine requires identity with publicKeyB64 and privateKeyB64");
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

  async authenticate(transport) {
    this.#sessionInfo = null;
    this.#transition(AUTH_STATES.UNAUTHENTICATED);

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

      // Step 2: Expect session.challenge
      const responseType = String(helloResponse?.t || "");
      if (responseType !== SESSION_CHALLENGE_TYPE) {
        throw new AuthFailure(`unexpected response type: ${responseType || "unknown"}`);
      }

      this.#transition(AUTH_STATES.CHALLENGE_RECEIVED);
      const challengeBody = helloResponse && helloResponse.body && typeof helloResponse.body === "object"
        ? helloResponse.body
        : {};

      const challengeId = String(challengeBody.challengeId || "");
      const nonceB64 = String(challengeBody.nonceB64 || "");
      const nodeKeyId = String(challengeBody.nodeKeyId || "");
      const nodePublicKeyB64 = String(challengeBody.nodePublicKeyB64 || "");
      const relayKeyId = String(challengeBody.relayKeyId || "");
      const issuedAtMs = Number(challengeBody.issuedAtMs);
      const expiresAtMs = Number(challengeBody.expiresAtMs);
      const challengeWsPath = String(challengeBody.wsPath || "");
      const challengeSignatureB64 = String(challengeBody.signatureB64 || "");

      if (!challengeId || !nonceB64 || !nodeKeyId || !nodePublicKeyB64 || !relayKeyId
        || !Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs)
        || !challengeWsPath || !challengeSignatureB64) {
        throw new AuthFailure("session challenge incomplete");
      }
      if (Date.now() > expiresAtMs) {
        throw new AuthFailure("session challenge expired");
      }

      // CRITICAL-2 defense: if the SDK was configured with an expected node
      // pubkey, reject any challenge whose nodePublicKeyB64 doesn't match.
      // This prevents a MITM from relaying a different node's challenge.
      if (this.#expectedNodePublicKeyB64
        && this.#expectedNodePublicKeyB64 !== nodePublicKeyB64) {
        throw new AuthFailure(
          "session challenge from unexpected node — refusing to sign. "
          + "Configured expectedNodePublicKeyB64 does not match the challenge.",
        );
      }

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

      // Step 3: Sign the challenge with the SDK identity key.
      this.#transition(AUTH_STATES.AUTHENTICATING);

      const signatureB64 = await signPayload({
        privateKeyB64: this.#identity.privateKeyB64,
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

      // Step 4: Send session.authenticate
      const readyResponse = await transport.sendRequest({
        type: SESSION_AUTHENTICATE_TYPE,
        body: {
          challengeId,
          signatureB64,
        },
        expectedResponseType: this.#sessionHello.responseType || null,
        timeoutMs: 5000,
      });

      // Step 5: Store session info
      const readyType = String(readyResponse?.t || "");
      if (this.#sessionHello.responseType && readyType !== this.#sessionHello.responseType) {
        throw new AuthFailure(`unexpected ready type: ${readyType || "unknown"}`);
      }

      const readyBody = readyResponse && typeof readyResponse.body === "object" && readyResponse.body !== null
        ? readyResponse.body
        : {};
      this.#sessionInfo = {
        ...readyBody,
        nodeKeyId,
        nodePublicKeyB64,
        relayKeyId,
      };
      this.#transition(AUTH_STATES.AUTHENTICATED);
      this.#eventBus.emit(SDK_EVENTS.AUTH_AUTHENTICATED, {
        publicKeyB64: this.#identity.publicKeyB64,
        deviceId: normalizedDeviceId,
        nodeKeyId,
        nodePublicKeyB64,
        relayKeyId,
      });

      return this.#sessionInfo;
    } catch (err) {
      this.#transition(AUTH_STATES.FAILED, { error: err?.message });
      throw err instanceof AuthFailure ? err : new AuthFailure(err?.message || "auth failed", { cause: err });
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
