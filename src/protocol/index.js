import {
  toUint8Array,
  objectToBytes,
  bytesToObject,
  bytesToBase64,
} from "@rezprotocol/core";

export function encodeEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("encodeEnvelope(envelope) requires an object envelope");
  }
  return objectToBytes(envelope);
}

export function decodeEnvelope(bytes) {
  const parsed = bytesToObject(bytes);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("decodeEnvelope(bytes) produced a non-object envelope");
  }
  return parsed;
}

export function verifyEnvelope(envelopeOrBytes, context = {}) {
  const envelope =
    envelopeOrBytes instanceof Uint8Array ||
    envelopeOrBytes instanceof ArrayBuffer ||
    ArrayBuffer.isView(envelopeOrBytes)
      ? decodeEnvelope(envelopeOrBytes)
      : envelopeOrBytes;

  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("verifyEnvelope(envelope|bytes) requires an object envelope");
  }

  if (typeof context.verify === "function") {
    const ok = context.verify(envelope);
    if (!ok) throw new Error("Envelope verification failed");
  }

  return envelope;
}

export async function signEnvelope(envelope, keyRef) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("signEnvelope(envelope, keyRef) requires an object envelope");
  }
  if (!keyRef || typeof keyRef.sign !== "function") {
    throw new Error("signEnvelope(envelope, keyRef) requires keyRef.sign(bytes)");
  }

  const bytes = encodeEnvelope(envelope);
  const signature = await keyRef.sign(bytes);
  return {
    ...envelope,
    signature: bytesToBase64(toUint8Array(signature)),
  };
}

/**
 * Resolve the identity of an established session — inbox-first (SDK-2).
 *
 * There are two kinds of identity here and conflating them is the bug this
 * function used to contain:
 *
 * - **`localInboxId` is node-authenticated.** The node bound it at
 *   `inbox.claim` against the claimant key, and echoing it back is the node
 *   stating what it actually authenticated. Remote state, and legitimately so.
 * - **`accountId` and `deviceId` are LOCAL.** Per CAPABILITY_MODEL §8/§9 no
 *   account id crosses the wire to a node at all — the node cannot correlate
 *   inboxes to an account, which is a privacy primitive rather than a
 *   convenience. The SDK owns the `accountId → inboxes` mapping; a node has
 *   nothing to contribute to it.
 *
 * The old code read `sessionInfo.accountId` FIRST and fell back to the local
 * value, which inverted the ownership: it made a remote claim outrank local
 * truth. A node's `session.ready` carries no such field today
 * (`SessionReadyEvent` is `serverTime` + `capabilities`), so nothing was broken
 * in practice — but a node that simply added one would have had its claim
 * adopted as the session's account identity, reintroducing the correlation the
 * model exists to prevent, silently and with no local value to contradict it.
 *
 * So the remote value is never a SOURCE. It is only ever a cross-check, and
 * there are exactly two ways that check fails, both refused:
 *
 * - it disagrees with the account we authenticated as — someone is describing a
 *   different session than the one we opened;
 * - it appears when we hold no local account id at all — the adoption case, and
 *   the one the finding is really about.
 *
 * Agreement is permitted rather than rejected because not every caller of this
 * function is talking to a node: rez-chat hands it the session info of its own
 * runtime client, where `accountId` is the app echoing back the account it just
 * connected as. That is local truth wearing the same shape, and refusing it
 * would break a legitimate caller to defend against a field it owns.
 *
 * `deviceId` gets the same treatment for the same reason: the node's
 * `capabilities.deviceId` is an ECHO of what this client sent in `session.hello`.
 * A mismatch means the session is not the one we asked for, and is refused
 * rather than reconciled.
 *
 * @param {object} sessionInfo the node's `session.ready` body, or an equivalent
 *   session descriptor from a local runtime client
 * @param {{ accountId?: string, deviceId?: string }} fallback locally-held identity
 * @returns {{ accountId: string, deviceId: string, localInboxId: string|null }}
 */
export function resolveSessionIdentity(sessionInfo = {}, fallback = {}) {
  const info = sessionInfo && typeof sessionInfo === "object" ? sessionInfo : {};
  const featureMap = info.capabilities && typeof info.capabilities === "object" ? info.capabilities : null;

  const accountId = String(fallback.accountId || "").trim();
  const claimedAccountId = String(info.accountId || "").trim();
  if (claimedAccountId && claimedAccountId !== accountId) {
    const err = new Error(
      accountId
        ? "session identity claimed accountId '" + claimedAccountId + "' but this client authenticated as '"
          + accountId + "' — refusing a session bound to a different account."
        : "session identity asserted accountId '" + claimedAccountId + "' with no local account to check it "
          + "against — account identity is SDK-local and never node-authenticated (CAPABILITY_MODEL §8).",
    );
    err.code = "SESSION_ACCOUNT_MISMATCH";
    throw err;
  }

  const localDeviceId = String(fallback.deviceId || "").trim();
  const echoedDeviceId = String((featureMap && featureMap.deviceId) || "").trim();
  if (localDeviceId && echoedDeviceId && localDeviceId !== echoedDeviceId) {
    const err = new Error(
      "session.ready echoed deviceId '" + echoedDeviceId + "' but this client authenticated as '"
      + localDeviceId + "' — refusing a session bound to a different device.",
    );
    err.code = "SESSION_DEVICE_MISMATCH";
    throw err;
  }

  const localInboxId = String((featureMap && featureMap.localInboxId) || "").trim() || null;
  return { accountId, deviceId: localDeviceId || echoedDeviceId, localInboxId };
}
