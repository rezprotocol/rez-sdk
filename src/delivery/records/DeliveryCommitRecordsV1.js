import {
  Hash,
  RRecord,
  base64ToBytes,
  canonicalJSONStringify,
  requireCanonicalB64,
} from "@rezprotocol/core";
import {
  assertExactRecordKeys,
  canonicalRecordBytes,
  parseRecordBytes,
  requireSha256Hex,
} from "./recordShared.js";

export const DELIVERY_COMMIT_RECORD_VERSION = 1;
export const DELIVERY_REPLAY_STATES = Object.freeze(["ready-to-apply", "applied"]);

const SESSION_KEYS = Object.freeze([
  "recordVersion", "recordKey", "indexKey", "indexValue",
  "expectedSessionVersion", "nextSessionVersion", "nextSnapshotDigest",
  "nextSessionRecord",
]);
const PEER_LINK_KEYS = Object.freeze([
  "recordVersion", "peerLinkId", "recordKey", "pairIndexKey", "pairIndexValue",
  "expectedPeerLinkVersion", "nextPeerLinkVersion", "nextPeerLinkDigest",
  "nextPeerLinkRecord",
]);
const EVENT_INDEX_KEYS = Object.freeze([
  "recordVersion", "ownerAccountId", "peerLinkId", "eventId", "atMs", "seq",
]);
const EVENT_KEYS = Object.freeze([
  "recordVersion", "eventId", "recordKey", "entryKey", "eventRecord", "indexEntry",
]);
const WORK_KEYS = Object.freeze([
  "recordVersion", "owner", "sealedDigest", "laneId", "sessionId", "peerLinkId",
  "authenticatedSenderAccountId", "authenticatedSenderDeviceId", "sourceMailboxId", "sourceEventId",
  "plaintextB64", "createdAtMs",
]);
const REPLAY_KEYS = Object.freeze([
  "recordVersion", "owner", "sealedDigest", "state", "workKey", "createdAtMs", "updatedAtMs",
]);
const COMMIT_KEYS = Object.freeze([
  "recordVersion", "owner", "sealedDigest", "runtimeEpoch", "laneId", "commitGeneration",
  "sessionIntent", "peerLinkIntent", "lifecycleEventIntent", "work", "replayState", "createdAtMs",
]);

function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(label + " must be an object");
  }
  return JSON.parse(JSON.stringify(value));
}

function requireString(value, label) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(label + " must be a non-empty string");
  }
  return value.trim();
}

function requirePositiveInt(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(label + " must be a positive safe integer");
  }
  return value;
}

function requireNonNegativeInt(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(label + " must be a non-negative safe integer");
  }
  return value;
}

function nullableString(value, label) {
  if (value === null) return null;
  return requireString(value, label);
}

function canonicalDigest(value) {
  const plain = JSON.parse(JSON.stringify(value));
  return Hash.sha256Hex(new TextEncoder().encode(canonicalJSONStringify(plain)));
}

export class SessionCommitIntentV1 extends RRecord {
  static type = "sdk.delivery.session_commit_intent.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, SESSION_KEYS, "SessionCommitIntentV1");
    this.recordVersion = raw.recordVersion == null ? 1 : raw.recordVersion;
    this.recordKey = raw.recordKey;
    this.indexKey = raw.indexKey;
    this.indexValue = raw.indexValue;
    this.expectedSessionVersion = raw.expectedSessionVersion;
    this.nextSessionVersion = raw.nextSessionVersion;
    this.nextSnapshotDigest = raw.nextSnapshotDigest;
    this.nextSessionRecord = requireObject(raw.nextSessionRecord, "SessionCommitIntentV1.nextSessionRecord");
    this._seal();
  }

  validate() {
    this.assert(this.recordVersion === 1, "SessionCommitIntentV1.recordVersion must be 1");
    requireString(this.recordKey, "SessionCommitIntentV1.recordKey");
    requireString(this.indexKey, "SessionCommitIntentV1.indexKey");
    requireString(this.indexValue, "SessionCommitIntentV1.indexValue");
    requireNonNegativeInt(this.expectedSessionVersion, "SessionCommitIntentV1.expectedSessionVersion");
    requirePositiveInt(this.nextSessionVersion, "SessionCommitIntentV1.nextSessionVersion");
    this.assert(this.nextSessionVersion === this.expectedSessionVersion + 1,
      "SessionCommitIntentV1.nextSessionVersion must equal expectedSessionVersion + 1");
    requireSha256Hex(this.nextSnapshotDigest, "SessionCommitIntentV1.nextSnapshotDigest");
    this.assert(canonicalDigest(this.nextSessionRecord) === this.nextSnapshotDigest,
      "SessionCommitIntentV1.nextSnapshotDigest must authenticate nextSessionRecord");
    this.assert(this.nextSessionRecord.version === this.nextSessionVersion,
      "SessionCommitIntentV1.nextSessionRecord.version must equal nextSessionVersion");
  }
}

export class PeerLinkTransitionIntentV1 extends RRecord {
  static type = "sdk.delivery.peer_link_transition_intent.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, PEER_LINK_KEYS, "PeerLinkTransitionIntentV1");
    this.recordVersion = raw.recordVersion == null ? 1 : raw.recordVersion;
    this.peerLinkId = raw.peerLinkId;
    this.recordKey = raw.recordKey;
    this.pairIndexKey = raw.pairIndexKey;
    this.pairIndexValue = raw.pairIndexValue;
    this.expectedPeerLinkVersion = raw.expectedPeerLinkVersion;
    this.nextPeerLinkVersion = raw.nextPeerLinkVersion;
    this.nextPeerLinkDigest = raw.nextPeerLinkDigest;
    this.nextPeerLinkRecord = requireObject(raw.nextPeerLinkRecord, "PeerLinkTransitionIntentV1.nextPeerLinkRecord");
    this._seal();
  }

  validate() {
    this.assert(this.recordVersion === 1, "PeerLinkTransitionIntentV1.recordVersion must be 1");
    requireString(this.peerLinkId, "PeerLinkTransitionIntentV1.peerLinkId");
    requireString(this.recordKey, "PeerLinkTransitionIntentV1.recordKey");
    requireString(this.pairIndexKey, "PeerLinkTransitionIntentV1.pairIndexKey");
    requireString(this.pairIndexValue, "PeerLinkTransitionIntentV1.pairIndexValue");
    requirePositiveInt(this.expectedPeerLinkVersion, "PeerLinkTransitionIntentV1.expectedPeerLinkVersion");
    requirePositiveInt(this.nextPeerLinkVersion, "PeerLinkTransitionIntentV1.nextPeerLinkVersion");
    this.assert(this.nextPeerLinkVersion === this.expectedPeerLinkVersion + 1,
      "PeerLinkTransitionIntentV1.nextPeerLinkVersion must equal expectedPeerLinkVersion + 1");
    requireSha256Hex(this.nextPeerLinkDigest, "PeerLinkTransitionIntentV1.nextPeerLinkDigest");
    this.assert(canonicalDigest(this.nextPeerLinkRecord) === this.nextPeerLinkDigest,
      "PeerLinkTransitionIntentV1.nextPeerLinkDigest must authenticate nextPeerLinkRecord");
    this.assert(this.nextPeerLinkRecord.version === this.nextPeerLinkVersion,
      "PeerLinkTransitionIntentV1.nextPeerLinkRecord.version must equal nextPeerLinkVersion");
  }
}

export class PeerLinkEventIndexEntryV1 extends RRecord {
  static type = "sdk.delivery.peer_link_event_index_entry.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, EVENT_INDEX_KEYS, "PeerLinkEventIndexEntryV1");
    this.recordVersion = raw.recordVersion == null ? 1 : raw.recordVersion;
    this.ownerAccountId = raw.ownerAccountId;
    this.peerLinkId = raw.peerLinkId;
    this.eventId = raw.eventId;
    this.atMs = raw.atMs;
    this.seq = raw.seq;
    this._seal();
  }

  validate() {
    this.assert(this.recordVersion === 1, "PeerLinkEventIndexEntryV1.recordVersion must be 1");
    requireString(this.ownerAccountId, "PeerLinkEventIndexEntryV1.ownerAccountId");
    requireString(this.peerLinkId, "PeerLinkEventIndexEntryV1.peerLinkId");
    requireString(this.eventId, "PeerLinkEventIndexEntryV1.eventId");
    requirePositiveInt(this.atMs, "PeerLinkEventIndexEntryV1.atMs");
    requireNonNegativeInt(this.seq, "PeerLinkEventIndexEntryV1.seq");
  }
}

export class LifecycleEventIntentV1 extends RRecord {
  static type = "sdk.delivery.lifecycle_event_intent.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, EVENT_KEYS, "LifecycleEventIntentV1");
    this.recordVersion = raw.recordVersion == null ? 1 : raw.recordVersion;
    this.eventId = raw.eventId;
    this.recordKey = raw.recordKey;
    this.entryKey = raw.entryKey;
    this.eventRecord = requireObject(raw.eventRecord, "LifecycleEventIntentV1.eventRecord");
    this.indexEntry = raw.indexEntry instanceof PeerLinkEventIndexEntryV1
      ? raw.indexEntry
      : new PeerLinkEventIndexEntryV1(raw.indexEntry);
    this._seal();
  }

  validate() {
    this.assert(this.recordVersion === 1, "LifecycleEventIntentV1.recordVersion must be 1");
    requireString(this.eventId, "LifecycleEventIntentV1.eventId");
    requireString(this.recordKey, "LifecycleEventIntentV1.recordKey");
    requireString(this.entryKey, "LifecycleEventIntentV1.entryKey");
    this.assert(this.eventRecord.eventId === this.eventId,
      "LifecycleEventIntentV1.eventRecord.eventId must match eventId");
    this.assert(this.indexEntry.eventId === this.eventId,
      "LifecycleEventIntentV1.indexEntry.eventId must match eventId");
  }

  toJSON() {
    return {
      ...super.toJSON(),
      indexEntry: this.indexEntry.toJSON(),
    };
  }
}

export class DecryptedDeliveryWorkV1 extends RRecord {
  static type = "sdk.delivery.decrypted_work.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, WORK_KEYS, "DecryptedDeliveryWorkV1");
    this.recordVersion = raw.recordVersion == null ? 1 : raw.recordVersion;
    this.owner = raw.owner;
    this.sealedDigest = raw.sealedDigest;
    this.laneId = raw.laneId;
    this.sessionId = raw.sessionId;
    this.peerLinkId = raw.peerLinkId;
    this.authenticatedSenderAccountId = raw.authenticatedSenderAccountId;
    this.authenticatedSenderDeviceId = raw.authenticatedSenderDeviceId == null ? null : raw.authenticatedSenderDeviceId;
    this.sourceMailboxId = raw.sourceMailboxId == null ? null : raw.sourceMailboxId;
    this.sourceEventId = raw.sourceEventId == null ? null : raw.sourceEventId;
    this.plaintextB64 = raw.plaintextB64;
    this.createdAtMs = raw.createdAtMs;
    this._seal();
  }

  validate() {
    this.assert(this.recordVersion === 1, "DecryptedDeliveryWorkV1.recordVersion must be 1");
    requireString(this.owner, "DecryptedDeliveryWorkV1.owner");
    requireSha256Hex(this.sealedDigest, "DecryptedDeliveryWorkV1.sealedDigest");
    requireString(this.laneId, "DecryptedDeliveryWorkV1.laneId");
    requireString(this.sessionId, "DecryptedDeliveryWorkV1.sessionId");
    requireString(this.peerLinkId, "DecryptedDeliveryWorkV1.peerLinkId");
    requireString(this.authenticatedSenderAccountId, "DecryptedDeliveryWorkV1.authenticatedSenderAccountId");
    nullableString(this.authenticatedSenderDeviceId, "DecryptedDeliveryWorkV1.authenticatedSenderDeviceId");
    nullableString(this.sourceMailboxId, "DecryptedDeliveryWorkV1.sourceMailboxId");
    nullableString(this.sourceEventId, "DecryptedDeliveryWorkV1.sourceEventId");
    requireCanonicalB64(this.plaintextB64, "DecryptedDeliveryWorkV1.plaintextB64");
    this.assert(base64ToBytes(this.plaintextB64).length > 0,
      "DecryptedDeliveryWorkV1.plaintextB64 must decode to non-empty bytes");
    requirePositiveInt(this.createdAtMs, "DecryptedDeliveryWorkV1.createdAtMs");
  }
}

export class ReplayIdentityRecordV1 extends RRecord {
  static type = "sdk.delivery.replay_identity.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, REPLAY_KEYS, "ReplayIdentityRecordV1");
    this.recordVersion = raw.recordVersion == null ? 1 : raw.recordVersion;
    this.owner = raw.owner;
    this.sealedDigest = raw.sealedDigest;
    this.state = raw.state;
    this.workKey = raw.workKey;
    this.createdAtMs = raw.createdAtMs;
    this.updatedAtMs = raw.updatedAtMs;
    this._seal();
  }

  validate() {
    this.assert(this.recordVersion === 1, "ReplayIdentityRecordV1.recordVersion must be 1");
    requireString(this.owner, "ReplayIdentityRecordV1.owner");
    requireSha256Hex(this.sealedDigest, "ReplayIdentityRecordV1.sealedDigest");
    this.assert(DELIVERY_REPLAY_STATES.includes(this.state), "ReplayIdentityRecordV1.state is unsupported");
    requireString(this.workKey, "ReplayIdentityRecordV1.workKey");
    requirePositiveInt(this.createdAtMs, "ReplayIdentityRecordV1.createdAtMs");
    requirePositiveInt(this.updatedAtMs, "ReplayIdentityRecordV1.updatedAtMs");
  }
}

export class DeliveryCommitRecordV1 extends RRecord {
  static type = "sdk.delivery.commit_record.v1";

  constructor(raw = {}) {
    super();
    assertExactRecordKeys(raw, COMMIT_KEYS, "DeliveryCommitRecordV1");
    this.recordVersion = raw.recordVersion == null ? DELIVERY_COMMIT_RECORD_VERSION : raw.recordVersion;
    this.owner = raw.owner;
    this.sealedDigest = raw.sealedDigest;
    this.runtimeEpoch = raw.runtimeEpoch;
    this.laneId = raw.laneId;
    this.commitGeneration = raw.commitGeneration;
    this.sessionIntent = raw.sessionIntent instanceof SessionCommitIntentV1
      ? raw.sessionIntent
      : new SessionCommitIntentV1(raw.sessionIntent);
    this.peerLinkIntent = raw.peerLinkIntent == null
      ? null
      : (raw.peerLinkIntent instanceof PeerLinkTransitionIntentV1
          ? raw.peerLinkIntent
          : new PeerLinkTransitionIntentV1(raw.peerLinkIntent));
    this.lifecycleEventIntent = raw.lifecycleEventIntent == null
      ? null
      : (raw.lifecycleEventIntent instanceof LifecycleEventIntentV1
          ? raw.lifecycleEventIntent
          : new LifecycleEventIntentV1(raw.lifecycleEventIntent));
    this.work = raw.work instanceof DecryptedDeliveryWorkV1
      ? raw.work
      : new DecryptedDeliveryWorkV1(raw.work);
    this.replayState = raw.replayState;
    this.createdAtMs = raw.createdAtMs;
    this._seal();
  }

  validate() {
    this.assert(this.recordVersion === DELIVERY_COMMIT_RECORD_VERSION,
      "DeliveryCommitRecordV1.recordVersion must be 1");
    requireString(this.owner, "DeliveryCommitRecordV1.owner");
    requireSha256Hex(this.sealedDigest, "DeliveryCommitRecordV1.sealedDigest");
    requirePositiveInt(this.runtimeEpoch, "DeliveryCommitRecordV1.runtimeEpoch");
    requireString(this.laneId, "DeliveryCommitRecordV1.laneId");
    requirePositiveInt(this.commitGeneration, "DeliveryCommitRecordV1.commitGeneration");
    this.assert(this.replayState === "ready-to-apply",
      "DeliveryCommitRecordV1.replayState must be ready-to-apply");
    requirePositiveInt(this.createdAtMs, "DeliveryCommitRecordV1.createdAtMs");
    this.assert(this.work.owner === this.owner, "DeliveryCommitRecordV1.work.owner must match owner");
    this.assert(this.work.sealedDigest === this.sealedDigest,
      "DeliveryCommitRecordV1.work.sealedDigest must match sealedDigest");
    this.assert(this.work.laneId === this.laneId, "DeliveryCommitRecordV1.work.laneId must match laneId");
    const session = this.sessionIntent.nextSessionRecord;
    const sessionDeviceId = typeof session.peerDeviceId === "string" && session.peerDeviceId.length > 0
      ? session.peerDeviceId : null;
    this.assert(this.laneId === "ratchet:" + this.work.sessionId,
      "DeliveryCommitRecordV1.laneId must bind the work session");
    this.assert(session.localAccountId === this.owner,
      "DeliveryCommitRecordV1 session owner must match owner");
    this.assert(session.sessionId === this.work.sessionId,
      "DeliveryCommitRecordV1 sessionId must match work");
    this.assert(session.peerLinkId === this.work.peerLinkId,
      "DeliveryCommitRecordV1 session peerLinkId must match work");
    this.assert(session.peerAccountId === this.work.authenticatedSenderAccountId,
      "DeliveryCommitRecordV1 session peerAccountId must match authenticated sender");
    this.assert(sessionDeviceId === this.work.authenticatedSenderDeviceId,
      "DeliveryCommitRecordV1 session peerDeviceId must match authenticated sender device");
    this.assert(this.sessionIntent.recordKey === "peer-link:sessions:" + this.owner + "::" + this.work.sessionId,
      "DeliveryCommitRecordV1 session recordKey is not canonical");
    const expectedSessionIndexKey = sessionDeviceId
      ? "peer-link:sessions:by-peer-link-device:" + this.owner + "::" + this.work.peerLinkId + "::" + sessionDeviceId
      : "peer-link:sessions:by-peer-link:" + this.owner + "::" + this.work.peerLinkId;
    this.assert(this.sessionIntent.indexKey === expectedSessionIndexKey,
      "DeliveryCommitRecordV1 session indexKey is not canonical");
    this.assert(this.sessionIntent.indexValue === this.work.sessionId,
      "DeliveryCommitRecordV1 session indexValue must match sessionId");
    this.assert((this.peerLinkIntent === null) === (this.lifecycleEventIntent === null),
      "DeliveryCommitRecordV1 peerLinkIntent and lifecycleEventIntent must both be present or both be null");
    if (this.peerLinkIntent) {
      const peer = this.peerLinkIntent.nextPeerLinkRecord;
      this.assert(this.peerLinkIntent.peerLinkId === this.work.peerLinkId && peer.peerLinkId === this.work.peerLinkId,
        "DeliveryCommitRecordV1 peer-link identity must match work");
      this.assert(peer.localAccountId === this.owner && peer.peerAccountId === this.work.authenticatedSenderAccountId,
        "DeliveryCommitRecordV1 peer-link accounts must match work authority");
      this.assert(this.peerLinkIntent.recordKey === "peer-link:records:" + this.owner + "::" + this.work.peerLinkId,
        "DeliveryCommitRecordV1 peer-link recordKey is not canonical");
      this.assert(this.peerLinkIntent.pairIndexKey === "peer-link:pairs:" + this.owner + "::" + peer.peerAccountId,
        "DeliveryCommitRecordV1 peer-link pairIndexKey is not canonical");
      this.assert(this.peerLinkIntent.pairIndexValue === this.work.peerLinkId,
        "DeliveryCommitRecordV1 peer-link pairIndexValue must match peerLinkId");
    }
    if (this.lifecycleEventIntent) {
      const event = this.lifecycleEventIntent;
      this.assert(event.eventRecord.ownerAccountId === this.owner
          && event.eventRecord.peerLinkId === this.work.peerLinkId,
      "DeliveryCommitRecordV1 event scope must match work");
      this.assert(event.recordKey === "peer-link:events:" + this.owner + "::" + event.eventId,
        "DeliveryCommitRecordV1 event recordKey is not canonical");
      this.assert(event.entryKey === "peer-link:events-index:" + this.owner + "::" + this.work.peerLinkId + "::" + event.eventId,
        "DeliveryCommitRecordV1 event entryKey is not canonical");
      this.assert(event.indexEntry.ownerAccountId === this.owner
          && event.indexEntry.peerLinkId === this.work.peerLinkId,
      "DeliveryCommitRecordV1 event index scope must match work");
    }
  }

  toJSON() {
    return {
      ...super.toJSON(),
      sessionIntent: this.sessionIntent.toJSON(),
      peerLinkIntent: this.peerLinkIntent === null ? null : this.peerLinkIntent.toJSON(),
      lifecycleEventIntent: this.lifecycleEventIntent === null ? null : this.lifecycleEventIntent.toJSON(),
      work: this.work.toJSON(),
    };
  }

  toBytes() {
    return canonicalRecordBytes(this);
  }

  static fromBytes(bytes) {
    return DeliveryCommitRecordV1.fromJSON(parseRecordBytes(bytes, "DeliveryCommitRecordV1"));
  }
}
