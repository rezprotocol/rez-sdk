import {
  Hash,
  bytesToBase64,
  canonicalJSONStringify,
} from "@rezprotocol/core";
import {
  DeliveryCommitRecordV1,
  DecryptedDeliveryWorkV1,
  ReplayIdentityRecordV1,
} from "./records/DeliveryCommitRecordsV1.js";

export const DELIVERY_COMMIT_PREFIX = "sdk:delivery:commit:v1:";
export const DELIVERY_REPLAY_PREFIX = "sdk:delivery:replay:v1:";
export const DELIVERY_WORK_PREFIX = "sdk:delivery:work:v1:";

const WRITE_ATTEMPTS = 2;

function requireString(value, label) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(label + " must be a non-empty string");
  }
  return value.trim();
}

function toPlain(value) {
  return JSON.parse(JSON.stringify(value));
}

function canonicalDigest(value) {
  return Hash.sha256Hex(new TextEncoder().encode(canonicalJSONStringify(toPlain(value))));
}

function base64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function digestComponent(hex) {
  if (typeof hex !== "string" || !/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error("sealedDigest must be 64 lowercase hex characters");
  }
  const bytes = new Uint8Array(32);
  for (let index = 0; index < 32; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return base64Url(bytes);
}

export class DeliveryCommitFatalError extends Error {
  constructor({ message, scope, key = null, laneId = null, owner = null, cause = null } = {}) {
    super(String(message || "delivery commit recovery failed"), cause ? { cause } : undefined);
    this.name = "DeliveryCommitFatalError";
    this.code = "DELIVERY_COMMIT_FATAL";
    this.scope = scope === "lane" || scope === "owner" ? scope : "store";
    this.key = key;
    this.laneId = laneId;
    this.owner = owner;
  }
}

/**
 * Single-record receive commit WAL.
 *
 * The WAL value is the only commit point. Canonical session, peer-link, event,
 * replay, and work keys are deterministic roll-forward projections. No
 * projection is trusted merely because a sibling key exists; each one is
 * verified and repaired independently before the WAL is compacted.
 */
export class DeliveryCommitStore {
  #kv;
  #clock;
  #runtimeEpoch;
  #quarantinedLanes = new Map();
  #ownerFatal = new Map();
  #storeFatal = null;
  #assertOwnership = null;
  #pruneTicks = new Map();
  #prunePromises = new Map();

  constructor({ keyValueStore, clock = () => Date.now(), runtimeEpoch = null } = {}) {
    if (!keyValueStore || typeof keyValueStore.set !== "function"
        || typeof keyValueStore.getStrict !== "function"
        || typeof keyValueStore.delete !== "function"
        || typeof keyValueStore.keys !== "function") {
      throw new Error("DeliveryCommitStore requires KeyValueStore set/getStrict/delete/keys");
    }
    if (typeof clock !== "function") throw new Error("DeliveryCommitStore requires clock");
    if (runtimeEpoch !== null && (!Number.isSafeInteger(runtimeEpoch) || runtimeEpoch < 1)) {
      throw new Error("DeliveryCommitStore runtimeEpoch must be a positive safe integer");
    }
    this.#kv = keyValueStore;
    this.#clock = clock;
    this.#runtimeEpoch = runtimeEpoch;
  }

  get runtimeEpoch() {
    if (this.#runtimeEpoch === null) throw new Error("DeliveryCommitStore runtime ownership is not active");
    return this.#runtimeEpoch;
  }

  activateRuntimeEpoch(runtimeEpoch, assertOwnership = null) {
    this.#assertOwnership = assertOwnership;
    if (!Number.isSafeInteger(runtimeEpoch) || runtimeEpoch < 1) {
      throw new Error("DeliveryCommitStore runtimeEpoch must be a positive safe integer");
    }
    if (this.#runtimeEpoch !== null && this.#runtimeEpoch !== runtimeEpoch) {
      throw new Error("DeliveryCommitStore runtime epoch is already active");
    }
    this.#runtimeEpoch = runtimeEpoch;
    return runtimeEpoch;
  }

  static sealedDigest(packetBytes) {
    if (!(packetBytes instanceof Uint8Array) || packetBytes.length === 0) {
      throw new Error("DeliveryCommitStore.sealedDigest requires non-empty Uint8Array");
    }
    return Hash.sha256Hex(packetBytes);
  }

  static ownerHash(owner) {
    const normalized = requireString(owner, "owner");
    return base64Url(Hash.sha256(new TextEncoder().encode(normalized)));
  }

  static commitKey(owner, sealedDigest) {
    return DELIVERY_COMMIT_PREFIX + DeliveryCommitStore.ownerHash(owner) + ":" + digestComponent(sealedDigest);
  }

  static replayKey(owner, sealedDigest) {
    return DELIVERY_REPLAY_PREFIX + DeliveryCommitStore.ownerHash(owner) + ":" + digestComponent(sealedDigest);
  }

  static workKey(owner, sealedDigest) {
    return DELIVERY_WORK_PREFIX + DeliveryCommitStore.ownerHash(owner) + ":" + digestComponent(sealedDigest);
  }

  static canonicalDigest(value) {
    return canonicalDigest(value);
  }

  assertAvailable(owner, laneId) {
    const normalizedOwner = this.#assertOwnerAvailable(owner);
    const normalizedLane = requireString(laneId, "laneId");
    const laneErr = this.#quarantinedLanes.get(normalizedOwner + "::" + normalizedLane);
    if (laneErr) throw laneErr;
  }

  async lookup(owner, sealedDigest) {
    this.#assertOwnerAvailable(owner);
    const replayKey = DeliveryCommitStore.replayKey(owner, sealedDigest);
    const replayRaw = await this.#strict(replayKey, { scope: "owner", owner });
    if (replayRaw === undefined) return null;
    let replay;
    try {
      replay = ReplayIdentityRecordV1.fromJSON(replayRaw);
    } catch (err) {
      throw this.#fatal({ message: "unreadable replay identity", scope: "owner", owner, key: replayKey, cause: err });
    }
    if (replay.owner !== owner || replay.sealedDigest !== sealedDigest
        || replay.workKey !== DeliveryCommitStore.workKey(owner, sealedDigest)) {
      throw this.#fatal({ message: "replay identity key/content mismatch", scope: "store", key: replayKey });
    }
    const workRaw = await this.#strict(replay.workKey, { scope: "owner", owner });
    if (workRaw === undefined) return { replay, work: null };
    let work;
    try {
      work = DecryptedDeliveryWorkV1.fromJSON(workRaw);
    } catch (err) {
      throw this.#fatal({ message: "unreadable decrypted work", scope: "owner", owner, key: replay.workKey, cause: err });
    }
    if (work.owner !== owner || work.sealedDigest !== sealedDigest) {
      throw this.#fatal({ message: "decrypted work key/content mismatch", scope: "store", key: replay.workKey });
    }
    return { replay, work };
  }

  async commitAndRollForward(input) {
    const record = input instanceof DeliveryCommitRecordV1 ? input : new DeliveryCommitRecordV1(input);
    this.assertAvailable(record.owner, record.laneId);
    if (record.runtimeEpoch !== this.#runtimeEpoch) {
      throw this.#fatal({
        message: "delivery commit runtime epoch does not match current grant",
        scope: "owner",
        owner: record.owner,
        laneId: record.laneId,
      });
    }
    const key = DeliveryCommitStore.commitKey(record.owner, record.sealedDigest);
    const existing = await this.lookup(record.owner, record.sealedDigest);
    if (existing) {
      if (existing.replay.state === "applied") return null;
      if (existing.work) return existing.work;
      const pendingRaw = await this.#strict(key, { scope: "owner", owner: record.owner });
      if (pendingRaw === undefined) {
        throw this.#fatal({
          message: "ready replay identity has neither work nor recoverable commit",
          scope: "owner",
          owner: record.owner,
          key: existing.replay.workKey,
        });
      }
      let pending;
      try {
        pending = DeliveryCommitRecordV1.fromJSON(pendingRaw);
      } catch (err) {
        throw this.#fatal({ message: "invalid delivery commit record", scope: "owner", owner: record.owner, key, cause: err });
      }
      if (DeliveryCommitStore.commitKey(pending.owner, pending.sealedDigest) !== key) {
        throw this.#fatal({ message: "delivery commit key/content mismatch", scope: "store", key });
      }
      await this.#rollForward(key, pending);
      const recovered = await this.lookup(record.owner, record.sealedDigest);
      if (!recovered || !recovered.work) {
        throw this.#fatal({
          message: "delivery commit recovery did not restore ready work",
          scope: "owner",
          owner: record.owner,
          key: existing.replay.workKey,
        });
      }
      return recovered.work;
    }

    // A compacted replay identity must never allow a stale receive intent to
    // recreate applied plaintext. Recovery of an existing WAL remains separate.
    const current = await this.#strict(record.sessionIntent.recordKey, { scope: "lane", owner: record.owner, laneId: record.laneId });
    const currentVersion = current === undefined ? 0 : Number(current.version);
    if (currentVersion !== record.sessionIntent.expectedSessionVersion) {
      throw this.#fatal({ message: "new delivery commit does not extend the current session version", scope: "lane", owner: record.owner, laneId: record.laneId });
    }
    await this.#writeCommit(key, record);
    await this.#rollForward(key, record);
    return record.work;
  }

  async recoverOwner(owner) {
    const normalizedOwner = requireString(owner, "owner");
    this.#assertOwnerAvailable(normalizedOwner);
    const prefix = DELIVERY_COMMIT_PREFIX + DeliveryCommitStore.ownerHash(normalizedOwner) + ":";
    let keys;
    try {
      keys = await this.#kv.keys(prefix);
    } catch (err) {
      throw this.#fatal({ message: "delivery commit enumeration failed", scope: "owner", owner: normalizedOwner, cause: err });
    }
    const records = [];
    for (const key of keys) {
      let raw;
      try {
        raw = await this.#kv.getStrict(key);
      } catch (err) {
        throw this.#fatal({ message: "unreadable delivery commit record", scope: "owner", owner: normalizedOwner, key, cause: err });
      }
      if (raw === undefined) {
        throw this.#fatal({ message: "delivery commit disappeared after enumeration", scope: "owner", owner: normalizedOwner, key });
      }
      let record;
      try {
        record = DeliveryCommitRecordV1.fromJSON(raw);
      } catch (err) {
        throw this.#fatal({ message: "invalid delivery commit record", scope: "owner", owner: normalizedOwner, key, cause: err });
      }
      if (record.owner !== normalizedOwner || DeliveryCommitStore.commitKey(record.owner, record.sealedDigest) !== key) {
        throw this.#fatal({ message: "delivery commit key/content mismatch", scope: "store", key });
      }
      if (record.runtimeEpoch > this.#runtimeEpoch) {
        throw this.#fatal({ message: "delivery commit bears a future runtime epoch", scope: "owner", owner: normalizedOwner, key });
      }
      records.push({ key, record });
    }
    records.sort((left, right) => {
      const laneOrder = left.record.laneId.localeCompare(right.record.laneId);
      if (laneOrder !== 0) return laneOrder;
      return left.record.commitGeneration - right.record.commitGeneration;
    });
    for (const row of records) {
      try {
        this.assertAvailable(row.record.owner, row.record.laneId);
        await this.#rollForward(row.key, row.record);
      } catch (err) {
        // A readable WAL gives us a trustworthy lane identity. Preserve the
        // commit and quarantine only that lane, then continue recovering the
        // owner's independent lanes. Owner/store failures remain terminal.
        if (!(err instanceof DeliveryCommitFatalError) || err.scope !== "lane") {
          throw err;
        }
      }
    }
    await this.pruneAppliedReplay(normalizedOwner);
    return records.length;
  }

  async listPendingWork(owner) {
    const normalizedOwner = requireString(owner, "owner");
    this.#assertOwnerAvailable(normalizedOwner);
    const prefix = DELIVERY_WORK_PREFIX + DeliveryCommitStore.ownerHash(normalizedOwner) + ":";
    let keys;
    try {
      keys = await this.#kv.keys(prefix);
    } catch (err) {
      throw this.#fatal({ message: "decrypted work enumeration failed", scope: "owner", owner: normalizedOwner, cause: err });
    }
    const work = [];
    for (const key of keys) {
      const raw = await this.#strict(key, { scope: "owner", owner: normalizedOwner });
      if (raw === undefined) {
        throw this.#fatal({ message: "decrypted work disappeared after enumeration", scope: "owner", owner: normalizedOwner, key });
      }
      let record;
      try {
        record = DecryptedDeliveryWorkV1.fromJSON(raw);
      } catch (err) {
        throw this.#fatal({ message: "invalid decrypted work record", scope: "owner", owner: normalizedOwner, key, cause: err });
      }
      if (record.owner !== normalizedOwner || DeliveryCommitStore.workKey(record.owner, record.sealedDigest) !== key) {
        throw this.#fatal({ message: "decrypted work key/content mismatch", scope: "store", key });
      }
      const replayKey = DeliveryCommitStore.replayKey(normalizedOwner, record.sealedDigest);
      const replayRaw = await this.#strict(replayKey, { scope: "owner", owner: normalizedOwner });
      if (replayRaw === undefined) {
        throw this.#fatal({ message: "decrypted work has no replay identity", scope: "owner", owner: normalizedOwner, key });
      }
      let replay;
      try {
        replay = ReplayIdentityRecordV1.fromJSON(replayRaw);
      } catch (err) {
        throw this.#fatal({ message: "invalid replay identity", scope: "owner", owner: normalizedOwner, key: replayKey, cause: err });
      }
      if (replay.owner !== normalizedOwner || replay.sealedDigest !== record.sealedDigest || replay.workKey !== key) {
        throw this.#fatal({ message: "replay identity key/content mismatch", scope: "store", key: replayKey });
      }
      if (replay.state === "applied") {
        await this.#deleteAndVerify(key, { scope: "owner", owner: normalizedOwner });
        continue;
      }
      work.push(record);
    }
    work.sort((left, right) => left.createdAtMs - right.createdAtMs || left.sealedDigest.localeCompare(right.sealedDigest));
    return work;
  }

  async markApplied(owner, sealedDigest) {
    const normalizedOwner = requireString(owner, "owner");
    this.#assertOwnerAvailable(normalizedOwner);
    const replayKey = DeliveryCommitStore.replayKey(normalizedOwner, sealedDigest);
    const workKey = DeliveryCommitStore.workKey(normalizedOwner, sealedDigest);
    const raw = await this.#strict(replayKey, { scope: "owner", owner: normalizedOwner });
    if (raw === undefined) {
      throw this.#fatal({ message: "cannot apply delivery work without replay identity", scope: "owner", owner: normalizedOwner, key: replayKey });
    }
    let replay;
    try {
      replay = ReplayIdentityRecordV1.fromJSON(raw);
    } catch (err) {
      throw this.#fatal({ message: "invalid replay identity", scope: "owner", owner: normalizedOwner, key: replayKey, cause: err });
    }
    if (replay.owner !== normalizedOwner || replay.sealedDigest !== sealedDigest || replay.workKey !== workKey) {
      throw this.#fatal({ message: "replay identity key/content mismatch", scope: "store", key: replayKey });
    }
    const applied = new ReplayIdentityRecordV1({
      ...replay.toJSON(),
      state: "applied",
      updatedAtMs: this.#clock(),
    });
    await this.#setAndVerify(replayKey, applied, (value) => {
      const decoded = ReplayIdentityRecordV1.fromJSON(value);
      return decoded.state === "applied" && decoded.sealedDigest === sealedDigest;
    }, { scope: "owner", owner: normalizedOwner });
    await this.#deleteAndVerify(workKey, { scope: "owner", owner: normalizedOwner });
    const tick = (this.#pruneTicks.get(normalizedOwner) || 0) + 1;
    this.#pruneTicks.set(normalizedOwner, tick);
    if (tick === 1 || tick % 64 === 0) await this.pruneAppliedReplay(normalizedOwner);
  }

  /** Bound applied replay markers; pending plaintext and WAL always win. */
  async pruneAppliedReplay(owner, { nowMs = this.#clock(), retentionMs = 7 * 24 * 60 * 60 * 1000, maxRecords = 10000 } = {}) {
    const normalizedOwner = requireString(owner, "owner");
    this.#assertOwnerAvailable(normalizedOwner);
    if (!Number.isFinite(nowMs) || !Number.isFinite(retentionMs) || retentionMs < 0
        || !Number.isSafeInteger(maxRecords) || maxRecords < 0) throw new Error("invalid replay retention policy");
    const existing = this.#prunePromises.get(normalizedOwner);
    if (existing) return existing;
    const pending = (async () => {
      const scope = { scope: "owner", owner: normalizedOwner };
      const rows = [];
      for (const key of await this.#kv.keys(DELIVERY_REPLAY_PREFIX + DeliveryCommitStore.ownerHash(normalizedOwner) + ":")) {
        const raw = await this.#strict(key, scope);
        if (raw === undefined) continue;
        let record;
        try { record = ReplayIdentityRecordV1.fromJSON(raw); } catch (err) {
          throw this.#fatal({ ...scope, key, message: "invalid replay identity during pruning", cause: err });
        }
        if (record.owner !== normalizedOwner || DeliveryCommitStore.replayKey(record.owner, record.sealedDigest) !== key
            || DeliveryCommitStore.workKey(record.owner, record.sealedDigest) !== record.workKey) {
          throw this.#fatal({ ...scope, key, message: "replay identity key/content mismatch during pruning" });
        }
        if (record.state === "applied") rows.push({ key, record });
      }
      rows.sort((a,b) => b.record.updatedAtMs - a.record.updatedAtMs || a.key.localeCompare(b.key));
      let removed = 0;
      for (let i = 0; i < rows.length; i += 1) {
        const { key, record } = rows[i];
        if (i < maxRecords && nowMs - record.updatedAtMs < retentionMs) continue;
        if (await this.#strict(record.workKey, scope) !== undefined
            || await this.#strict(DeliveryCommitStore.commitKey(normalizedOwner, record.sealedDigest), scope) !== undefined) continue;
        await this.#deleteAndVerify(key, scope);
        removed += 1;
      }
      return removed;
    })();
    this.#prunePromises.set(normalizedOwner, pending);
    try { return await pending; } finally { this.#prunePromises.delete(normalizedOwner); }
  }

  async #ownedSet(key, value) {
    if (this.#assertOwnership) this.#assertOwnership();
    return this.#kv.set(key, value);
  }

  async #ownedDelete(key) {
    if (this.#assertOwnership) this.#assertOwnership();
    return this.#kv.delete(key);
  }

  async #writeCommit(key, record) {
    const plain = toPlain(record);
    let lastError = null;
    for (let attempt = 0; attempt < WRITE_ATTEMPTS; attempt += 1) {
      try {
        await this.#ownedSet(key, plain);
        const stored = await this.#kv.getStrict(key);
        const decoded = DeliveryCommitRecordV1.fromJSON(stored);
        if (DeliveryCommitStore.commitKey(decoded.owner, decoded.sealedDigest) !== key
            || canonicalJSONStringify(toPlain(decoded)) !== canonicalJSONStringify(plain)) {
          throw new Error("delivery commit read-back mismatch");
        }
        return;
      } catch (err) {
        lastError = err;
      }
    }
    throw this.#fatal({
      message: "delivery commit point could not be proven durable",
      scope: "lane",
      owner: record.owner,
      laneId: record.laneId,
      key,
      cause: lastError,
    });
  }

  async #rollForward(commitKey, record) {
    const lane = { scope: "lane", owner: record.owner, laneId: record.laneId };
    const sessionIntent = record.sessionIntent;
    const sessionVerdict = await this.#sessionVerdict(sessionIntent, lane);
    if (sessionVerdict === "apply") {
      await this.#setAndVerify(sessionIntent.recordKey, sessionIntent.nextSessionRecord, (value) => (
        value && value.version === sessionIntent.nextSessionVersion
          && canonicalDigest(value) === sessionIntent.nextSnapshotDigest
      ), lane);
      await this.#setAndVerify(sessionIntent.indexKey, sessionIntent.indexValue,
        (value) => value === sessionIntent.indexValue, lane);
    }

    if (record.peerLinkIntent && sessionVerdict === "apply") {
      const peerVerdict = await this.#peerLinkVerdict(record.peerLinkIntent, lane);
      if (peerVerdict === "apply") {
        await this.#setAndVerify(record.peerLinkIntent.recordKey, record.peerLinkIntent.nextPeerLinkRecord, (value) => (
          value && value.version === record.peerLinkIntent.nextPeerLinkVersion
            && canonicalDigest(value) === record.peerLinkIntent.nextPeerLinkDigest
        ), lane);
        await this.#setAndVerify(record.peerLinkIntent.pairIndexKey, record.peerLinkIntent.pairIndexValue,
          (value) => value === record.peerLinkIntent.pairIndexValue, lane);
      }
    }

    if (record.lifecycleEventIntent) {
      const eventIntent = record.lifecycleEventIntent;
      await this.#setAndVerify(eventIntent.recordKey, eventIntent.eventRecord,
        (value) => canonicalJSONStringify(value) === canonicalJSONStringify(toPlain(eventIntent.eventRecord)), lane);
      await this.#setAndVerify(eventIntent.entryKey, eventIntent.indexEntry,
        (value) => canonicalJSONStringify(value) === canonicalJSONStringify(toPlain(eventIntent.indexEntry)), lane);
    }

    const workKey = DeliveryCommitStore.workKey(record.owner, record.sealedDigest);
    const replayKey = DeliveryCommitStore.replayKey(record.owner, record.sealedDigest);
    const replay = new ReplayIdentityRecordV1({
      owner: record.owner,
      sealedDigest: record.sealedDigest,
      state: "ready-to-apply",
      workKey,
      createdAtMs: record.createdAtMs,
      updatedAtMs: record.createdAtMs,
    });
    await this.#setAndVerify(replayKey, replay, (value) => {
      const decoded = ReplayIdentityRecordV1.fromJSON(value);
      return decoded.owner === record.owner && decoded.sealedDigest === record.sealedDigest
        && decoded.workKey === workKey && (decoded.state === "ready-to-apply" || decoded.state === "applied");
    }, lane, { preserveAppliedReplay: true });
    const replayAfter = ReplayIdentityRecordV1.fromJSON(await this.#strict(replayKey, lane));
    if (replayAfter.state === "applied") {
      await this.#deleteAndVerify(workKey, lane);
    } else {
      await this.#setAndVerify(workKey, record.work, (value) => (
        canonicalJSONStringify(value) === canonicalJSONStringify(toPlain(record.work))
      ), lane);
    }
    await this.#deleteAndVerify(commitKey, lane);
  }

  async #sessionVerdict(intent, lane) {
    const current = await this.#strict(intent.recordKey, lane);
    if (current === undefined) {
      if (intent.expectedSessionVersion === 0) return "apply";
      throw this.#fatal({ ...lane, key: intent.recordKey, message: "canonical session is absent under committed delivery" });
    }
    const version = Number(current.version);
    if (!Number.isSafeInteger(version) || version < 1) {
      throw this.#fatal({ ...lane, key: intent.recordKey, message: "canonical session has invalid version" });
    }
    if (version === intent.expectedSessionVersion) return "apply";
    if (version === intent.nextSessionVersion) {
      if (canonicalDigest(current) !== intent.nextSnapshotDigest) {
        throw this.#fatal({ ...lane, key: intent.recordKey, message: "canonical session digest mismatch at next version" });
      }
      return "apply";
    }
    if (version > intent.nextSessionVersion) return "stale";
    throw this.#fatal({ ...lane, key: intent.recordKey, message: "canonical session version regressed" });
  }

  async #peerLinkVerdict(intent, lane) {
    const current = await this.#strict(intent.recordKey, lane);
    if (current === undefined) {
      throw this.#fatal({ ...lane, key: intent.recordKey, message: "canonical peer link is absent under committed delivery" });
    }
    const version = Number(current.version);
    if (!Number.isSafeInteger(version) || version < 1) {
      throw this.#fatal({ ...lane, key: intent.recordKey, message: "canonical peer link has invalid version" });
    }
    if (version === intent.expectedPeerLinkVersion) return "apply";
    if (version === intent.nextPeerLinkVersion) {
      if (canonicalDigest(current) !== intent.nextPeerLinkDigest) {
        throw this.#fatal({ ...lane, key: intent.recordKey, message: "canonical peer-link digest mismatch at next version" });
      }
      return "apply";
    }
    if (version > intent.nextPeerLinkVersion) return "stale";
    throw this.#fatal({ ...lane, key: intent.recordKey, message: "canonical peer-link version regressed" });
  }

  async #strict(key, fatal) {
    try {
      return await this.#kv.getStrict(key);
    } catch (err) {
      throw this.#fatal({ ...fatal, key, message: "unreadable key during delivery recovery", cause: err });
    }
  }

  async #setAndVerify(key, value, verify, fatal, options = {}) {
    const plain = toPlain(value);
    let lastError = null;
    for (let attempt = 0; attempt < WRITE_ATTEMPTS; attempt += 1) {
      try {
        const before = await this.#kv.getStrict(key);
        if (before !== undefined && verify(before)) return;
        if (options.preserveAppliedReplay === true && before !== undefined) {
          const replay = ReplayIdentityRecordV1.tryCreate(before);
          if (replay && replay.state === "applied") return;
        }
        await this.#ownedSet(key, plain);
        const after = await this.#kv.getStrict(key);
        if (after !== undefined && verify(after)) return;
        lastError = new Error("canonical read-back did not match intent");
      } catch (err) {
        lastError = err;
        try {
          const afterError = await this.#kv.getStrict(key);
          if (afterError !== undefined && verify(afterError)) return;
        } catch (readErr) {
          lastError = readErr;
        }
      }
    }
    throw this.#fatal({ ...fatal, key, message: "canonical delivery projection could not converge", cause: lastError });
  }

  async #deleteAndVerify(key, fatal) {
    let lastError = null;
    for (let attempt = 0; attempt < WRITE_ATTEMPTS; attempt += 1) {
      try {
        await this.#ownedDelete(key);
        if ((await this.#kv.getStrict(key)) === undefined) return;
        lastError = new Error("key remained after delete");
      } catch (err) {
        lastError = err;
        try {
          if ((await this.#kv.getStrict(key)) === undefined) return;
        } catch (readErr) {
          lastError = readErr;
        }
      }
    }
    throw this.#fatal({ ...fatal, key, message: "delivery commit compaction could not be proven", cause: lastError });
  }

  #assertOwnerAvailable(owner) {
    if (this.#runtimeEpoch === null) throw new Error("DeliveryCommitStore runtime ownership is not active");
    if (this.#storeFatal) throw this.#storeFatal;
    const normalizedOwner = requireString(owner, "owner");
    const ownerErr = this.#ownerFatal.get(normalizedOwner);
    if (ownerErr) throw ownerErr;
    return normalizedOwner;
  }

  #fatal(input) {
    const err = input instanceof DeliveryCommitFatalError ? input : new DeliveryCommitFatalError(input);
    if (err.scope === "store") {
      this.#storeFatal = err;
    } else if (err.scope === "owner" && err.owner) {
      this.#ownerFatal.set(err.owner, err);
    } else if (err.owner && err.laneId) {
      this.#quarantinedLanes.set(err.owner + "::" + err.laneId, err);
    }
    return err;
  }
}
