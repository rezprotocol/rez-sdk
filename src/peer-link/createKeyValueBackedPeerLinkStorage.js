function cloneJsonValue(value) {
  if (value === undefined) {
    return undefined;
  }
  return JSON.parse(JSON.stringify(value));
}

function assertNonEmptyString(value, label) {
  const normalized = String(value || "").trim();
  if (!normalized) {
    throw new Error(`${label} is required`);
  }
  return normalized;
}

function assertRecord(record, label) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(`${label} must be an object`);
  }
}

function normalizeVersion(record) {
  const version = Number(record.version);
  if (Number.isInteger(version) && version > 0) {
    return version;
  }
  return 1;
}

function normalizeListOptions(options) {
  let limit = null;
  let cursor = null;
  if (options && typeof options === "object" && !Array.isArray(options)) {
    if (Number.isInteger(options.limit) && options.limit > 0) {
      limit = options.limit;
    }
    if (typeof options.cursor === "string") {
      const normalizedCursor = options.cursor.trim();
      if (normalizedCursor) {
        cursor = normalizedCursor;
      }
    }
  }
  return { limit, cursor };
}

function pairKeyFor(localAccountId, peerAccountId) {
  const a = assertNonEmptyString(localAccountId, "localAccountId");
  const b = assertNonEmptyString(peerAccountId, "peerAccountId");
  return `${a}::${b}`;
}

function isRecoverableStatus(status) {
  const normalized = String(status || "").trim().toLowerCase();
  const terminalStatuses = new Set(["closed", "revoked", "deleted"]);
  if (!normalized) {
    return true;
  }
  return !terminalStatuses.has(normalized);
}

function isPendingStatus(status) {
  const normalized = String(status || "").trim().toLowerCase();
  const nonPendingStatuses = new Set(["completed", "failed", "revoked", "cancelled"]);
  if (!normalized) {
    return true;
  }
  return !nonPendingStatuses.has(normalized);
}

class KeyValuePeerLinkStore {
  constructor({ keyValueStore }) {
    if (!keyValueStore) {
      throw new Error("KeyValuePeerLinkStore requires keyValueStore");
    }
    this.keyValueStore = keyValueStore;
    this.recordPrefix = "peer-link:records:";
    this.pairPrefix = "peer-link:pairs:";
  }

  _recordKey(ownerAccountId, peerLinkId) {
    const owner = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const normalized = assertNonEmptyString(peerLinkId, "peerLinkId");
    return `${this.recordPrefix}${owner}::${normalized}`;
  }

  _pairKey(ownerAccountId, peerAccountId) {
    return `${this.pairPrefix}${pairKeyFor(ownerAccountId, peerAccountId)}`;
  }

  async getById(ownerAccountId, peerLinkId) {
    const stored = await this.keyValueStore.get(this._recordKey(ownerAccountId, peerLinkId));
    return cloneJsonValue(stored);
  }

  async getByPair(ownerAccountId, peerAccountId) {
    const peerLinkId = await this.keyValueStore.get(this._pairKey(ownerAccountId, peerAccountId));
    if (typeof peerLinkId !== "string" || !peerLinkId) {
      return undefined;
    }
    return this.getById(ownerAccountId, peerLinkId);
  }

  async create(record) {
    assertRecord(record, "peerLinkRecord");
    const peerLinkId = assertNonEmptyString(record.peerLinkId, "peerLinkId");
    const localAccountId = assertNonEmptyString(record.localAccountId, "localAccountId");
    const peerAccountId = assertNonEmptyString(record.peerAccountId, "peerAccountId");
    const existing = await this.keyValueStore.get(this._recordKey(localAccountId, peerLinkId));
    if (existing !== undefined) {
      throw new Error(`Peer link already exists for ${peerLinkId}`);
    }
    const pairIndexKey = this._pairKey(localAccountId, peerAccountId);
    const indexedPeerLinkId = await this.keyValueStore.get(pairIndexKey);
    if (typeof indexedPeerLinkId === "string" && indexedPeerLinkId && indexedPeerLinkId !== peerLinkId) {
      throw new Error(`Peer link already exists for pair ${pairKeyFor(localAccountId, peerAccountId)}`);
    }
    const nextRecord = cloneJsonValue(record);
    nextRecord.version = normalizeVersion(record);
    await this.keyValueStore.set(this._recordKey(localAccountId, peerLinkId), nextRecord);
    await this.keyValueStore.set(pairIndexKey, peerLinkId);
    return cloneJsonValue(nextRecord);
  }

  async update(record, expectedVersion) {
    assertRecord(record, "peerLinkRecord");
    const peerLinkId = assertNonEmptyString(record.peerLinkId, "peerLinkId");
    const localAccountId = assertNonEmptyString(record.localAccountId, "localAccountId");
    const peerAccountId = assertNonEmptyString(record.peerAccountId, "peerAccountId");
    const current = await this.keyValueStore.get(this._recordKey(localAccountId, peerLinkId));
    if (current === undefined) {
      throw new Error(`Peer link not found for ${peerLinkId}`);
    }
    const normalizedExpectedVersion = Number(expectedVersion);
    if (!Number.isInteger(normalizedExpectedVersion) || normalizedExpectedVersion < 1) {
      throw new Error("expectedVersion must be a positive integer");
    }
    const currentVersion = normalizeVersion(current);
    if (currentVersion !== normalizedExpectedVersion) {
      throw new Error(`Peer link version mismatch for ${peerLinkId}`);
    }
    if (current.localAccountId !== localAccountId) {
      throw new Error("Peer link owner cannot change");
    }
    const currentPair = pairKeyFor(current.localAccountId, current.peerAccountId);
    const nextPair = pairKeyFor(localAccountId, peerAccountId);
    if (currentPair !== nextPair) {
      throw new Error("Peer link account pair cannot change");
    }
    const nextRecord = cloneJsonValue(record);
    nextRecord.version = currentVersion + 1;
    await this.keyValueStore.set(this._recordKey(localAccountId, peerLinkId), nextRecord);
    await this.keyValueStore.set(this._pairKey(localAccountId, peerAccountId), peerLinkId);
    return cloneJsonValue(nextRecord);
  }

  async listByOwner(ownerAccountId) {
    const normalizedOwnerAccountId = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const keys = await this.keyValueStore.keys(this.recordPrefix);
    const out = [];
    for (const key of keys) {
      const record = await this.keyValueStore.get(key);
      if (!record || typeof record !== "object") {
        continue;
      }
      if (record.localAccountId === normalizedOwnerAccountId) {
        out.push(cloneJsonValue(record));
      }
    }
    out.sort((left, right) => String(left.peerLinkId || "").localeCompare(String(right.peerLinkId || "")));
    return out;
  }
}

class KeyValueSecureSessionStore {
  constructor({ keyValueStore }) {
    if (!keyValueStore) {
      throw new Error("KeyValueSecureSessionStore requires keyValueStore");
    }
    this.keyValueStore = keyValueStore;
    this.recordPrefix = "peer-link:sessions:";
    this.peerLinkIndexPrefix = "peer-link:sessions:by-peer-link:";
    // S2.5: per-device session index. A legacy (single-device) session is stored
    // under the by-peer-link index above; a per-device session (record carries
    // peerDeviceId) is stored under this index instead, so a peer-link can hold
    // one session PER peer device without the two clobbering each other.
    this.peerLinkDeviceIndexPrefix = "peer-link:sessions:by-peer-link-device:";
  }

  _recordKey(ownerAccountId, sessionId) {
    const owner = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const normalized = assertNonEmptyString(sessionId, "sessionId");
    return `${this.recordPrefix}${owner}::${normalized}`;
  }

  _indexKey(ownerAccountId, peerLinkId) {
    const owner = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const normalized = assertNonEmptyString(peerLinkId, "peerLinkId");
    return `${this.peerLinkIndexPrefix}${owner}::${normalized}`;
  }

  _deviceIndexKey(ownerAccountId, peerLinkId, peerDeviceId) {
    const owner = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const link = assertNonEmptyString(peerLinkId, "peerLinkId");
    const device = assertNonEmptyString(peerDeviceId, "peerDeviceId");
    return `${this.peerLinkDeviceIndexPrefix}${owner}::${link}::${device}`;
  }

  async getById(ownerAccountId, sessionId) {
    const stored = await this.keyValueStore.get(this._recordKey(ownerAccountId, sessionId));
    return cloneJsonValue(stored);
  }

  async getByPeerLinkId(ownerAccountId, peerLinkId) {
    const sessionId = await this.keyValueStore.get(this._indexKey(ownerAccountId, peerLinkId));
    if (typeof sessionId !== "string" || !sessionId) {
      return undefined;
    }
    return this.getById(ownerAccountId, sessionId);
  }

  // S2.5: resolve the per-device session for (owner, peerLinkId, peerDeviceId).
  async getByPeerLinkAndDevice(ownerAccountId, peerLinkId, peerDeviceId) {
    const sessionId = await this.keyValueStore.get(this._deviceIndexKey(ownerAccountId, peerLinkId, peerDeviceId));
    if (typeof sessionId !== "string" || !sessionId) {
      return undefined;
    }
    return this.getById(ownerAccountId, sessionId);
  }

  // S2.5: every per-device session under one peer-link, for fan-out trial-decrypt
  // and the no-cross-advance checks. Scans records (mirrors listRecoverable) and
  // filters to this owner+link that carry a peerDeviceId. Excludes the legacy
  // single-device session (no peerDeviceId), which is reached via getByPeerLinkId.
  async listByPeerLink(ownerAccountId, peerLinkId) {
    const owner = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const link = assertNonEmptyString(peerLinkId, "peerLinkId");
    const keys = await this.keyValueStore.keys(this.recordPrefix);
    const out = [];
    for (const key of keys) {
      const record = await this.keyValueStore.get(key);
      if (!record || typeof record !== "object") {
        continue;
      }
      if (record.localAccountId !== owner) {
        continue;
      }
      if (record.peerLinkId !== link) {
        continue;
      }
      const peerDeviceId = typeof record.peerDeviceId === "string" ? record.peerDeviceId.trim() : "";
      if (!peerDeviceId) {
        continue;
      }
      out.push(cloneJsonValue(record));
    }
    out.sort((left, right) => String(left.peerDeviceId || "").localeCompare(String(right.peerDeviceId || "")));
    return out;
  }

  async put(record) {
    assertRecord(record, "secureSessionRecord");
    const sessionId = assertNonEmptyString(record.sessionId, "sessionId");
    const ownerAccountId = assertNonEmptyString(record.localAccountId, "localAccountId");
    const peerLinkId = assertNonEmptyString(record.peerLinkId, "peerLinkId");
    const peerDeviceId = typeof record.peerDeviceId === "string" ? record.peerDeviceId.trim() : "";
    const existing = await this.keyValueStore.get(this._recordKey(ownerAccountId, sessionId));
    const nextRecord = cloneJsonValue(record);
    if (existing && typeof existing === "object") {
      nextRecord.version = normalizeVersion(existing) + 1;
    } else {
      nextRecord.version = normalizeVersion(record);
    }
    await this.keyValueStore.set(this._recordKey(ownerAccountId, sessionId), nextRecord);
    if (peerDeviceId) {
      // Per-device session: index by (peerLinkId, peerDeviceId). Do NOT touch the
      // legacy by-peer-link index — multiple devices would clobber its single slot.
      await this.keyValueStore.set(this._deviceIndexKey(ownerAccountId, peerLinkId, peerDeviceId), sessionId);
    } else {
      await this.keyValueStore.set(this._indexKey(ownerAccountId, peerLinkId), sessionId);
    }
    return cloneJsonValue(nextRecord);
  }

  async delete(ownerAccountId, sessionId) {
    const owner = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const normalizedSessionId = assertNonEmptyString(sessionId, "sessionId");
    const existing = await this.keyValueStore.get(this._recordKey(owner, normalizedSessionId));
    const removed = await this.keyValueStore.delete(this._recordKey(owner, normalizedSessionId));
    if (!removed) {
      return false;
    }
    if (existing && typeof existing === "object" && typeof existing.peerLinkId === "string" && existing.peerLinkId) {
      const existingPeerDeviceId = typeof existing.peerDeviceId === "string" ? existing.peerDeviceId.trim() : "";
      if (existingPeerDeviceId) {
        const deviceIndexKey = this._deviceIndexKey(owner, existing.peerLinkId, existingPeerDeviceId);
        const indexedSessionId = await this.keyValueStore.get(deviceIndexKey);
        if (indexedSessionId === normalizedSessionId) {
          await this.keyValueStore.delete(deviceIndexKey);
        }
      } else {
        const indexKey = this._indexKey(owner, existing.peerLinkId);
        const indexedSessionId = await this.keyValueStore.get(indexKey);
        if (indexedSessionId === normalizedSessionId) {
          await this.keyValueStore.delete(indexKey);
        }
      }
    }
    return true;
  }

  async listRecoverable(ownerAccountId) {
    const normalizedOwnerAccountId = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const keys = await this.keyValueStore.keys(this.recordPrefix);
    const out = [];
    for (const key of keys) {
      const record = await this.keyValueStore.get(key);
      if (!record || typeof record !== "object") {
        continue;
      }
      const owner = typeof record.localAccountId === "string" && record.localAccountId
        ? record.localAccountId
        : record.ownerAccountId;
      if (owner !== normalizedOwnerAccountId) {
        continue;
      }
      if (!isRecoverableStatus(record.status)) {
        continue;
      }
      out.push(cloneJsonValue(record));
    }
    out.sort((left, right) => String(left.sessionId || "").localeCompare(String(right.sessionId || "")));
    return out;
  }
}

class KeyValueHandshakeAttemptStore {
  constructor({ keyValueStore }) {
    if (!keyValueStore) {
      throw new Error("KeyValueHandshakeAttemptStore requires keyValueStore");
    }
    this.keyValueStore = keyValueStore;
    this.recordPrefix = "peer-link:handshakes:";
  }

  _recordKey(ownerAccountId, handshakeAttemptId) {
    const owner = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const normalized = assertNonEmptyString(handshakeAttemptId, "handshakeAttemptId");
    return `${this.recordPrefix}${owner}::${normalized}`;
  }

  async getById(ownerAccountId, handshakeAttemptId) {
    const stored = await this.keyValueStore.get(this._recordKey(ownerAccountId, handshakeAttemptId));
    return cloneJsonValue(stored);
  }

  async create(record) {
    assertRecord(record, "handshakeAttemptRecord");
    const handshakeAttemptId = assertNonEmptyString(record.handshakeAttemptId, "handshakeAttemptId");
    const ownerAccountId = assertNonEmptyString(record.ownerAccountId, "ownerAccountId");
    const existing = await this.keyValueStore.get(this._recordKey(ownerAccountId, handshakeAttemptId));
    if (existing !== undefined) {
      throw new Error(`Handshake attempt already exists for ${handshakeAttemptId}`);
    }
    const nextRecord = cloneJsonValue(record);
    nextRecord.version = normalizeVersion(record);
    await this.keyValueStore.set(this._recordKey(ownerAccountId, handshakeAttemptId), nextRecord);
    return cloneJsonValue(nextRecord);
  }

  async update(record, expectedVersion) {
    assertRecord(record, "handshakeAttemptRecord");
    const handshakeAttemptId = assertNonEmptyString(record.handshakeAttemptId, "handshakeAttemptId");
    const ownerAccountId = assertNonEmptyString(record.ownerAccountId, "ownerAccountId");
    const current = await this.keyValueStore.get(this._recordKey(ownerAccountId, handshakeAttemptId));
    if (current === undefined) {
      throw new Error(`Handshake attempt not found for ${handshakeAttemptId}`);
    }
    const normalizedExpectedVersion = Number(expectedVersion);
    if (!Number.isInteger(normalizedExpectedVersion) || normalizedExpectedVersion < 1) {
      throw new Error("expectedVersion must be a positive integer");
    }
    const currentVersion = normalizeVersion(current);
    if (currentVersion !== normalizedExpectedVersion) {
      throw new Error(`Handshake attempt version mismatch for ${handshakeAttemptId}`);
    }
    const nextRecord = cloneJsonValue(record);
    nextRecord.version = currentVersion + 1;
    await this.keyValueStore.set(this._recordKey(ownerAccountId, handshakeAttemptId), nextRecord);
    return cloneJsonValue(nextRecord);
  }

  async listByPeerLinkId(ownerAccountId, peerLinkId) {
    const normalizedOwnerAccountId = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const normalizedPeerLinkId = assertNonEmptyString(peerLinkId, "peerLinkId");
    const keys = await this.keyValueStore.keys(this.recordPrefix);
    const out = [];
    for (const key of keys) {
      const record = await this.keyValueStore.get(key);
      if (!record || typeof record !== "object") {
        continue;
      }
      if (record.ownerAccountId !== normalizedOwnerAccountId) {
        continue;
      }
      if (record.peerLinkId !== normalizedPeerLinkId) {
        continue;
      }
      out.push(cloneJsonValue(record));
    }
    out.sort((left, right) => String(left.handshakeAttemptId || "").localeCompare(String(right.handshakeAttemptId || "")));
    return out;
  }

  async listPending(ownerAccountId) {
    const normalizedOwnerAccountId = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const keys = await this.keyValueStore.keys(this.recordPrefix);
    const out = [];
    for (const key of keys) {
      const record = await this.keyValueStore.get(key);
      if (!record || typeof record !== "object") {
        continue;
      }
      const owner = typeof record.ownerAccountId === "string" && record.ownerAccountId
        ? record.ownerAccountId
        : record.localAccountId;
      if (owner !== normalizedOwnerAccountId) {
        continue;
      }
      if (!isPendingStatus(record.status)) {
        continue;
      }
      out.push(cloneJsonValue(record));
    }
    out.sort((left, right) => String(left.handshakeAttemptId || "").localeCompare(String(right.handshakeAttemptId || "")));
    return out;
  }
}

class KeyValuePeerLinkEventStore {
  constructor({ keyValueStore }) {
    if (!keyValueStore) {
      throw new Error("KeyValuePeerLinkEventStore requires keyValueStore");
    }
    this.keyValueStore = keyValueStore;
    this.recordPrefix = "peer-link:events:";
    this.indexPrefix = "peer-link:events:index:";
  }

  _recordKey(ownerAccountId, eventId) {
    const owner = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const normalized = assertNonEmptyString(eventId, "eventId");
    return `${this.recordPrefix}${owner}::${normalized}`;
  }

  _indexKey(ownerAccountId, peerLinkId) {
    const owner = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const normalized = assertNonEmptyString(peerLinkId, "peerLinkId");
    return `${this.indexPrefix}${owner}::${normalized}`;
  }

  async append(eventRecord) {
    assertRecord(eventRecord, "peerLinkEventRecord");
    const ownerAccountId = assertNonEmptyString(eventRecord.ownerAccountId, "ownerAccountId");
    const eventId = assertNonEmptyString(eventRecord.eventId, "eventId");
    const peerLinkId = assertNonEmptyString(eventRecord.peerLinkId, "peerLinkId");
    const recordKey = this._recordKey(ownerAccountId, eventId);
    const existing = await this.keyValueStore.get(recordKey);
    if (existing !== undefined) {
      if (existing && typeof existing === "object" && existing.peerLinkId === peerLinkId) {
        return cloneJsonValue(existing);
      }
      throw new Error(`Peer link event already exists for ${eventId}`);
    }
    const nextRecord = cloneJsonValue(eventRecord);
    await this.keyValueStore.set(recordKey, nextRecord);
    const indexKey = this._indexKey(ownerAccountId, peerLinkId);
    const index = await this.keyValueStore.get(indexKey);
    const nextIndex = Array.isArray(index) ? index.slice() : [];
    nextIndex.push(eventId);
    await this.keyValueStore.set(indexKey, nextIndex);
    return cloneJsonValue(nextRecord);
  }

  async listByPeerLinkId(ownerAccountId, peerLinkId, options) {
    const normalizedOwnerAccountId = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const normalizedPeerLinkId = assertNonEmptyString(peerLinkId, "peerLinkId");
    const normalizedOptions = normalizeListOptions(options);
    const index = await this.keyValueStore.get(this._indexKey(normalizedOwnerAccountId, normalizedPeerLinkId));
    const ids = Array.isArray(index) ? index.slice() : [];
    let start = 0;
    if (normalizedOptions.cursor) {
      const cursorIndex = ids.indexOf(normalizedOptions.cursor);
      if (cursorIndex >= 0) {
        start = cursorIndex + 1;
      }
    }
    const windowIds = normalizedOptions.limit ? ids.slice(start, start + normalizedOptions.limit) : ids.slice(start);
    const items = [];
    for (const eventId of windowIds) {
      const record = await this.keyValueStore.get(this._recordKey(normalizedOwnerAccountId, eventId));
      if (record !== undefined) {
        items.push(cloneJsonValue(record));
      }
    }
    let nextCursor = null;
    if (normalizedOptions.limit && start + normalizedOptions.limit < ids.length && items.length > 0) {
      nextCursor = String(items[items.length - 1].eventId || "");
    }
    return { items, nextCursor };
  }
}

class KeyValueNodeKeyMaterialStore {
  constructor({ keyValueStore }) {
    if (!keyValueStore) {
      throw new Error("KeyValueNodeKeyMaterialStore requires keyValueStore");
    }
    this.keyValueStore = keyValueStore;
    this.identityPrefix = "peer-link:keys:identity:";
    this.invitePreKeyPrefix = "peer-link:keys:invite:";
    // Per-device X3DH identity material (S2.5): the device's X25519 identity-DH
    // key + its signature by the device key (C). Keyed by (account, deviceId) so a
    // device's material is distinct from the account-level identity above.
    this.deviceIdentityPrefix = "peer-link:keys:device:";
  }

  _identityKey(accountId) {
    const normalized = assertNonEmptyString(accountId, "accountId");
    return `${this.identityPrefix}${normalized}`;
  }

  _deviceIdentityKey(accountId, deviceId) {
    const owner = assertNonEmptyString(accountId, "accountId");
    const device = assertNonEmptyString(deviceId, "deviceId");
    return `${this.deviceIdentityPrefix}${owner}::${device}`;
  }

  _invitePreKey(ownerAccountId, inviteId) {
    const owner = assertNonEmptyString(ownerAccountId, "ownerAccountId");
    const normalized = assertNonEmptyString(inviteId, "inviteId");
    return `${this.invitePreKeyPrefix}${owner}::${normalized}`;
  }

  async getAccountIdentity(accountId) {
    const stored = await this.keyValueStore.get(this._identityKey(accountId));
    return cloneJsonValue(stored);
  }

  async putAccountIdentity(accountId, material) {
    if (material === undefined) {
      throw new Error("material is required");
    }
    const nextMaterial = cloneJsonValue(material);
    await this.keyValueStore.set(this._identityKey(accountId), nextMaterial);
    return cloneJsonValue(nextMaterial);
  }

  async getDeviceIdentity(accountId, deviceId) {
    const stored = await this.keyValueStore.get(this._deviceIdentityKey(accountId, deviceId));
    return cloneJsonValue(stored);
  }

  async putDeviceIdentity(accountId, deviceId, material) {
    if (material === undefined) {
      throw new Error("material is required");
    }
    const nextMaterial = cloneJsonValue(material);
    await this.keyValueStore.set(this._deviceIdentityKey(accountId, deviceId), nextMaterial);
    return cloneJsonValue(nextMaterial);
  }

  async getInvitePreKey(ownerAccountId, inviteId) {
    const stored = await this.keyValueStore.get(this._invitePreKey(ownerAccountId, inviteId));
    return cloneJsonValue(stored);
  }

  async putInvitePreKey(ownerAccountId, inviteId, material) {
    if (material === undefined) {
      throw new Error("material is required");
    }
    const nextMaterial = cloneJsonValue(material);
    await this.keyValueStore.set(this._invitePreKey(ownerAccountId, inviteId), nextMaterial);
    return cloneJsonValue(nextMaterial);
  }

  async deleteInvitePreKey(ownerAccountId, inviteId) {
    return this.keyValueStore.delete(this._invitePreKey(ownerAccountId, inviteId));
  }
}

export function createKeyValueBackedPeerLinkStorage({ keyValueStore } = {}) {
  if (!keyValueStore) {
    throw new Error("createKeyValueBackedPeerLinkStorage requires keyValueStore");
  }
  return {
    peerLinks: new KeyValuePeerLinkStore({ keyValueStore }),
    sessions: new KeyValueSecureSessionStore({ keyValueStore }),
    handshakeAttempts: new KeyValueHandshakeAttemptStore({ keyValueStore }),
    events: new KeyValuePeerLinkEventStore({ keyValueStore }),
    keys: new KeyValueNodeKeyMaterialStore({ keyValueStore }),
  };
}
