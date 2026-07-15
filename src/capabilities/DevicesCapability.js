import { REZ_CONTRACT_TYPES } from "@rezprotocol/core";

const T = REZ_CONTRACT_TYPES;

/**
 * Coerce an RRecord (or its already-plain JSON) into the wire body object the
 * node handler reads. The device.bind/device.revoke handlers reconstruct the
 * rez-core records from these objects and re-verify every signature, so the SDK
 * carries them verbatim — it never trims or reshapes the signed bodies.
 */
function toBody(record) {
  if (record && typeof record.toJSON === "function") return record.toJSON();
  return record && typeof record === "object" ? record : null;
}

/**
 * Devices capability — bind / revoke a per-device home cursor (S2.5 Slice 4/5).
 *
 * `bind` presents the device→account chain (a DeviceRegistrationV1, account-
 * signed) plus a DeviceInboxBindingV1 (device-signed) so the durable home keys
 * this device's cursor on the SIGNED self-certifying deviceId rather than the
 * unsigned SessionHello string. `revoke` fail-closes a device at the home.
 *
 * Both are no-ops against a non-durable node (the relay answers
 * SERVICE_UNAVAILABLE) — callers gate on the negotiated `durableInbox`
 * capability before invoking. The wire op stays single-sourced through
 * UplinkPool.sendRequest, identical to every other capability.
 */
export class DevicesCapability {
  #pool;

  constructor({ pool }) {
    this.#pool = pool;
  }

  /**
   * @param {object} opts
   * @param {object|null} [opts.deviceRegistration] — DeviceRegistrationV1
   *     instance or its toJSON(). Null on a DELEGATED session (S10): the
   *     session's cert chain IS the registration (device.register was
   *     dropped; the node's dual-mode handler reads sessionAuthority), so
   *     only the device-signed binding rides.
   * @param {object} opts.deviceInboxBinding — DeviceInboxBindingV1 instance or its toJSON()
   * @returns {Promise<{ inboxId: string, deviceId: string }>}
   */
  async bind({ deviceRegistration = null, deviceInboxBinding } = {}) {
    const reg = deviceRegistration === null ? null : toBody(deviceRegistration);
    const binding = toBody(deviceInboxBinding);
    if (!binding) {
      throw new Error("DevicesCapability.bind requires deviceInboxBinding");
    }
    if (deviceRegistration !== null && !reg) {
      throw new Error("DevicesCapability.bind deviceRegistration must be a record object or null (delegated session)");
    }
    const response = await this.#pool.sendRequest({
      type: T.DEVICE_BIND,
      body: {
        ...(reg ? { deviceRegistration: reg } : {}),
        deviceInboxBinding: binding,
      },
      expectedResponseType: T.DEVICE_BIND_RES,
    });
    return response && typeof response.body === "object" ? response.body : {};
  }

  /**
   * Submit a serialized AccountDeviceMutationV1 (S2.5 S11) to the account's
   * authority home. The home verifies the envelope + the authenticated session's
   * capability, serializes the add/revoke under a per-account lock, and returns
   * the folded { revision, devices, authorityState } (or a { stale, currentRevision,
   * ... } snapshot on an expectedRevision mismatch — the caller re-reads + retries).
   * No-op against a non-durable node (SERVICE_UNAVAILABLE).
   *
   * @param {object} opts
   * @param {object} opts.mutation — AccountDeviceMutationV1 instance or its toJSON()
   * @returns {Promise<object>} the serializer result
   */
  async submitDeviceMutation({ mutation } = {}) {
    const body = toBody(mutation);
    if (!body) {
      throw new Error("DevicesCapability.submitDeviceMutation requires mutation");
    }
    const response = await this.#pool.sendRequest({
      type: T.ACCOUNT_DEVICE_MUTATION_SUBMIT,
      body: { mutation: body },
      expectedResponseType: T.ACCOUNT_DEVICE_MUTATION_SUBMIT_RES,
    });
    return response && typeof response.body === "object" ? response.body : {};
  }

  /**
   * Fetch the home's current authority state for the authenticated account —
   * { epoch, revokedCertIds, minValidIssuedAtMs } — so an authorized device can
   * fold + publish the signed AccountAuthorityStateV1 for off-home peers. The home
   * serves this for the authenticated account only. No-op against a non-durable
   * node (SERVICE_UNAVAILABLE).
   *
   * @param {object} [opts]
   * @param {string} [opts.accountIdentityPublicKeyB64] — defaults to the session account
   * @returns {Promise<{ epoch: number, revokedCertIds: string[], minValidIssuedAtMs: number }>}
   */
  async getAuthorityState({ accountIdentityPublicKeyB64 } = {}) {
    const body = {};
    if (typeof accountIdentityPublicKeyB64 === "string" && accountIdentityPublicKeyB64.length > 0) {
      body.accountIdentityPublicKeyB64 = accountIdentityPublicKeyB64;
    }
    const response = await this.#pool.sendRequest({
      type: T.ACCOUNT_AUTHORITY_STATE_GET,
      body,
      expectedResponseType: T.ACCOUNT_AUTHORITY_STATE_GET_RES,
    });
    return response && typeof response.body === "object" ? response.body : {};
  }

  /**
   * Self-publish this device's DevicePrekeyBundleV1 (self-contained, device-signed)
   * to the account HOME (S2.5 S12) so sibling devices can aggregate the account's
   * full device set. No-op against a non-durable node (SERVICE_UNAVAILABLE).
   *
   * @param {object} opts
   * @param {object} opts.bundle — DevicePrekeyBundleV1 instance or its toJSON()
   * @returns {Promise<{ deviceId: string, prekeyVersion: number, applied: boolean }>}
   */
  async publishDeviceBundle({ bundle } = {}) {
    const body = toBody(bundle);
    if (!body) {
      throw new Error("DevicesCapability.publishDeviceBundle requires bundle");
    }
    const response = await this.#pool.sendRequest({
      type: T.ACCOUNT_DEVICE_BUNDLE_PUBLISH,
      body: { bundle: body },
      expectedResponseType: T.ACCOUNT_DEVICE_BUNDLE_PUBLISH_RES,
    });
    return response && typeof response.body === "object" ? response.body : {};
  }

  /**
   * Fetch the account's full ACTIVE device set from the home (S2.5 S12) — every
   * active device's self-published DevicePrekeyBundleV1 — so a publishing device
   * can assemble the multi-device DeviceSetRecordV1 it seals per peer. Served for
   * the authenticated account only. No-op against a non-durable node.
   *
   * @param {object} [opts]
   * @param {string} [opts.accountIdentityPublicKeyB64] — defaults to the session account
   * @returns {Promise<{ devices: Array<{ deviceId: string, prekeyVersion: number, bundle: object }> }>}
   */
  async getAccountDeviceSet({ accountIdentityPublicKeyB64 } = {}) {
    const body = {};
    if (typeof accountIdentityPublicKeyB64 === "string" && accountIdentityPublicKeyB64.length > 0) {
      body.accountIdentityPublicKeyB64 = accountIdentityPublicKeyB64;
    }
    const response = await this.#pool.sendRequest({
      type: T.ACCOUNT_DEVICE_SET_GET,
      body,
      expectedResponseType: T.ACCOUNT_DEVICE_SET_GET_RES,
    });
    const b = response && typeof response.body === "object" ? response.body : {};
    return { devices: Array.isArray(b.devices) ? b.devices : [] };
  }
}
