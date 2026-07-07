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
   * @param {object} opts
   * @param {object} opts.deviceRevoke — DeviceRevokeV1 instance or its toJSON()
   * @returns {Promise<{ inboxId: string, revokedDeviceId: string, revoked: boolean }>}
   */
  async revoke({ deviceRevoke } = {}) {
    const revoke = toBody(deviceRevoke);
    if (!revoke) {
      throw new Error("DevicesCapability.revoke requires deviceRevoke");
    }
    const response = await this.#pool.sendRequest({
      type: T.DEVICE_REVOKE,
      body: { deviceRevoke: revoke },
      expectedResponseType: T.DEVICE_REVOKE_RES,
    });
    return response && typeof response.body === "object" ? response.body : {};
  }
}
