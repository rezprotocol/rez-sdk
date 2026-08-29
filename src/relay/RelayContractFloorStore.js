/**
 * RelayContractFloorStore — client-side record of the highest wire-contract
 * version each VERIFIED relay identity has successfully authenticated at
 * (SESSION_AUTH_V5 slice 2B, plans/SESSION_AUTH_V5_SLICE2_PLAN.md).
 *
 * Keys are relay identity public keys (`nodePublicKeyB64`) that have already
 * been cryptographically verified by the challenge self-signature /
 * CRITICAL-2 binding at the moment of recording — NEVER endpoint URL/IP,
 * which an attacker controls.
 *
 * FROZEN CONTRACT — the floor is MONOTONIC per identity:
 *
 *     highestObservedContract(R) = max(existing, successfulContract)
 *
 * A later LOWER observation is a fact about the CURRENT session
 * (`observedCurrent`, `downgrade: true` in the recordObserved result) and may
 * drive downgrade handling, but it NEVER reduces the stored floor. This store
 * is not "last seen version" — treating it as one is exactly the
 * implementation error this contract exists to forbid.
 *
 * This default implementation is in-memory. Embedders that want the floor to
 * survive restarts supply a `backing` with the same two-method surface
 * (`get(key) → number|null`, `set(key, value)`); the monotonicity rule is
 * enforced HERE, above the backing, so no backing can weaken it.
 */
export class RelayContractFloorStore {
  #backing;
  #memory = new Map();

  constructor({ backing = null } = {}) {
    if (backing !== null) {
      if (typeof backing.get !== "function" || typeof backing.set !== "function") {
        throw new Error("RelayContractFloorStore backing requires get(key) and set(key, value)");
      }
    }
    this.#backing = backing;
  }

  #read(relayIdentityB64) {
    if (this.#backing) {
      const value = this.#backing.get(relayIdentityB64);
      return Number.isInteger(value) && value > 0 ? value : null;
    }
    const value = this.#memory.get(relayIdentityB64);
    return Number.isInteger(value) ? value : null;
  }

  #write(relayIdentityB64, value) {
    if (this.#backing) {
      this.#backing.set(relayIdentityB64, value);
      return;
    }
    this.#memory.set(relayIdentityB64, value);
  }

  /**
   * Record a successful authentication at `contractVersion` against the
   * verified relay identity. Monotonic (see class doc).
   *
   * @param {object} opts
   * @param {string} opts.relayIdentityB64 — VERIFIED nodePublicKeyB64
   * @param {number} opts.contractVersion — the contract the session used
   * @returns {{ floor: number, observedCurrent: number, downgrade: boolean }}
   */
  recordObserved({ relayIdentityB64, contractVersion } = {}) {
    const key = typeof relayIdentityB64 === "string" ? relayIdentityB64.trim() : "";
    if (!key) {
      throw new Error("recordObserved requires the verified relayIdentityB64");
    }
    if (!Number.isInteger(contractVersion) || contractVersion <= 0) {
      throw new Error("recordObserved requires a positive integer contractVersion");
    }
    const existing = this.#read(key);
    const floor = existing === null ? contractVersion : Math.max(existing, contractVersion);
    if (existing === null || floor > existing) {
      this.#write(key, floor);
    }
    return {
      floor,
      observedCurrent: contractVersion,
      downgrade: existing !== null && contractVersion < existing,
    };
  }

  /**
   * @param {string} relayIdentityB64
   * @returns {number|null} the recorded floor, or null when this identity has
   *   never been observed
   */
  floorFor(relayIdentityB64) {
    const key = typeof relayIdentityB64 === "string" ? relayIdentityB64.trim() : "";
    if (!key) return null;
    return this.#read(key);
  }
}
