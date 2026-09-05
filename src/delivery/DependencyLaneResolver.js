function requireOwner(value) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error("DependencyLaneResolver requires owner");
  }
  return value.trim();
}

function requireLane(value) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error("DependencyLaneResolver requires laneId");
  }
  return value.trim();
}

/**
 * Fair owner barrier plus per-session serialization.
 *
 * Session work holds a shared owner grant and one exclusive session lane.
 * Owner-global work holds an exclusive owner grant. Requests are admitted in
 * FIFO batches: adjacent shared requests may run together, but no shared request
 * may jump an already-queued exclusive request. That makes the two-direction
 * barrier starvation-free while preserving concurrency across independent
 * ratchet sessions.
 */
export class DependencyLaneResolver {
  #owners = new Map();
  #sessionTails = new Map();
  #closedOwners = new Set();
  #closePromises = new Map();

  sessionLaneId(sessionId) {
    return "ratchet:" + requireLane(sessionId);
  }

  ownerLaneId(owner) {
    return "owner:" + requireOwner(owner);
  }

  runSession(owner, sessionId, fn) {
    if (typeof fn !== "function") throw new Error("DependencyLaneResolver.runSession requires fn");
    const normalizedOwner = requireOwner(owner);
    if (this.#closedOwners.has(normalizedOwner)) {
      return Promise.reject(new Error("DependencyLaneResolver owner is closed"));
    }
    const laneId = this.sessionLaneId(sessionId);
    return this.#withOwnerGrant(normalizedOwner, "shared", () => this.#withSessionLane(
      normalizedOwner + "::" + laneId,
      () => fn(laneId),
    ));
  }

  runOwner(owner, fn) {
    if (typeof fn !== "function") throw new Error("DependencyLaneResolver.runOwner requires fn");
    const normalizedOwner = requireOwner(owner);
    if (this.#closedOwners.has(normalizedOwner)) {
      return Promise.reject(new Error("DependencyLaneResolver owner is closed"));
    }
    const laneId = this.ownerLaneId(normalizedOwner);
    return this.#withOwnerGrant(normalizedOwner, "exclusive", () => fn(laneId));
  }

  closeOwner(owner) {
    const normalizedOwner = requireOwner(owner);
    const existing = this.#closePromises.get(normalizedOwner);
    if (existing) return existing;
    this.#closedOwners.add(normalizedOwner);
    const closed = this.#withOwnerGrant(normalizedOwner, "exclusive", () => undefined);
    this.#closePromises.set(normalizedOwner, closed);
    return closed;
  }

  #state(owner) {
    let state = this.#owners.get(owner);
    if (!state) {
      state = { activeShared: 0, activeExclusive: false, queue: [] };
      this.#owners.set(owner, state);
    }
    return state;
  }

  #withOwnerGrant(owner, mode, fn) {
    return new Promise((resolve, reject) => {
      const state = this.#state(owner);
      state.queue.push({ mode, fn, resolve, reject });
      this.#drain(owner, state);
    });
  }

  #drain(owner, state) {
    if (state.activeExclusive || state.queue.length === 0) return;
    const first = state.queue[0];
    if (first.mode === "exclusive") {
      if (state.activeShared !== 0) return;
      state.queue.shift();
      state.activeExclusive = true;
      this.#runGranted(first, () => {
        state.activeExclusive = false;
        this.#cleanupOrDrain(owner, state);
      });
      return;
    }

    while (state.queue.length > 0 && state.queue[0].mode === "shared" && !state.activeExclusive) {
      const request = state.queue.shift();
      state.activeShared += 1;
      this.#runGranted(request, () => {
        state.activeShared -= 1;
        this.#cleanupOrDrain(owner, state);
      });
    }
  }

  #runGranted(request, release) {
    Promise.resolve().then(request.fn).then(
      (value) => {
        release();
        request.resolve(value);
      },
      (err) => {
        release();
        request.reject(err);
      },
    );
  }

  #cleanupOrDrain(owner, state) {
    if (!state.activeExclusive && state.activeShared === 0 && state.queue.length === 0) {
      this.#owners.delete(owner);
      return;
    }
    this.#drain(owner, state);
  }

  #withSessionLane(key, fn) {
    const previous = this.#sessionTails.get(key) || Promise.resolve();
    const run = previous.then(fn, fn);
    const tail = run.then(() => undefined, () => undefined);
    this.#sessionTails.set(key, tail);
    tail.then(() => {
      if (this.#sessionTails.get(key) === tail) this.#sessionTails.delete(key);
    });
    return run;
  }
}
