export class TypedEventBus {
  #handlers = new Map();

  on(eventName, handler) {
    if (typeof eventName !== "string" || !eventName) {
      throw new Error("on() requires eventName string");
    }
    if (typeof handler !== "function") {
      throw new Error("on() requires handler function");
    }
    const set = this.#handlers.get(eventName) || new Set();
    set.add(handler);
    this.#handlers.set(eventName, set);
    return () => {
      const current = this.#handlers.get(eventName);
      if (!current) return;
      current.delete(handler);
      if (current.size === 0) this.#handlers.delete(eventName);
    };
  }

  once(eventName, handler) {
    if (typeof handler !== "function") {
      throw new Error("once() requires handler function");
    }
    let off;
    const wrapper = (payload) => {
      if (off) off();
      handler(payload);
    };
    off = this.on(eventName, wrapper);
    return off;
  }

  off(eventName, handler) {
    const set = this.#handlers.get(eventName);
    if (!set) return;
    set.delete(handler);
    if (set.size === 0) this.#handlers.delete(eventName);
  }

  emit(eventName, payload) {
    const set = this.#handlers.get(eventName);
    if (!set || set.size === 0) return;
    for (const fn of [...set]) {
      try {
        fn(payload);
      } catch {
        // listener errors are non-fatal
      }
    }
  }

  removeAllListeners(eventName) {
    if (eventName) {
      this.#handlers.delete(eventName);
    } else {
      this.#handlers.clear();
    }
  }

  listenerCount(eventName) {
    const set = this.#handlers.get(eventName);
    return set ? set.size : 0;
  }
}
