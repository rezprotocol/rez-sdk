/**
 * MetricsCollector — lightweight counters and histograms for SDK observability.
 *
 * Tracks: request count, request duration, connection state changes,
 * frames received, reconnect count, auth attempts.
 */
export class MetricsCollector {
  #counters = new Map();
  #histograms = new Map();
  #hooks = new Set();

  increment(name, value = 1) {
    const current = this.#counters.get(name) || 0;
    this.#counters.set(name, current + value);
    this.#notify({ type: "counter", name, value: current + value, delta: value });
  }

  record(name, value) {
    if (!Number.isFinite(value)) return;
    let hist = this.#histograms.get(name);
    if (!hist) {
      hist = { count: 0, sum: 0, min: Infinity, max: -Infinity };
      this.#histograms.set(name, hist);
    }
    hist.count += 1;
    hist.sum += value;
    if (value < hist.min) hist.min = value;
    if (value > hist.max) hist.max = value;
    this.#notify({ type: "histogram", name, value, count: hist.count });
  }

  snapshot() {
    const counters = {};
    for (const [k, v] of this.#counters) counters[k] = v;
    const histograms = {};
    for (const [k, v] of this.#histograms) {
      histograms[k] = {
        count: v.count,
        sum: v.sum,
        min: v.min === Infinity ? 0 : v.min,
        max: v.max === -Infinity ? 0 : v.max,
        avg: v.count > 0 ? v.sum / v.count : 0,
      };
    }
    return { counters, histograms };
  }

  reset() {
    this.#counters.clear();
    this.#histograms.clear();
  }

  onMetric(handler) {
    if (typeof handler !== "function") throw new Error("handler required");
    this.#hooks.add(handler);
    return () => this.#hooks.delete(handler);
  }

  #notify(metric) {
    for (const hook of this.#hooks) {
      try { hook(metric); } catch { /* ignore */ }
    }
  }
}
