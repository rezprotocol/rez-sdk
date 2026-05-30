class FakeSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  constructor() {
    this.readyState = FakeSocket.CONNECTING;
    this._handlers = new Map();
    this._peer = null;
  }

  addEventListener(name, handler) {
    const set = this._handlers.get(name) || new Set();
    set.add(handler);
    this._handlers.set(name, set);
  }

  removeEventListener(name, handler) {
    const set = this._handlers.get(name);
    if (!set) return;
    set.delete(handler);
    if (set.size === 0) this._handlers.delete(name);
  }

  send(data) {
    if (this.readyState !== FakeSocket.OPEN) throw new Error("socket not open");
    const peer = this._peer;
    if (!peer || peer.readyState !== FakeSocket.OPEN) throw new Error("peer not open");
    queueMicrotask(() => {
      peer._emit("message", { data: typeof data === "string" ? data : String(data) });
    });
  }

  close(code = 1000, reason = "") {
    this.readyState = FakeSocket.CLOSED;
    this._emit("close", { code, reason });
    if (this._peer && this._peer.readyState !== FakeSocket.CLOSED) {
      this._peer.readyState = FakeSocket.CLOSED;
      this._peer._emit("close", { code, reason });
    }
  }

  _open() {
    this.readyState = FakeSocket.OPEN;
    this._emit("open", {});
  }

  _emit(name, payload) {
    const set = this._handlers.get(name);
    if (!set) return;
    for (const handler of [...set]) {
      handler(payload);
    }
  }
}

export class FakeWsHarness {
  constructor() {
    this._handlersByUrl = new Map();
  }

  register(url, handler) {
    this._handlersByUrl.set(url, handler);
  }

  factory(url) {
    const serverHandler = this._handlersByUrl.get(url);
    if (!serverHandler) {
      throw new Error(`No fake server for ${url}`);
    }
    const client = new FakeSocket();
    const server = new FakeSocket();
    client._peer = server;
    server._peer = client;
    serverHandler(server);
    queueMicrotask(() => {
      client._open();
      server._open();
    });
    return client;
  }
}

