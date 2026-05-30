/**
 * Abstract base class for SDK transports.
 * Concrete implementations: WsTransport, TcpTransport
 */
export class Transport {
  async connect() {
    throw new Error("Transport.connect() is abstract");
  }

  async close() {
    throw new Error("Transport.close() is abstract");
  }

  isConnected() {
    throw new Error("Transport.isConnected() is abstract");
  }

  async sendFrame(frame) {
    throw new Error("Transport.sendFrame() is abstract");
  }

  async sendRequest({ type, body, expectedResponseType, timeoutMs }) {
    throw new Error("Transport.sendRequest() is abstract");
  }

  onFrame(handler) {
    throw new Error("Transport.onFrame() is abstract");
  }

  onState(handler) {
    throw new Error("Transport.onState() is abstract");
  }
}
