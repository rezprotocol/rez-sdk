export const SDK_EVENTS = Object.freeze({
  // Connection lifecycle
  LIFECYCLE_START: "start",
  LIFECYCLE_READY: "ready",
  LIFECYCLE_CONNECT: "connect",
  LIFECYCLE_DISCONNECT: "disconnect",
  LIFECYCLE_STOP: "stop",
  LIFECYCLE_ERROR: "error",

  // Detailed SDK state changes
  CONNECTION_STATE_CHANGED: "sdk.connection.stateChanged",
  CONNECTION_HEALTH_CHANGED: "sdk.connection.healthChanged",

  // Auth lifecycle
  AUTH_STATE_CHANGED: "sdk.auth.stateChanged",
  AUTH_AUTHENTICATED: "sdk.auth.authenticated",
  AUTH_REAUTH_REQUIRED: "sdk.auth.reauthRequired",

  // Transport
  TRANSPORT_UPLINK_CHANGED: "sdk.transport.uplinkChanged",
  TRANSPORT_RECONNECTING: "sdk.transport.reconnecting",
  TRANSPORT_RECONNECTED: "sdk.transport.reconnected",

  // Session
  SESSION_READY: "sdk.session.ready",
  SESSION_LOST: "sdk.session.lost",

  // Observability
  METRIC: "sdk.metric",
  WARN: "sdk.warn",
});
