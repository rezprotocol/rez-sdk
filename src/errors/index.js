export class SdkError extends Error {
  constructor(code, message, { retryable = false, cause = null } = {}) {
    super(message);
    this.name = "SdkError";
    this.code = code;
    this.retryable = retryable;
    if (cause) this.cause = cause;
  }
}

export class AuthFailure extends SdkError {
  constructor(message, opts = {}) {
    super("AUTH_FAILURE", message, { retryable: false, ...opts });
    this.name = "AuthFailure";
  }
}

export class UplinkUnavailable extends SdkError {
  constructor(message, opts = {}) {
    super("UPLINK_UNAVAILABLE", message, { retryable: true, ...opts });
    this.name = "UplinkUnavailable";
  }
}

export class RoutingUnavailable extends SdkError {
  constructor(message, opts = {}) {
    super("ROUTING_UNAVAILABLE", message, { retryable: true, ...opts });
    this.name = "RoutingUnavailable";
  }
}

export class RetryableTransportFailure extends SdkError {
  constructor(message, opts = {}) {
    super("TRANSPORT_FAILURE", message, { retryable: true, ...opts });
    this.name = "RetryableTransportFailure";
  }
}

export class PermanentValidationFailure extends SdkError {
  constructor(message, opts = {}) {
    super("VALIDATION_FAILURE", message, { retryable: false, ...opts });
    this.name = "PermanentValidationFailure";
  }
}

export class AuthorizationFailure extends SdkError {
  constructor(message, opts = {}) {
    super("AUTHORIZATION_FAILURE", message, { retryable: false, ...opts });
    this.name = "AuthorizationFailure";
  }
}

export class ReauthRequired extends SdkError {
  constructor(message, opts = {}) {
    super("REAUTH_REQUIRED", message, { retryable: true, ...opts });
    this.name = "ReauthRequired";
  }
}

export class CapabilityUnavailable extends SdkError {
  constructor(message, opts = {}) {
    super("CAPABILITY_UNAVAILABLE", message, { retryable: false, ...opts });
    this.name = "CapabilityUnavailable";
  }
}

export class ConnectionTimeout extends SdkError {
  constructor(message, opts = {}) {
    super("CONNECTION_TIMEOUT", message, { retryable: true, ...opts });
    this.name = "ConnectionTimeout";
  }
}

export class RequestTimeout extends SdkError {
  constructor(message, opts = {}) {
    super("REQUEST_TIMEOUT", message, { retryable: true, ...opts });
    this.name = "RequestTimeout";
  }
}
