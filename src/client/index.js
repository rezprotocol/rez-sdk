// --- New SDK public API ---
export { createRezClient, createRezClientAsync } from "./createRezClient.js";
export { RezClient } from "./RezClient.js";
export { RezPayloadSendParams } from "./RezPayloadSendParams.js";
export { SDK_EVENTS } from "../events/SdkEvents.js";
export { TypedEventBus } from "../events/TypedEventBus.js";
export { CONNECTION_STATES } from "../connection/ConnectionState.js";
export { AUTH_STATES } from "../auth/AuthStateMachine.js";

// Error taxonomy
export {
  SdkError,
  AuthFailure,
  UplinkUnavailable,
  RoutingUnavailable,
  RetryableTransportFailure,
  PermanentValidationFailure,
  AuthorizationFailure,
  ReauthRequired,
  CapabilityUnavailable,
  ConnectionTimeout,
  RequestTimeout,
} from "../errors/index.js";

// Capabilities
export {
  MailboxCapability,
  NodeCapability,
  SubscriptionCapability,
  MeshCapability,
  ConnectivityCapability,
  IdentityCapability,
  InboxesCapability,
} from "../capabilities/index.js";

// Inbox-claim store (SDK-side persistence of inbox claimant material)
export { InboxClaimStore } from "../inbox/InboxClaimStore.js";

// Observability
export { MetricsCollector } from "../observability/MetricsCollector.js";

// Invite codes (browser-safe, no rez-node dependency)
export { isInviteCodeV2, parseInviteCodeV2, encodeInviteCodeV2 } from "../util/inviteCodeV2.js";

// --- Existing exports (backward-compat) ---
export { createDefaultCodecChain } from "../defaults/createDefaultCodecChain.js";
export { createDefaultLogger, RRecord, Identity, deriveAccountIdFromPublicKey } from "../defaults/createDefaultLogger.js";
export { createDefaultStorageProvider } from "../defaults/createDefaultStorageProvider.js";
export { RezRuntimeBuilder } from "../builders/RezRuntimeBuilder.js";
export {
  encodeEnvelope,
  decodeEnvelope,
  verifyEnvelope,
  signEnvelope,
  resolveSessionIdentity,
} from "../protocol/index.js";
export * from "../keystore/index.js";
export { IndexedDbStorageProvider } from "../storage/IndexedDbStorageProvider.js";
export { bytesToBase64, base64ToBytes } from "../util/bytes.js";
export {
  SecureChannelManager,
  E2eePacketCodec,
  X3DHKeyExchange,
  BrowserCryptoProvider,
  E2eeDeliveryAckV1,
  E2eeHandshakeAckV1,
  E2eeRehandshakeRequestV1,
} from "../e2ee/index.js";
export { REZ_CONTRACT_TYPES } from "../contracts/index.js";
export { RCapability, CapabilitySigner, CapabilityValidator } from "../capabilities/index.js";
export { canonicalJSONStringify } from "../util/canonical.js";
export { UplinkPoolClient } from "./UplinkPoolClient.js";
export { WsConnection } from "./WsConnection.js";
export { WARN_CODES } from "../pool/WarnCodes.js";
export { createFrameCodec as createJsonFrameCodec } from "../transport/FrameCodec.js";
export { asInt, nonEmpty, requireId } from "../util/coerce.js";

// Bridge infrastructure (wrapped via rez-sdk/bridge to avoid direct @rezprotocol/core import)
export {
  BRIDGE_FRAME_TYPES,
  BRIDGE_ERROR_CODES,
  BridgeRequest,
  BridgeResponse,
  BridgeEvent,
  BridgeRouter,
} from "../bridge/index.js";
