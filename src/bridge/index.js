// Re-export bridge infrastructure from rez-core.
// This wrapper exists so rez-sdk/client surface doesn't import @rezprotocol/core directly.
export {
  BRIDGE_FRAME_TYPES,
  BRIDGE_ERROR_CODES,
  BridgeRequest,
  BridgeResponse,
  BridgeEvent,
  BridgeRouter,
} from "@rezprotocol/core";
