// E2EE classes are canonical in @rezprotocol/core; re-export for backward compat
export {
  SecureChannelManager,
  E2eePacketCodec,
  X3DHKeyExchange,
  E2eeDeliveryAckV1,
  E2eeHandshakeAckV1,
  E2eeRehandshakeRequestV1,
} from "@rezprotocol/core";
export { BrowserCryptoProvider } from "./BrowserCryptoProvider.js";
