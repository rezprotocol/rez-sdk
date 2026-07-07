export { runDeviceLinkRequester } from "./DeviceLinkRequester.js";
export { DeviceLinkApprover } from "./DeviceLinkApprover.js";
export { deriveRendezvousKeyPair } from "./rendezvous.js";
export { DEVICE_LINK_LEAF_CAPABILITIES } from "./capabilities.js";
// The app layer (rez-chat) imports the code helpers through the SDK — it is
// forbidden from importing rez-core directly (workspace policy).
export {
  DEVICE_LINK_CODE_PREFIX,
  DEVICE_LINK_PSK_BYTES,
  encodeDeviceLinkCodeV1,
  parseDeviceLinkCodeV1,
  isDeviceLinkCodeV1,
  deviceLinkFingerprint,
} from "@rezprotocol/core";
