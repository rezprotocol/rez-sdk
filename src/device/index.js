export {
  deriveDeviceIdFromPublicKeyB64,
  generateDeviceKeyPair,
  buildSignedDeviceRegistration,
  buildSignedDeviceInboxBinding,
  buildSignedAccountDeviceMutation,
  buildSignedAccountAuthorityState,
  verifyDeviceRegistration,
} from "./deviceIdentity.js";
// The dual-mode (direct B / delegated cert-chain) account-authority verifier
// — re-exported so app layers (rez-chat AE-1 OriginalMessage admission)
// reach it through the SDK boundary instead of importing rez-core directly.
export { verifyAccountAuthority } from "@rezprotocol/core";
