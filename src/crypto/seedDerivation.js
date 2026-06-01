// SDK-side re-export of the BIP39-seed HKDF derivation helper implemented in
// @rezprotocol/core. See ./bip39.js for the rationale on why these live here
// as thin re-exports instead of being duplicated in the SDK.
export { SeedKeys } from "@rezprotocol/core/src/crypto/seedDerivation.js";
