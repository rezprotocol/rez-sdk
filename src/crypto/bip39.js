// SDK-side re-export of the BIP39 mnemonic primitives implemented in
// @rezprotocol/core. rez-chat (and any other workspace forbidden from
// importing rez-core directly) gets at them through here. Same shape, same
// behavior — this file is intentionally thin so there is exactly one
// implementation in the monorepo.
export { Bip39 } from "@rezprotocol/core/src/crypto/bip39.js";
