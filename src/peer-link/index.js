// rez-sdk peer-link entry — the canonical home for PeerLinkService and the
// KV-backed peer-link storage bundle.
//
// These were previously in rez-node; they moved to rez-sdk in the Shape A
// migration so that SDK clients (chat-server, future apps) hold the crypto
// state and a hosted node never sees plaintext. See docs/CAPABILITY_MODEL.md
// and project_relay_network_thesis.md (memory).
//
// This subpath is server-side only — it uses `node:crypto`. Browser-bundled
// callers should not import from here.

export { PeerLinkService } from "./PeerLinkService.js";
export { createKeyValueBackedPeerLinkStorage } from "./createKeyValueBackedPeerLinkStorage.js";
export { canonicalPayloadBytesV1 } from "./inviteCodeV1.js";
