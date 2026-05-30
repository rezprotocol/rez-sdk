export { MailboxCapability } from "./MailboxCapability.js";
export { InboxesCapability } from "./InboxesCapability.js";
export { NodeCapability } from "./NodeCapability.js";
export { SubscriptionCapability } from "./SubscriptionCapability.js";
export { MeshCapability } from "./MeshCapability.js";
export { ConnectivityCapability } from "./ConnectivityCapability.js";
export { IdentityCapability } from "./IdentityCapability.js";

// Capability primitives (canonical in @rezprotocol/core; wrapped so the SDK
// client surface does not import @rezprotocol/core directly — see
// scripts/invariants.mjs scanRezSdkClientSurface).
export { RCapability, CapabilitySigner, CapabilityValidator } from "@rezprotocol/core";
