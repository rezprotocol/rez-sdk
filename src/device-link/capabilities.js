import { CAP_DEVICE_SET_PUBLISH } from "@rezprotocol/core";

/**
 * The capabilities a device-link leaf cert grants — a MODULE CONSTANT, never
 * caller-chosen (confused-deputy guard, same posture as
 * DEVICE_SET_PUBLISH_CAPABILITY). Depth-1 launch: no capability.delegate, no
 * capability.revoke, no device.revoke — a linked device can message and
 * publish its device set, nothing more. Widening this list is a security
 * decision, not a parameter.
 *
 * The publish capability is sourced from rez-core's CAP_DEVICE_SET_PUBLISH
 * (audit leaf-3c F6) so this list cannot drift from the node's authorization
 * vocabulary. ("peerLink.create" has no core constant yet — left as a literal.)
 */
export const DEVICE_LINK_LEAF_CAPABILITIES = Object.freeze(["peerLink.create", CAP_DEVICE_SET_PUBLISH]);
