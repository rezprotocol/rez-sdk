/**
 * The capabilities a device-link leaf cert grants — a MODULE CONSTANT, never
 * caller-chosen (confused-deputy guard, same posture as
 * DEVICE_SET_PUBLISH_CAPABILITY). Depth-1 launch: no capability.delegate, no
 * capability.revoke, no device.revoke — a linked device can message and
 * publish its device set, nothing more. Widening this list is a security
 * decision, not a parameter.
 */
export const DEVICE_LINK_LEAF_CAPABILITIES = Object.freeze(["peerLink.create", "deviceSet.publish"]);
