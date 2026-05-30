import { decodeOuterPacket as decodeOuterPacketCore } from "@rezprotocol/core";

export function decodeOuterPacket(bytes) {
  return decodeOuterPacketCore(bytes);
}
