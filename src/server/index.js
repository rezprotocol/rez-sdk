// rez-sdk's server entry. Previously this re-exported rez-node concerns
// (startRezNode, RezNode, FsStorageProvider, NodeCryptoProvider, RezRestServer)
// as a convenience for chat — but that created a dep direction (sdk → node)
// that contradicts the architecture (sdk uses core; node uses sdk + core).
// Consumers should import those directly from "@rezprotocol/node".
//
// This entry keeps only protocol/codec primitives that are sdk-shaped.
export { encodeOuterPacket, decodeOuterPacket, bytesToRoutingKey, assertContractTree, JsonCodec, verifyReceiptV1, Hash } from "@rezprotocol/core";
export { createFrameCodec as createJsonFrameCodec } from "../transport/FrameCodec.js";
