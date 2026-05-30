import { CodecChain, CanonicalizeCodec, JsonCodec } from "@rezprotocol/core";

export function createDefaultCodecChain() {
  return new CodecChain([new CanonicalizeCodec(), new JsonCodec()]);
}
