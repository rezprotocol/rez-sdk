import { RezClient, Identity, bytesToBase64 } from "@rezprotocol/sdk/client";

// A disposable development identity. A real app must retain its keys in its
// own protected storage; running this example again creates a new identity.
const identity = await Identity.generate();
const uplink = process.env.REZ_UPLINK || "wss://chat.rezprotocol.io/ws";
const client = new RezClient({
  uplinks: [uplink],
  identity: {
    accountId: identity.getAccountId(),
    deviceId: "rez:dev:example-" + globalThis.crypto.randomUUID(),
    publicKeyB64: bytesToBase64(identity.getPublicKeyBytes()),
    privateKeyB64: bytesToBase64(identity.getPrivateKeyBytes()),
  },
});

try {
  await client.start();
  await client.connect();
  await client.node.status();
  console.log("Connected to RezNet; authenticated node.status succeeded.");
} finally {
  await client.stop();
}
