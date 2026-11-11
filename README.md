# @rezprotocol/sdk

App-facing runtime SDK for Rez.

## Developer preview: 0.6.0-rc.14

Use Node 24 or newer for the packaged connection example:

```sh
npm install @rezprotocol/sdk@0.6.0-rc.14
node node_modules/@rezprotocol/sdk/examples/connect.mjs
```

The developer channel is also available as `npm install @rezprotocol/sdk@next`.
Use the explicit version above for a reproducible installation.

The example creates a disposable identity, authenticates to
`wss://chat.rezprotocol.io/ws`, calls `node.status` and shuts down. It never
prints private keys. Set `REZ_UPLINK` to use your own node. Core is installed
automatically at the matching release version; applications consume the SDK.
For a source checkout, install from the polyrepo workspace root.

This is an early developer network. Retain application keys and local state in
protected storage, handle disconnects and retryable failures, and use test data.
Hosted durability currently relies on one database host and recovery backups.
Transport acceptance is separate from your application's recipient delivery
receipt. Rez Chat's invites, groups and message statuses are application logic;
they are not an SDK chat API. Phone/native release acceptance is separate.

## Purpose

`@rezprotocol/sdk` hides protocol/crypto internals behind higher-level client APIs so app code can integrate Rez without handling core primitives directly.

## Browser app usage

```js
import { RezClient } from "@rezprotocol/sdk/client";

const rez = new RezClient({
  uplinks: ["ws://localhost:8787/ws"],
  identity: {
    accountId,
    deviceId,
    publicKeyB64,
    privateKeyB64,
  },
});

rez.on("start", () => console.log("Rez SDK starting"));
rez.on("ready", () => console.log("Rez SDK ready"));
rez.on("connect", () => console.log("Rez node connected"));
rez.on("disconnect", () => console.log("Rez node disconnected"));
rez.on("stop", () => console.log("Rez SDK stopped"));
rez.on("error", (event) => console.error(event.message));

await rez.start();
await rez.connect();
const status = await rez.node.status();
```

`createRezClient(options)` remains supported as a compatibility wrapper around `new RezClient(options)`.

## Lifecycle

SDK constructors are synchronous and inert. They validate options and wire local objects, but they do not connect to nodes, open storage, start polling, or mutate remote state.

- `start()` initializes local async resources.
- `connect()` starts node/uplink interaction. Calling `connect()` before `start()` runs `start()` first.
- `disconnect()` closes network interaction.
- `stop()` tears down the started SDK runtime.

Canonical lifecycle events are `start`, `ready`, `connect`, `disconnect`, `stop`, and `error`.

## Lexicon

- **Peer Link**: encrypted relationship between accounts/devices.
- **Inbox**: app-facing store-and-forward delivery target.
- **Envelope**: protocol/internal wrapper hidden by normal SDK APIs.
- **Mailbox**: wire/protocol family name; SDK docs should prefer Inbox for app-facing APIs.
- **Channel**: reserved for `channel.*` protocol contracts.

## Capabilities

Higher-level features are exposed as capabilities on the client facade:

- **WalletCapability** — Service Credit balances and settlement receipts for paid services. The wallet account is the account identity key, stored under its derived `rez:acct:*` form.
- **HandlesCapability** — claiming and renewing paid `@handles`.

Core messaging is free; paid services settle against Service Credits (off-chain during beta). The REZ token economy these capabilities are structured around is documented in [`rez-contracts`](https://github.com/rezprotocol/rez-contracts).

## Notes

- Protocol/crypto primitive ownership remains in `@rezprotocol/core`.
- App runtime code should consume SDK facade APIs.

---

## Related projects

- [**rez-core**](https://github.com/rezprotocol/rez-core) — cryptographic primitives + protocol records (the SDK's foundation)
- [**rez-node**](https://github.com/rezprotocol/rez-node) — relay node runtime that the SDK connects to
- [**rez-ui**](https://github.com/rezprotocol/rez-ui) — shared UI framework
- [**rez-chat**](https://github.com/rezprotocol/rez-chat) — reference desktop chat application
- [**rez-contracts**](https://github.com/rezprotocol/rez-contracts) — Solidity contract suite for the REZ token economy

For protocol-level documentation (capability model, identifiers, wire contracts, message lifecycle), see [`rez-core/docs/`](https://github.com/rezprotocol/rez-core/tree/main/docs).

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Security disclosures: see [SECURITY.md](./SECURITY.md).

## License

Apache 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
