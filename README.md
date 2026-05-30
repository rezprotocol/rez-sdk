# @rezprotocol/sdk

App-facing runtime SDK for Rez.

## Purpose

`@rezprotocol/sdk` hides protocol/crypto internals behind higher-level client APIs so app code can integrate Rez without handling core primitives directly.

## Browser app usage

```js
import { RezClient } from "@rezprotocol/sdk/client";

const rez = new RezClient({
  uplinks: ["ws://localhost:8787/ws"],
  identity: {
    accountId,
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

## Notes

- Protocol/crypto primitive ownership remains in `@rezprotocol/core`.
- App runtime code should consume SDK facade APIs.

---

## Related projects

- [**rez-core**](https://github.com/rezprotocol/rez-core) — cryptographic primitives + protocol records (the SDK's foundation)
- [**rez-node**](https://github.com/rezprotocol/rez-node) — relay node runtime that the SDK connects to
- [**rez-ui**](https://github.com/rezprotocol/rez-ui) — shared UI framework
- [**rez-chat**](https://github.com/rezprotocol/rez-chat) — reference desktop chat application

For protocol-level documentation (capability model, identifiers, wire contracts, message lifecycle), see [`rez-core/docs/`](https://github.com/rezprotocol/rez-core/tree/main/docs).

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Security disclosures: see [SECURITY.md](./SECURITY.md).

## License

Apache 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
