# Contributing to @rezprotocol/sdk

Thanks for considering a contribution. `@rezprotocol/sdk` is the client runtime layer; bugs here are visible to every Rez application end-user. Please read this before opening a PR.

## Getting started

```bash
git clone https://github.com/rezprotocol/rez-sdk.git
cd rez-sdk
npm install
npm test
```

## Code style

This codebase is **vanilla JavaScript, ESM only**.

- ES2022+: async/await, classes, native `import` / `export`
- `#privateField` / `#privateMethod()` for private members; `_protectedMethod()` convention for protected
- **No optional chaining (`?.`)** — use explicit `if` / `===` checks
- **No empty `catch` blocks** — every caught exception must be handled or re-thrown
- No TypeScript, no Babel/SWC, no transpilation
- Tests use Node's built-in `node:test` runner

## Architecture

The SDK is a **facade**: it hides protocol/crypto internals from app code. Adding directly-exposed protocol primitives or wire types to the SDK public API is a layering violation — those belong in [`@rezprotocol/core`](https://github.com/rezprotocol/rez-core).

- Protocol/crypto primitive ownership lives in `@rezprotocol/core`
- App runtime code should consume SDK facade APIs, not core directly
- The SDK's lifecycle is `start()` → `connect()` → `disconnect()` → `stop()`; constructors are synchronous and inert

Layer responsibilities across all Rez packages: [`rez-core/docs/ARCHITECTURE_GUARANTEES.md`](https://github.com/rezprotocol/rez-core/blob/main/docs/ARCHITECTURE_GUARANTEES.md).

## Tests

```bash
npm test
```

All PRs must pass tests. Changes that touch peer-link, session, or keystore code require new test coverage demonstrating the change works against an un-mocked SDK + node integration — mocked-only tests have historically hidden crypto-correctness bugs in this codebase.

## Pull request process

1. Fork → branch → push.
2. Open a PR against `main`.
3. Describe the change concretely (what + why; the *what* should match the diff).
4. CI runs tests.
5. Maintainer review.

## Licensing

By submitting a contribution, you agree that your contribution will be licensed under the Apache License 2.0, the license of this repository (per Section 5 of the Apache License).

## Security disclosures

Please do **not** open public issues for security vulnerabilities. See [SECURITY.md](./SECURITY.md) for the disclosure process.
