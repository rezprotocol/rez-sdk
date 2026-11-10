# Responsive startup and attachment recovery — 2026-11-10

Status: committed, pushed and publicly deployed at 2026-11-10 23:51:23 UTC;
clean-source verification and live Chrome/Firefox interrupted-transfer
acceptance pass.

Source commits: Core `4da269f`, SDK `46509ee`, Chat `02f27df`. The isolated
build excludes unrelated working changes, including the extra IndexedDB
ownership hunks. Entry SHA-256:
`d8a175580df0635cdbf8f04903dbfdc1a72de4cd00d8972f2b9f16d661394c89`;
entry script `assets/index-BYcczCDv.js`. The server verified every artifact
hash, retained the previous public entry and old hashed assets, atomically
promoted this entry, fetched and byte-compared it, and passed `/ready` with
storage/Redis healthy and no degradation. Release:
`/opt/rez/releases/web-background-20261110/`. Temporary public test HTML pages
were removed. Existing service-worker network-first navigation picks this up
on normal refresh; saved browser data must remain intact. No network-node
redeploy or wire migration is needed for this client-only slice.

The UI previously waited for initial inbox catch-up, and file reassembly kept
chunks only in memory. Refresh could therefore discard bytes whose deposits
were already acknowledged. Browser storage mutations also resolved at request
success, before their transaction could still abort.

## Changes and ownership

- Core `src/filetransfer/FileTransferSessionV1.js` and its new context test:
  extend the existing local record with authenticated sender/context binding;
  preserve explicit legacy null/null records without trusting them for resume.
  Transfer and manifest identities must match. No wire format changes.
- SDK `src/filetransfer/FileTransferService.js`, existing service tests and
  new recovery tests: persist existing `FileChunkV1` records before receipts;
  reconcile the chunk/bitmap crash window; validate context, hash and size;
  await application completion, then persist completion before chunk cleanup.
  Retain a small bound session for replay without duplicate projection.
- SDK `src/storage/IndexedDbStorageProvider.js` and six new commit-completion
  tests: put/delete/clear wait for transaction completion and reject an abort
  even after request success. Only these three changes are included; unrelated
  storage/native/runtime-ownership work is excluded.
- Chat `ServerFileTransferService.js` and its tests: persist chat channel
  metadata, propagate completion failures, repair a partial message/index
  projection under its original timestamp, and reuse the stable inbound ID.
- Chat `ChatServerApp.js`, `InboxCatchupService.js`, `ConnectionService.js`
  and new background/order regressions: expose local services after runtime
  binding and consumer activation while initial catch-up proceeds; preserve
  the separate sync signal, visible failures and shutdown generation guard.
- Chat hosted-web acceptance now interrupts a real image after a committed
  chunk and server cursor acknowledgement, exercises sending while later
  pages are blocked, then reopens the same browser storage and verifies exact
  image bytes/rendering without replaying the consumed first page.

SDK owns one local eager-transfer budget: 64 MiB / 1,024 chunks. It protects
sender chunking and receiver allocation; it is unrelated to the earlier
1 MB transport-frame limit. Files still use the existing 64 KiB push chunks.

## Verification

Isolated clean source, excluding all unrelated working changes:

- Core full suite: **582 pass**, zero failures/skips.
- SDK full suite: **549 pass**, zero failures/skips.
- Chat full suite: **1,118 pass, zero fail, three explicitly gated native/live
  integration tests not run**; isolated SDK portability **2 pass**.
- Extra background/sync-order cases: **5 pass**, zero failures/skips.
- Focused inbox/file/authentication/architecture integration: **63 pass**,
  zero failures/skips (overlaps the full suite).
- Production web build and integrity injection pass. Existing bundle-size
  warning remains. No dependency or tooling configuration changed. The
  isolated existing SQLite dependency was rebuilt to run its real tests.

The three opt-in tests launch native Electron/live-relay workflows; they do
not certify the published desktop release. Live Chrome **41.9 s** and Firefox
**40.1 s** complete workflows both pass with zero failures/skips: a confirmed
consumed page, committed local chunk, usable UI and successful send while
later pages are blocked, then restart, exact 1.7 MB PNG/render recovery without
consumed-page replay, and reverse reply. Unlock-to-usable measured **1.832 s
in Chrome / 1.856 s in Firefox**. These are synthetic observations, not a
promise for every connection. Evidence:
`/tmp/rez-client-acceptance-20261110/background-*`.

Post-promotion public Firefox login/invite/first-message/offline-reopen/reply
also passes: **1 test**, 12.3 seconds; existing-contact unlock **1.759 s**,
first-message receive **342 ms**. Source staging was byte-compared with the
clean tested candidate. Unrelated Core/Chat/Node tracked-diff hashes and SDK
unrelated diffs/full mixed IndexedDB working-file hash are unchanged.

## Required focused audit

Specs checked: Core file manifest/chunk/session contracts and reassembly;
SDK KeyValueStore/IndexedDB encryption and mutation semantics; Chat
`CHAT_APP_SPEC.md` section 13; runtime terminal-vs-retryable binding; durable
apply-outbox/cursor ordering; message/index idempotence; generic ChatBridge
events and UI sync store. Existing caught-up semantics include bounded
undecryptable retries; this does not certify every historical item applied.

Canonical owners: Core owns shared file records and cryptographic vocabulary;
SDK owns transfer validation/reassembly/persistence and browser storage; Chat
owns channel/message/index semantics and startup orchestration; UI renders
connection/sync state. Node wire records and authenticated mailbox authority
are unchanged. No new wire records, transport directives or cross-layer
imports were added.

Duplicate/split-brain findings: volatile chunk buffers and transient channel
maps were removed; existing records and one projection identity are reused.
One byte/chunk budget guards both transfer directions. Boundary/SSOT findings:
no unresolved violation in changed code/direct dependencies; generic transport
and Chat-to-Core boundary tests pass. No protocol logic moved into Chat/UI.
Hidden-transform/invariant findings: persisted receipts cannot outrun committed
bytes, context cannot rebind, failed projection remains retryable, cache bytes
are hash checked, and background activation cannot bypass static wiring/auth.
God-class findings: existing ChatServerApp remains orchestration; no new mixed
responsibility or god module introduced. Whole-class decomposition and the
entire product were not audited. Dead code removed: the in-memory chunk and
channel maps and premature request-success resolution. Tests added/updated:
the record, storage, file recovery, projection, startup, event-order and hosted
browser cases listed above. No unresolved finding in the focused audit.

## Remaining limitations

This is not true on-demand media retrieval, streaming reassembly or an
off-main-thread worker. Large files still consume eager decode/reassembly
memory and CPU. The eager byte/chunk bounds limit exposure; total retained
incomplete-transfer/cache quotas and garbage collection remain future work.
Older interrupted files whose bytes were already discarded may need sender
resend. No account reset or site-data deletion is appropriate. Image sender
delivery receipts still need their canonical application identity/completion
contract. Native desktop packaging, custody and release gates remain open.
iPhone and Swift sources are untouched. New tester invitations remain on hold
for the recorded client/release limitations.
