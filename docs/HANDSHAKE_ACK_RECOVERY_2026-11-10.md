# Handshake acknowledgement recovery — 2026-11-10

Status: clean-source tests and web build pass; staged/live browser acceptance pending.

The hosted byte-bounded mailbox can return a short first page containing an
old connection-confirmation acknowledgement followed by a file manifest and
one image chunk. After a refresh, the SDK rejected that acknowledgement
because the peer link was already established. The client therefore kept its
consumed cursor below the acknowledgement and could not fetch later pages.
Live Chrome traces returned the same three-event, 766,410-byte first page;
the problem was no longer an oversized WebSocket frame.

## Changes and verification

- `rez-sdk/src/peer-link/PeerLinkService.js`: authenticate acknowledgement
  replay against the stored peer signing key and signature. Check any pending
  nonce, then return the current snapshot without changing an established
  session, ratchet, route, display name or lifecycle history.
- Pending confirmation now requires its stored nonce. Delete it only after
  confirmation is durable, so a storage failure retains an authenticated retry.
- `rez-core/src/e2ee/E2eeHandshakeAckV1.js`: clarify pending confirmation and
  authenticated, mutation-free replay in the canonical record contract.
- `rez-chat/test/peerlink.commit-convergence.test.js`: real signed handshake,
  service restart, unchanged ratchet/link, forged replay, missing/mismatched
  nonce and injected session-read failure followed by successful retry.

The replay, missing-nonce and premature-cleanup regressions fail before their
respective repairs. Final clean candidate: **533 SDK tests pass**, **44 focused
Chat/recovery/architecture/PWA tests pass**, zero failures or skipped tests.
Production web build and integrity injection pass. Existing large-bundle
warning remains; build configuration/dependencies were not changed.

## Required focused audit

Specs checked: `E2eeHandshakeAckV1` authentication chain; SDK peer-link state
machine and single `#commitSession` writer; durable inbox's contiguous consumed
cursor; Chat inbound dedup and catch-up contracts; service-worker navigation
and immutable-asset caching.

Canonical owners: Core owns the signed acknowledgement record and vocabulary;
SDK owns peer-link authentication/state; Chat owns catch-up orchestration and
integration acceptance. No protocol behavior moves into UI or transport.
Duplicate/split-brain findings: none added; confirmation uses the existing
commit writer and replay has no second state writer. Boundary/SSOT findings:
no new wire or storage shape, dependency or dispatch method. Hidden transforms:
old signed routing/display fields never overwrite current state on replay.
God-class finding: `PeerLinkService` is an existing large orchestration class;
this fix remains inside its acknowledgement responsibility. Whole-class
decomposition was not audited or attempted. Dead code removed: premature
nonce cleanup; no unrelated cleanup. Tests updated: the convergence test and
its real-handshake fixture. No unresolved finding in changed code/direct
dependencies after the nonce-ordering repair.

Uncommitted runtime-ownership/native-storage work is excluded from the clean
candidate and commits. iPhone and Swift sources remain untouched.

## Remaining acceptance work

Staged client acceptance and recovery of partially processed older transfers
are not yet proven. This does not add persistent chunk reassembly, on-demand
media retrieval or image delivery receipts. Those claims must not be inferred
from acknowledgement replay. The earlier live notification timeout is also
under separate investigation. New tester invitations remain on hold.

Evidence: `/tmp/rez-client-acceptance-20261110/ack-*`,
`routing-chrome-image-profile.log`, and the clean source/build fixture at
`/tmp/rez-web-recovery-20261110/`.
