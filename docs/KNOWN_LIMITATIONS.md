# Known limitations

Things the SDK does not currently guarantee, written down so they are discovered
here rather than in the field.

---

## The atomic-commit gap (DT-302)

**A message can be lost — not corrupted — if storage rejects a write at one
specific instant during decryption.**

### What actually happens

Decrypting a packet advances the Double Ratchet. That advance has to be written
down, because the ratchet key that opened this packet is destroyed by opening it:
that is the forward secrecy the ratchet exists to provide. So a decrypt is really
two things — *open the packet* and *record that we opened it* — and they are not
one atomic operation.

Three outcomes:

| The ratchet write… | Result |
|---|---|
| succeeds | Normal. Message delivered. |
| **never reaches storage** | **Nothing is lost.** The stored ratchet is unchanged, so the packet is still openable and a later drain decrypts it cleanly. |
| **lands and is then rejected** | **That one packet is lost.** The stored ratchet has advanced past it, and the key that would open it is gone. |

Only the third row loses anything, and it is narrow: the write has to have taken
effect *and then* be reported as failed.

### What it does not do

- **It does not corrupt anything.** The ratchet is in a valid state either way.
- **It does not break the conversation.** Subsequent messages decrypt normally;
  the ratchet has advanced to a consistent point.
- **It does not lose more than the packets in flight at that moment.** This is not
  a cascade.
- **It is not silent.** See below.

### What it looks like when it happens

DT-007 made this fail loud rather than closing the gap. On a degraded commit the
SDK returns a typed `PeerLinkCommitErrorV1` on the decrypt result (`commitError`),
carrying the stage it failed at — one of `session-write`, `peer-link-transition`,
or `event-append`.

In Rez Chat that surfaces as a logged warning plus an `app.error` event:

```
[ServerPeerLinkProtocolService] decrypt commit degraded (session-write): <reason>
```

For a tester, the visible symptom is a message that never appears, with that
warning in the diagnostics bundle at the same moment. If you see it, the bundle is
worth attaching to a report — it is the difference between "a message went
missing" and "a message went missing *for this reason, at this stage*."

### Why it is open rather than fixed

Closing it needs a genuinely atomic commit across the ratchet write and the
replay commitment — that is DT-302's job, and it is a design question about
storage guarantees, not a patch. DT-007 deliberately narrowed the blast radius
first: a rejected write now fails closed and reports itself, instead of leaving
plaintext delivered on the strength of a write nobody confirmed.

The ordering was on purpose. A loud, bounded gap is a fine thing to ship; a silent
one is not.

### Exposure in practice

Storage rejecting a write *after it has taken effect* is not a routine event — it
implies a disk error, a quota rejection, or a backend fault mid-transaction. For a
single-user desktop install on local storage it is rare. It is more plausible on a
hosted Postgres home under failure conditions.
