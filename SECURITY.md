# Security Policy

`@rezprotocol/sdk` is the client runtime SDK for the Rez protocol. It is consumed by every Rez application; vulnerabilities here can compromise end users.

## Reporting a Vulnerability

**Please do not open public issues for suspected vulnerabilities.**

Use [GitHub Security Advisories](https://github.com/rezprotocol/rez-sdk/security/advisories/new) to report privately. Only the reporter and the repository maintainers can view the report.

## What to expect

- **Acknowledgement** within 72 hours.
- **Initial assessment** (severity, scope, reproduction) within 7 days.
- **Fix + coordinated disclosure** within 90 days of report — sooner for high-severity issues.
- **Credit** in the security advisory and release notes if you'd like (let us know).

## Scope

In scope:
- Session lifecycle issues that expose key material or break ratchet state
- Keystore / identity binding bypasses
- Peer-link handshake / authentication flaws
- Uplink connection-pool misuse that bypasses authentication
- Bus / IPC issues that allow privilege escalation between renderer and main process

Out of scope:
- Social engineering of users
- Attacks requiring active access to the user's device or keystore
- Issues affecting only un-tagged `main`-branch code

## Threat model and posture

Cross-package threat model and audit history live in [`rez-core`](https://github.com/rezprotocol/rez-core):
- [`docs/security.md`](https://github.com/rezprotocol/rez-core/blob/main/docs/security.md) — threat model + guarantees
- [`docs/SECURITY_POSTURE.md`](https://github.com/rezprotocol/rez-core/blob/main/docs/SECURITY_POSTURE.md) — audit history + disclosure posture
