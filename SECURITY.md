# Security

## Threat model

Single user, three surfaces: a VPS API, a Mac, a phone. The hub holds
operational state (checks, results, device records, queued envelopes)
— never the vault master key, which stays on the Mac. Service
credentials reach the VPS only as individually deployed, revocable
values (see `est-vault push --verify`), never as the store.

- At rest: one SQLite file, `0700` dir, WAL mode; no secret bytes in
  the schema by design (tokens referenced, values never stored).
- In motion: plain HTTP, bound to the tailnet IP only — WireGuard is
  the encryption. The bind address is the access control; `0.0.0.0`
  is a deployment bug, and deploy checks refuse it.
- Devices: paired keys only (see the pairing design); revocation is
  deleting a key. Lost phone: revoke, re-pair.
- Push: APNs carries envelope ids only, never content.
- Supply chain: committed `Cargo.lock`, `cargo audit` + `cargo deny`
  in CI, pinned GitHub Actions SHAs, no `unsafe` in this crate.

Out of scope: the VPS provider itself, the tailnet control plane, a
machine the attacker holds while unlocked, and a compromised Mac
(which holds the vault key by design — accepted, documented).

## Reporting

Do not open a public issue for a suspected vulnerability. Report it
through a [GitHub Security
Advisory](https://github.com/estifie/est-hub/security/advisories/new)
(private), including what you ran and what you observed. Aim: first
response within three days, fix or mitigation plan within two weeks
for anything that leaks secret bytes or opens the bind.

## Supported versions

Pre-1.0: only the latest `main` is supported. After 1.0, the latest
minor of the current major.
