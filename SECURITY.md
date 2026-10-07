# Security

## Threat model

Single user, three surfaces: a VPS API, a Mac, a phone. The hub holds
operational state (checks, results, device records, queued envelopes)
— never the vault master key, which stays on the Mac. Service
credentials reach the VPS only as individually deployed, revocable
values (see `est-vault push --verify`), never as the store.

- At rest: one SQLite file, `0700` dir, WAL mode; no secret bytes in
  the schema by design (tokens referenced, values never stored).
- In motion, one listener: plain HTTP on the tailnet IP only (18925 —
  WireGuard is the encryption; `0.0.0.0` is a deployment bug, and
  deploy checks refuse it). Access control is Tailscale membership:
  no public ingress, no client certificates, no owner-vs-device route
  split. The phone is a tailnet node; its HTTPS endpoint is
  `tailscale serve` on the hub host, with the certificate owned by
  Tailscale and no TLS code in the hub.
- Devices: a device is a name plus its reported push state. It
  registers itself (`PUT /devices/{name}` upserts over the tailnet);
  there is no ticket, no compare code, and no client certificate.
  Revocation is deleting the row (`devices revoke`), which also drops
  its Live Activity tokens and last-push stamp. Lost phone: revoke,
  reconnect from the new device.
- Push: APNs carries full alert text and Live Activity state (decided
  2026-10-06: notification content transits Apple over TLS so alerts
  arrive with the app closed and no VPN). The vault master key and raw
  secrets never enter a push, a cache row, or the hub.
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
