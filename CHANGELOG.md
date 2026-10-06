# Changelog

All notable changes, newest first. Format: Keep a Changelog;
versions: SemVer.

## [Unreleased]

### Added

- `serve`: bind and answer until Ctrl-C, printing its address as JSON.
- `ping`: ask a hub if it is alive, text or `--json`.
- `GET /ping`: the versioned envelope, plus 404 envelopes everywhere else.
- `db::open`: the SQLite store (0700 dir, WAL, `meta` table).
- Devices, checks, results, heartbeats, approvals, notify: full routes
  with same-day CLI twins, plus the `tests/cli_parity.rs` gate that
  fails CI when a route lacks its twin.
- The hub probes its own `url`/`api`/`heartbeat` checks on cadence;
  flips queue `health.flip` notifications for the delivery drivers.
