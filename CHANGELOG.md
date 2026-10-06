# Changelog

All notable changes, newest first. Format: Keep a Changelog;
versions: SemVer.

## [Unreleased]

### Added

- `serve`: bind and answer until Ctrl-C, printing its address as JSON.
- `ping`: ask a hub if it is alive, text or `--json`.
- `GET /ping`: the versioned envelope, plus 404 envelopes everywhere else.
- `db::open`: the SQLite store (0700 dir, WAL, `meta` table).
