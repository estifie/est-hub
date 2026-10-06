# est-hub

One API on the tailnet for the whole EST ecosystem: health, devices,
approvals, and notifications. Phones, desktops, daemons, scripts, and
agents all talk to the same routes; state lives in one SQLite file.

Status: pre-release. The API is unstable until 1.0; the envelope shape
(`{"ok":…,"v":1}`) is stable. The hub holds operational state only —
it never sees the vault master key.

## Run

```sh
cargo install --path .   # or: cargo build, then ./../.target/debug/est-hub
est-hub serve --port 0 --db /tmp/hub-dev.sqlite   # prints its address
est-hub ping --hub http://100.120.126.23:18925
```

Deploy binds the tailnet IP on port `18925`, never `0.0.0.0`.

## Docs

- [API](docs/api.md): routes, envelopes, status codes.
- [CLI](docs/cli.md): `serve` and `ping` reference.
- [Agent runbook](docs/agent.md): operate the hub without a dashboard.

## Modules

| Module | Purpose |
|---|---|
| `api` | Routes and versioned JSON envelopes |
| `db` | The SQLite store: open, WAL, tables |

## Develop

```sh
git config core.hooksPath .githooks   # one-time: enable the repo hooks
cargo fmt --all -- --check            # gate 1: formatting
cargo clippy --all-targets -- -D warnings   # gate 2: lints
cargo test                            # gate 3: unit + HTTP tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow,
[SECURITY.md](SECURITY.md) for the threat model and reporting, and
[CHANGELOG.md](CHANGELOG.md) for what changed.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See
[LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
