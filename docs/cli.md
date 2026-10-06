# est-hub CLI

Serve the API, or talk to it. `--help` is the short version of this file.

```sh
est-hub serve [--bind IP] [--port N] [--db PATH]
est-hub ping [--hub URL]
est-hub devices add NAME [--pubkey K] [--apns T]
est-hub devices list
est-hub devices show NAME
est-hub devices revoke NAME --yes
est-hub checks add NAME --type T --target U --owner O [options]
est-hub checks list [--owner O]
est-hub checks show NAME
est-hub checks set NAME --type T --target U --owner O [options]
est-hub checks delete NAME --yes
est-hub results report --check NAME --ok|--fail [--code C] [--reason R]
est-hub results list --check NAME [--limit N]
est-hub heartbeats beat --check NAME
est-hub approvals request --title T [--body B] [--reply-to R] [--ttl S]
est-hub approvals list [--state S]
est-hub approvals show ID
est-hub approvals decide ID --approve|--reject [--by WHO]
est-hub notify send --title T [--body B] [--topic T] [--to DEV]
est-hub notifications list [--limit N]
```

## Conventions

- **Exit codes:** `0` ok, `1` failed, `2` wrong usage.
- **Errors** go to stderr as `est-hub: ...`; data goes to stdout.
- **`--json`** rides on any command and prints one JSON object instead
  of text: `{"ok":true,"v":1,...}` or `{"ok":false,"v":1,"error":"…"}`.
- **Destructive commands ask first** — unless `--yes` is passed or stdin
  is not a terminal, in which case they refuse rather than guess. Agents:
  always pass `--yes` (you already decided).
- Every hub route has its twin here, enforced by `tests/cli_parity.rs`.

## serve

Bind and answer until Ctrl-C, probing hub-run checks on their own
cadence. Prints one line on stdout when ready:

```json
{"ok":true,"v":1,"listening":"127.0.0.1:18925"}
```

Logs go to stderr (`EST_LOG` levels). Defaults: bind `127.0.0.1`,
port `18925`, db `~/.config/est/hub/hub.sqlite` (`EST_HUB_DB` or
`--db` override). Deploy binds the tailnet IP — never `0.0.0.0`.
`--port 0` picks an ephemeral port and prints it (the test pattern).

```sh
est-hub serve --bind 100.120.126.23 --db /var/lib/est-hub/hub.sqlite
```

## ping

Ask a hub if it is alive. Reads `--hub`, `EST_HUB_URL`, else the local
default (`http://127.0.0.1:18925`).

```sh
est-hub ping --hub http://100.120.126.23:18925
est-hub ping --json   # the /ping body verbatim
```

## devices

Registry only until mTLS (P3) enforces it. `revoke` deletes the row —
gone means gone.

```sh
est-hub devices add iphone
est-hub devices revoke iphone --yes
```

## checks

`add` needs `--type` (`url`, `api`, `heartbeat`, `balance`), `--target`
(URL for `url`/`api`, label otherwise), and `--owner`. Options:
`--every S` (10-86400, default 60), `--timeout S` (1-300, default 10,
within `--every`), `--severity` (`low`/`normal`/`high`),
`--runner` (`hub`/`mac`/`both`), `--source` (`auto`/`manual`),
`--expect C`, `--contains S`, `--miss-after S`, `--warn-below F`,
`--crit-below F`. `set` replaces the whole definition; `show` prints
definition plus live state.

```sh
est-hub checks add site --type url --target https://example.com --owner estifie
est-hub checks list --owner estifie
```

## results, heartbeats

Report a probe, read history, stamp a beat. Reporters use these; the
hub's own prober uses them internally for `url`/`api`/`heartbeat`.

```sh
est-hub results report --check site --fail --reason "refused"
est-hub results list --check site --limit 5
est-hub heartbeats beat --check nightly
```

## approvals

Ask, list, answer. Pending past its deadline reads `expired` and a
decision then refuses; every ask decides at most once.

```sh
est-hub approvals request --title "deploy?" --ttl 3600
est-hub approvals decide 12 --approve --by estifie
```

## notify, notifications

Queue a notification, read the queue. Delivery drivers (Telegram,
then APNs) drain the same table; until one runs, clients poll it.

```sh
est-hub notify send --title "hello" --topic test
est-hub notifications list --limit 5
```
