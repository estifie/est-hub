# est-hub CLI

Serve the API, or talk to it. `--help` is the short version of this file.

```sh
est-hub serve [--bind IP] [--port N] [--db PATH] [--apns-key P]
est-hub ping [--hub URL]
est-hub devices add NAME [--apns T]
est-hub devices list
est-hub devices show NAME
est-hub devices revoke NAME --yes
est-hub devices set NAME [--apns T] [--apns-env E] [--apns-topic P]
est-hub devices live set NAME [--enable|--disable] [--pts HEX]
    [--checks a,b | --checks all] [--min-severity S]
    [--approvals|--no-approvals] [--alert-on-down|--no-alert-on-down]
est-hub devices live show NAME
est-hub devices live token NAME --activity ID --token T [--label L]
est-hub devices live untoken NAME ID
est-hub live test --to DEV --event update|end|start
est-hub checks add NAME --type T --target U --owner O [options]
est-hub checks list [--owner O]
est-hub checks show NAME
est-hub checks set NAME --type T --target U --owner O [options]
est-hub checks delete NAME --yes
est-hub checks sync [--ios-root P] [--backend-root P --backend-url U]
    [--every S] [--timeout S] [--prune] [--dry-run]
est-hub projects list
est-hub projects show SLUG
est-hub projects set SLUG --group G --name N [--bundle-id B]
est-hub projects icon SLUG --file P | --out P
est-hub results report --check NAME --ok|--fail [--code C] [--reason R] [--value F]
est-hub results list --check NAME [--limit N] [--since TS]
est-hub heartbeats beat --check NAME
est-hub approvals request --title T [--body B] [--reply-to R] [--ttl S]
est-hub approvals list [--state S]
est-hub approvals show ID
est-hub approvals decide ID --approve|--reject [--by WHO]
est-hub notify send --title T [--body B] [--topic T] [--to DEV]
est-hub notify test --to DEV [--title T] [--body B]
est-hub notifications list [--limit N] [--to D] [--since ID]
est-hub apns show
est-hub apns set [--key-id K] [--team-id T] [--topic P]
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

`serve` binds the tailnet API (the tailnet is the encryption) and, with
`--apns-key`, points the APNs sender at an explicit key path. The ready
line names the address it bound:

```json
{"ok":true,"v":1,"listening":"127.0.0.1:18925"}
```

The phone reaches the same API over the tailnet as
`https://<hub>.<tailnet>.ts.net:8443` — that endpoint is `tailscale serve` on
the hub host, not a hub flag; the hub holds no TLS code.

## ping

Ask a hub if it is alive. Reads `--hub`, `EST_HUB_URL`, else the local
default (`http://127.0.0.1:18925`).

```sh
est-hub ping --hub http://100.120.126.23:18925
est-hub ping --json   # the /ping body verbatim
```

## devices

`add` registers a row (always `active`); `set` updates push state
(`--apns-env` is `development` or `production`, `--apns-topic`
overrides the device's `apns-topic`); `revoke` deletes the row. `set`
upserts — a missing device is created — which is how an app registers
itself over the tailnet (`PUT /devices/{name}`) with no ceremony. There
are no `ticket`/`pair`/`confirm` verbs: access is tailnet membership.

```sh
est-hub devices add iphone
est-hub devices set iphone --apns T --apns-env production
est-hub devices revoke iphone --yes
```

## devices live, live

One hub-driven Live Activity card per device. `live set` writes the
feed — absent flags keep their values, like `devices set`:
`--enable`/`--disable` is the master switch (`--disable` ends the
running card and stops), `--pts` is the push-to-start token (hex),
`--checks` is a comma list or `all`, `--min-severity` is
`low`/`normal`/`high`, and the `--approvals`/`--alert-on-down` pairs
toggle counting and buzzing. `live show` reads the config plus status
(`off`/`pending`/`active`/`stale`), current activity, and stamps.
`live token` registers an activity push token (upsert by id);
`--label incident:{check}` files it as an incident card (recovery
ends those; status rows stay unlabeled and move the pointer).
`live untoken` forgets one. `live test` pushes a canned card now —
`update`, `end`, or `start` — printing `sent <apns-id>` or the
refusal, like `notify test`. Down flips push-to-start incident cards
per watching device on their own; muted checks pin nothing.

```sh
est-hub devices live set iphone --enable --pts ab12 --checks all --min-severity normal
est-hub devices live show iphone
est-hub devices live token iphone --activity ACT --token T
est-hub devices live untoken iphone ACT
est-hub live test --to iphone --event update
```


`add` needs `--type` (`url`, `api`, `heartbeat`, `balance`), `--target`
(URL for `url`/`api`, label otherwise), and `--owner`. Options:
`--every S` (10-86400, default 60), `--timeout S` (1-300, default 10,
within `--every`), `--severity` (`low`/`normal`/`high`),
`--runner` (`hub`/`mac`/`both`), `--source` (`auto`/`manual`),
`--expect C`, `--contains S`, `--miss-after S`, `--warn-below F`,
`--crit-below F`. `set` replaces the whole definition; `show` prints
definition plus live state. `sync` reads the ecosystem repos and
upserts `url` checks (`source=auto`, `runner=hub`): `--ios-root`
scans `apps/*` for `INFOPLIST_KEY_ECPrivacyURL`/`ECTermsURL`
(falling back to `*Config*.swift` literals), completing
served-but-unpinned apps from `site/apps.yaml` under the site
pattern an explicit URL proves, plus `support_url` from
`.estifie/asc/general.yaml` (`ios-<slug>-privacy|terms|support`);
`--backend-root` (with `--backend-url`) adds `backend-live`,
`backend-ready`, and one `backend-app-<key>` per `internal/apps`
subdir (per-app expects the 401 auth challenge). Unchanged
definitions are skipped; `--prune` deletes synced checks gone from
the repos, `--dry-run` prints the plan. `--every`/`--timeout`
default to 300/15.

```sh
est-hub checks add site --type url --target https://example.com --owner estifie
est-hub checks list --owner estifie
est-hub checks sync --ios-root ~/Desktop/iOS --dry-run
```

`ack` quiets the down page (`--for 30m`/`2h`/`7d`/seconds, default
2h, max 24h; recovery clears it and still buzzes); `mute` quiets both
directions (default 24h, max 30d). `unack`/`unmute` lift. `--note`
records why. Horizons print on `show` via `ack_until`/`mute_until`.

```sh
est-hub checks ack site --for 2h --note "deploying"
est-hub checks mute flaky --for 7d
est-hub checks unmute flaky
```

## projects

Project identity for the app's Projects tab: slug, group, name,
bundle id, icon, plus a health rollup (checks roll by owner ==
slug; down wins, then unknown, then up; zero checks reads unknown).
`checks sync --ios-root` upserts these from the workspace (names
from `site/apps.yaml`, bundle ids from
`PRODUCT_BUNDLE_IDENTIFIER`, icons from the `AppIcon.appiconset`,
uploads only when the sha changes, converting JPEGs via sips); `set`/`icon` are the manual
twins. Writes are tailnet-only; reads serve both listeners. Icons
are PNG, 1MB max, served base64 inside the envelope.

```sh
est-hub projects list
est-hub projects show daysleft
est-hub projects set daysleft --group ios --name "Days Left" --bundle-id com.estifie.daysleft
est-hub projects icon daysleft --file ./icon.png
```

## results, heartbeats

Report a probe, read history, stamp a beat. Reporters use these; the
hub's own prober uses them internally for `url`/`api`/`heartbeat`
(which record no value). `--value` takes a finite number (disk/mem
percent, load score, TLS days-left, credit balances); absent means no
value. Balance checks (`--type balance` with `--warn-below` /
`--crit-below`) evaluate the value on record and page past the lines.

```sh
est-hub results report --check site --fail --reason "refused"
est-hub results report --check vps-vps2-disk --ok --value 42 --reason "disk 42% used"
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

`send` queues a notification (and pushes immediately when the hub is
APNs-configured); `test` pushes now and queues nothing, printing
per-device `sent <apns-id>` or the refusal. `list` reads the queue
with `--limit`, `--to` (one device's rows), and `--since` (rows past
an id) for cheap refresh.

```sh
est-hub notify send --title "hello" --topic test
est-hub notify test --to iphone --title "hello"
est-hub notifications list --limit 5 --to iphone --since 12
est-hub notify alive
```

`alive` fires one watchdog round now (the serve loop sends every 6h).

## apns

Write the APNs sender ids the push path needs (`key_id`, `team_id`,
`topic` — absent flags keep their values). The `.p8` signing key
itself is a `0600` file: `--apns-key` on `serve`, `EST_HUB_APNS_KEY`,
else `apns.p8` beside the db.

```sh
est-hub apns show --json            # pushes on/off + topic (secret-free)
est-hub apns set --key-id KEY1234567 --team-id TEAM123456 --topic com.estifie.app
```

## secrets

Vault → server, per project. `push` reads a file (never argv) into
the hub; `token` mints the pull token once (re-minting kills the
old one); the deploy `pull`s with it and writes `.env` 0600.
`revoke` kills the token, `delete` kills secret + token, `list`
shows faces only (never env). Tailnet-only, all of it.

```sh
# Render from the vault (stays on the Mac), push the file, shred it.
est-vault run --use PROD:KEY:DATABASE_URL=DATABASE_URL --use PROD:KEY:API_KEY=API_KEY -- \
  sh -c 'printf "DATABASE_URL=%s\nAPI_KEY=%s\n" "$DATABASE_URL" "$API_KEY" > /tmp/api.env'
est-hub secrets push api --file /tmp/api.env && rm /tmp/api.env
est-hub secrets token api             # capture once
est-hub secrets pull api --token est_s_… --out /opt/api/.env
```

## balances

Display-only API balances (the hub shows, never computes): `set`
upserts a row, `list` reads them, `delete` drops one. Amounts are
free strings (`$12.34`, `84%`); providers poll on their own schedule
and write through this (no provider polling in the hub yet).

```sh
est-hub balances set openai --amount '$12.34' --currency USD --note 'team plan'
est-hub balances list
```

## agents

The herdr mirror: `scripts/est-herdr-watch` pushes one snapshot per
pane (`status` is herdr's own verb: `working|done|idle|blocked|
unknown`) and deletes rows when panes close. `list` reads the mirror
(working first, `STALE` past 10 silent minutes — display-only, never
pages); `push`/`delete` are the watcher's verbs, tailnet only.
Snapshots carry workspace/tab placing plus a tail of the pane's
recent output; omitted `space`/`tab`/`output` keep the stored values
(a failed read never wipes the last tail).

```sh
est-hub agents list
est-hub agents show 'w7:p1P'
est-hub agents push 'w7:p1P' --status working --title 'Release run-up' --cwd ~/Desktop/iOS --space iOS --tab 1
```

## backup

`scripts/hub-backup.sh` snapshots the hub sqlite over the tailnet
and stores it encrypted (openssl aes-256-cbc/pbkdf2, key in the Mac
Keychain, 14 snapshots ≈ 7 days in `~/.local/share/est/backups`).
`--restore FILE OUT` decrypts and counts the checks inside. Each run
also beats the `backup-age` heartbeat check (owner `sys`, miss-after
24h) — a missed full day pages DOWN in Health.
