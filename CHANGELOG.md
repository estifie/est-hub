# Changelog

All notable changes, newest first. Format: Keep a Changelog;
versions: SemVer.

## [Unreleased]

### Changed

- **Tailnet-only.** The hub no longer serves a public mTLS listener
  (was `18926`). It binds one plain HTTP listener on the tailnet IP;
  access control is Tailscale membership. The phone is a tailnet node
  and reaches the API as `https://<hub>.<tailnet>.ts.net:8443`, served by
  `tailscale serve` on the hub host (Tailscale owns the certificate;
  the hub holds no TLS code). `serve` loses `--tls-port`, `--tls-bind`,
  `--tls-san`, `--pair-url`, `--tls-cert`, `--tls-key`, and the `tls`
  subcommand. `PUT /devices/{name}` now upserts, so a device
  self-registers; the pairing ceremony (tickets, short codes, compare
  codes, hub-minted client certs) is gone.

### Removed

- `est-hub tls fingerprint|reset`, `devices ticket|pair|confirm`,
  `devices stale`, and the `scripts/est-pair` wrapper. The `certs`,
  `revoked_serials`, and `pair_tickets` tables are dropped on boot; the
  `pubkey`, `cert_serial`, `compare_code`, and `last_seen_ts` device
  columns are no longer read or written. Dependencies `rustls`,
  `tokio-rustls`, `rcgen`, `qrcode`, and `time` are gone.

### Added

- Numeric readings on results: `POST /results` takes an optional
  finite `value` (absent/`null` = none, anything else 400); result
  rows carry `value` and check `state` carries `last_value` (the
  latest result's value, `null` when it had none). Storage is
  additive (old DBs open, old rows read `null`); hub-run probes
  write no value. Twin `results report --value <f64>`.
- Host-scoped VPS reporter: `est-vps-health` reports
  `vps-<host>-disk|mem|load` (`target` `<host>`, owner `sys`)
  with numeric values, speaking the HTTP API directly (no `est-hub`
  binary on reporting hosts). `<host>` is `EST_VPS_HOST` else the
  short hostname.
- `checks sync` owns per-app backend probes to their app: new
  `backend-app-<key>` rows take owner `<key>` (rolling into the
  app's project health and page like the iOS probes); existing rows
  update on the next sync (`owner` is in the unchanged test).
- Balance evaluation: `balance` checks derive `ok` from each reported
  `value` (below `crit_below`, else `warn_below`, reads down and
  pages; up-but-below-warn keeps a suffix; no value or lines means
  the reporter's `ok` stands). Credit alerts actually fire now.
- Push visibility: `GET /apns` (`apns show` twin) answers whether
  pushes can send, secret-free on both listeners — the phone's Hub
  screen reads it instead of guessing.
- Approval asks push loudly: `POST /approvals` fans the full
  title + body with the ask id and `APPROVAL` category arming the
  banner's Approve/Reject actions (background decide, same ask once).
  Asks used to queue silently.
- Result history floors by time: `GET /checks/{name}/results` takes
  `?since=` (unix seconds) beside `?limit=` (`results list --since`),
  backing the detail screen's 24H/7D/30D ranges.

- Notification retention: queued rows older than 90 days die on the
  next push (results already pruned at 30d — now every
  ever-growing table has a budget).
- Watcher liveness: `est-herdr-watch` beats the `herdr-watch`
  heartbeat (every ~5min, pages after a day of silence — the Mac
  sleeps nightly, so minutes would lie), self-reports when herdr
  itself goes unreachable (hourly while down, recovery buzzes back),
  and nudges once when a working pane's output sits unchanged past
  30min ("{title} might be stuck").
- Watcher robustness: every ssh/herdr call carries a timeout (a hung
  child reads 124, never a frozen loop) and each discovery round
  pushes its snapshots in parallel (first cycle ~20s → ~3s).
- Fleet Live Activity (one card per device): every agent write
  converges it — live agents plus recently-settled rows (working
  first, six max), silent updates only when the rows move,
  push-to-start via PTS, end when nothing is live. Taps open the AI
  tab; the 6h refresh ends cards the mirror abandoned.
- Agent identity is placing-first everywhere: `space * tab` rows in
  the app, the fleet card, pushes, and the digest (terminal titles go
  stale — the placing never lies; title/cwd-leaf/pane still fall
  back). Push bodies carry the title for flavor plus the pane id.
- Agent status clock: `status_since_ts` stamps the last flip (new
  rows and flips stamp now, steady rows keep it, legacy 0 rows heal
  to their last push). The app's row age reads it, not the mirror
  stamp; `agents show` prints `in status`.
- App auto-refresh: pushes force-reload Now + AI the moment the
  banner lands, every tab re-enters TTL-gated on foreground, and the
  AI tab polls every 20s while visible — manual refresh is retired.
- `vps-tls`: `est-vps-health` handshakes localhost:18926 and reports
  the served leaf's days-left (fails under 14d — certbot renews at
  30, so less means renewal broke and the phone is weeks from dark).
- `scripts/est-balances`: provider credit poll on the Mac (launchd,
  every 6h) — OpenRouter + fal.ai balances into `balances set`.
  API keys stay in the login Keychain; only numbers ride ssh.
  Replicate has no documented balance endpoint and stays manual.
- Ack/mute: `PUT/DELETE /checks/{name}/ack|mute` (`{until_secs?,
  note?}`) with `checks ack|unack|mute|unmute` twins (`--for
  30m/2h/7d`). Ack quiets the down page (default 2h, max 24h;
  recovery clears it and still buzzes); mute quiets both directions
  (default 24h, max 30d). Checks carry `ack_until`/`mute_until`;
  silence quiets the buzz, never the queued history.
- Secrets (vault → server): `PUT/GET/DELETE /secrets/{project}`,
  `POST/DELETE …/token`, `GET /secrets` with `secrets
  push|pull|token|revoke|delete|list` twins — all tailnet-only. The
  vault renders on the Mac, the hub relays per-project blobs, the
  deploy pulls with a scoped `est_s_…` token (hash-stored, shown
  once, last-used stamped) and writes `.env` 0600.
- Alive watchdog: the serve loop fans a silent `hub.alive` round
  every 6h; `POST /notify/alive` (`notify alive`) fires one on
  demand. Phones that stop hearing ticks warn locally.
- Stale devices: `stale` bit past 14 silent days (never-seen reads
  fresh) plus `devices stale` for manual purge via revoke.
- Pair rate limit: 10/min per IP on the public listener, 429 past
  it (in-memory, restarts reset).
- Agents (the herdr mirror): `GET /agents`, `GET /agents/{pane}`
  with `agents list|show` twins (both listeners), plus tailnet-only
  `PUT/DELETE /agents/{pane}` (`agents push|delete`) fed by
  `scripts/est-herdr-watch` — one snapshot per pane, herdr's own
  verbs, working-first, `stale` past 10 silent minutes (display-only,
  never pages). Snapshots carry workspace/tab placing plus a recent
  output tail (keep-on-absent). The `herdr-*` heartbeat checks are
  deleted; agents mirror, never page.
- herdr instant pushes (`scripts/est-herdr-watch`, KeepAlive): the
  moment an agent settles it pushes — done/idle → "{title}
  finished", blocked → "{title} needs input", new working panes →
  "{title} started" (first cycle stays quiet) — 10s flicker guard
  off-loop, push-before-mirror, and a discovery safety net for flips
  the waiter misses — a settle buzzes only after 90s of
  continuous working (real completions buzz every time, flicker
  stays quiet; the old 20min finished cooldown is gone).
- vps reporters (cron on vps2, shipped by deploy): `est-vps-health`
  (disk/mem/load as `sys` heartbeat checks, numbers in the reason)
  and `est-digest` (daily 09:00 TRT push: downs, backup age, live
  agents, overnight finishes). `hub-backup.sh` runs twice daily and
  beats `backup-age` (miss-after 24h) — a missed day pages DOWN.
- `scripts/hub-backup.sh`: encrypted sqlite snapshots over the
  tailnet (openssl/pbkdf2, key in the Mac Keychain, 7 dailies),
  with `--restore` verification.
- Incident cards: down flips push-to-start one per watching device
  (`ESTIncidentAttributes`); recovery ends every `incident:{check}`
  token row. Token reports take `--label`; labeled rows ride beside
  the status pointer, never through it. Muted checks pin nothing.
- Balances: `GET /balances`, `PUT/DELETE /balances/{provider}` with
  `balances list|set|delete` twins. Display-only rows (amounts are
  free strings); providers poll on their own schedule for now.

- `serve`: bind and answer until Ctrl-C, printing its address as JSON.
- `ping`: ask a hub if it is alive, text or `--json`.
- `GET /ping`: the versioned envelope, plus 404 envelopes everywhere else.
- `db::open`: the SQLite store (0700 dir, WAL, `meta` table).
- Devices, checks, results, heartbeats, approvals, notify: full routes
  with same-day CLI twins, plus the `tests/cli_parity.rs` gate that
  fails CI when a route lacks its twin.
- The hub probes its own `url`/`api`/`heartbeat` checks on cadence;
  flips queue `health.flip` notifications for the delivery drivers.
- `scripts/est-pair`: pair a device in one command (ticket over SSH,
  QR on the terminal, prompted compare code, confirm) instead of
  hand-driving the ticket/confirm twins across two SSH calls.
  Hub refusals (already-paired 409 and friends) report distinctly
  from SSH failures, with the revoke command when that is the fix.
- `scripts/deploy.sh`: ship the hub to vps2 in one command (sync,
  server-side release build, install, restart, both-listener verify).
- Short-code pairing: ticket issuance returns an 8-digit `short_code`
  (same row: same expiry, same single use); `POST /devices/pair`
  accepts `{"code"}` as an alternative to `{"ticket"}` (exactly one,
  whitespace ignored); `devices pair` gains `--code`, and `devices
  ticket` prints the grouped `code:` line. The phone types 8 digits;
  full tickets stay for agents and drills.
- File-identity TLS: `serve --tls-cert/--tls-key` serves an on-disk
  chain+key (production's Let's Encrypt pair) while the hub CA still
  mints/verifies client certs; `tls fingerprint` takes the same flags
  to show and validate the served identity. Phones trust the hub
  through the system store; no private-CA bytes leave the server.
- Slice 0 hub security: the hub is its own P-256 CA (files beside the
  db, keys `0600`) with a public mTLS listener (TLS 1.3, port 18926)
  next to the plain tailnet API (18925). Full device-pairing ceremony:
  `POST /devices/tickets` (tailnet only, single-use 900s tickets),
  `POST /devices/pair` (both listeners, hub-minted client identity +
  compare code), `POST /devices/{name}/confirm` (tailnet only,
  pending→active), `PUT /devices/{name}` (push state, both listeners).
  Devices gain `state`/`cert_serial`/`apns_env`; revocation blocklists
  the serial (serials survive deletion); blocked auth queues throttled
  `device.blocked` alerts (1/hour per fingerprint). CLI twins
  `devices ticket|pair|confirm|set` and local `tls fingerprint|reset`;
  `serve` gains `--tls-port/--tls-bind/--tls-san/--pair-url` and a
  `tls` addr in its ready line. Replaces `rustls-pemfile` with
  `rustls-pki-types` PEM parsing (unmaintained-crate advisory).
- Device presence: every authed public request stamps `last_seen_ts`
  (additive column, legacy rows read `null` = never seen); devices
  serialize it, and `devices show` prints a human `seen:` line
  (`12s ago`, `-` when never). Refused requests never touch.
- Public device redaction: the mTLS listener strips `apns_token` from
  every device payload (list, show, update, pair) and serves the new
  `apns_configured` bit instead (true when a non-empty token is
  stored); the plain tailnet listener keeps the full token for the
  owner CLI. Devices serialize the bit on both listeners (additive).
- Part 3 hub APNs sender (`src/apns.rs`, hand-rolled, zero new crates
  beyond the `http2` reqwest feature and the already-in-tree
  `aws-lc-rs`): token-authenticated alert pushes over HTTP/2 with a
  fresh ES256 provider JWT per send. The `.p8` key is a `0600` file
  (`--apns-key` → `EST_HUB_APNS_KEY` → `apns.p8` beside the db;
  group/other-readable refuses loud) and the three Apple ids live in
  `meta`, written by tailnet-only `PUT /apns` (`apns set` twin).
  `POST /notify` queues first, then best-effort pushes when configured
  (unconfigured hubs stay queue-only); tailnet-only `POST /notify/test`
  (`notify test` twin) sends now, queues nothing, and answers per-device
  `apns_id`/`error`/`env`. Host follows `apns_env`, a 410 clears the
  dead token (env kept), and a row marks delivered when a send lands.
- Folded Part 3 fixes: `approval_create` queues an `approval.requested`
  row; `devices set` omits absent flags (no more push-state wipe);
  `GET /notifications` gains `?to` + `?since_id` filters (`notifications
  list` gains `--to`/`--since`).
- Part 4 hub Live Activity backend (`src/live.rs` + `src/apns.rs`
  extension, zero new crates): one hub-driven status card per device.
  Routes `PUT`/`GET /devices/{name}/live-activity` (feed config + PTS
  token, present-sets/absent-keeps; `enabled:false` ends + stops),
  `POST`/`DELETE …/tokens[/…]` (activity token upsert/delete by owner),
  and tailnet-only `POST /live-activities/test` (canned push now),
  with same-day CLI twins `devices live set|show|token|untoken` and
  `live test`. Storage is additive: `devices` gains `la_pts_token`,
  `la_config`, `la_activity_id`, `la_started_ts`, `apns_topic`, plus
  the `la_tokens` table. Pushes send `liveactivity` on the resolved
  per-device topic (`apns_topic` else hub `apns.topic`) with the
  `.push-type.liveactivity` suffix (alerts use the resolved topic
  as-is), `apns-expiration: 0`, priority 10 on a fresh down / start /
  end and 5 otherwise, and the pinned wire contract (content-state
  keys exactly `down_count`/`worst`/`pending_approvals`/`updated_ts`).
  Triggers: check flips fan out to watchers, approvals refresh
  counters quietly, config changes converge at once, and a 6h timer
  re-pushes every card (restarting aging ones before Apple's ~8h
  auto-end); a 410/`BadDeviceToken` deletes the dead token and queues
  one throttled `live.stale` notice. Token values never serve — show
  routes carry ids and configured bits only.
- `checks sync`: the ecosystem's repos become the source of truth for
  what health watches (`src/sync.rs`, CLI-only, no new routes). It
  scans `--ios-root/apps/*` for legal URLs (`INFOPLIST_KEY_EC*`
  build settings, `*Config*.swift` fallback, `site/apps.yaml`
  derivation under the proven pattern) plus `support_url` from
  `.estifie/asc/general.yaml`, and `--backend-root/internal/apps`
  for backend app keys probed at `/v1/<app>/access` (expect 401)
  under `--backend-url`, with `backend-live`/`backend-ready`
  (expect 200). Upserts skip unchanged definitions; `--prune`
  deletes synced checks gone from the repos, `--dry-run` plans.
- Flip fan-out pages: `live::on_flip` now pushes the queued
  `health.flip` row via APNs (throttled: one buzz per check per 5
  minutes) on top of the card refresh, from both the probe loop and
  `POST /results`. Birth stays quiet both ways (no flip, no row):
  only healthy↔dead transitions page. `record_result` returns the
  queued row
  for the fan-out. `checks sync` only flags stale what the run
  scanned (a backend-only run no longer calls the iOS checks gone).
- Projects backend for the app's Projects tab: `projects` table
  (slug, group, name, bundle id, icon bytes + sha), routes
  `GET /projects`, `GET /projects/{name}` (both with a live health
  rollup: owner == slug, down wins), tailnet-only
  `PUT /projects/{name}` (create-or-replace metadata, icon
  survives) and `PUT .../icon` (raw PNG, 1MB max), plus
  `GET .../icon` (base64 inside the envelope). Twins `projects
  list|show|set|icon`. `checks sync --ios-root` upserts rows from
  the workspace (registry names, bundle ids, app icons with sips
  JPEG conversion, sha-skipped uploads).

### Fixed

- APNs `429 TooManyProviderTokenUpdates`: the hub minted a fresh
  provider JWT per send, and Apple throttled the whole push leg. The
  token is now process-cached and reused for 50 minutes (Apple allows
  60), fingerprinted by key material so a rotated `.p8` fails over on
  the next send.
