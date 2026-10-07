# Agent runbook

You operate the whole hub through `est-hub` — no dashboard needed.
JSON mode everywhere, exit `0/1/2`, never interactive. This file grows
one section per slice; if a route has no CLI twin, that is a bug.

Set `EST_HUB_URL=http://100.120.126.23:18925` once per session and
drop `--hub` everywhere below.

## Is the hub alive?

```sh
est-hub ping --json
```

## Add a check, watch it flip, remove it

```sh
est-hub checks add demo-probe --type url --target https://example.com --owner estifie --json
est-hub checks show demo-probe --json        # state embedded
est-hub results report --check demo-probe --fail --reason "drill" --json
est-hub notifications list --limit 3 --json  # the health.flip row
est-hub checks delete demo-probe --yes
```

## Report and heartbeat (as a runner would)

```sh
est-hub results report --check site --ok --code 200 --json
est-hub heartbeats beat --check nightly --json
```

## Approvals roundtrip

```sh
est-hub approvals request --title "restart api?" --ttl 600 --json   # -> {"approval":{"id":N,…}}
est-hub approvals list --state pending --json
est-hub approvals decide N --approve --by estifie --json
```

## Ask the phone (scripts gate on the operator)

Anything destructive asks first and waits: `scripts/est-approve`
blocks until the ask is approved, rejected, expired, or `--wait`
runs out (exit 0 only on approved). The ask rides a loud push with
the full detail plus banner Approve/Reject actions, and stays
answerable in the Approvals screen (Overview attention links it).

```sh
est-approve --title "Deploy backend v43?" --body "vps2, rolling" --ttl 600 --wait 600
echo "exit: $?"   # 0 approved, 1 rejected/expired/timed-out/error
```

```sh
# vault pattern: never proceed unapproved
est-approve --title "Push PROD secrets to api?" --ttl 300 --wait 300 || exit 1
est-vault run --use PROD:KEY:DATABASE_URL=DATABASE_URL -- \
  sh -c 'printf "DATABASE_URL=%s\n" "$DATABASE_URL" > /tmp/api.env'
est-hub secrets push api --file /tmp/api.env && rm /tmp/api.env
```

## Devices

```sh
est-hub devices add iphone --json
est-hub devices revoke iphone --yes
```

Every row is `active`. A device registers itself; there is no ceremony.

## Connecting a device (the phone registers itself)

The phone is a tailnet node and reaches the hub over
`https://<hub>.<tailnet>.ts.net:8443` (served by `tailscale serve` on the
hub host). It registers itself — no ticket, no compare code, no
certificate:

```sh
# the device (over the tailnet):
#   PUT /devices/iphone {}                       -> upserts the row
#   PUT /devices/iphone {"apns_token":"…","apns_env":"production"}
```

The owner can do the same from the CLI:

```sh
est-hub devices add iphone --json
est-hub devices set iphone --apns T --apns-env production --json
```

`devices set` upserts, so a wrong name is a one-word fix. Revoke with
`est-hub devices revoke iphone --yes` (deletes the row; the name
reconnects clean).

## Push setup and test (once per hub)

```sh
est-hub apns set --key-id K --team-id T --topic com.estifie.app --json
est-hub notify test --to iphone --title "hello" --json   # sends now, queues nothing
```

The `.p8` key file (`0600`) lives beside the db unless `--apns-key`
(or `EST_HUB_APNS_KEY`) says otherwise. `notify send` queues first
and pushes immediately when configured; without the key + ids it
stays queue-only.

## Quiet a check, ship a secret

```sh
est-hub checks ack site --for 2h --note "deploying" --json
est-hub checks mute flaky --for 7d --json
est-hub checks unmute flaky --json
est-hub notify alive --json             # one watchdog round now
est-hub secrets push api --file /tmp/api.env --json
est-hub secrets token api --json       # capture the token once
est-hub secrets pull api --token est_s_… --out /opt/api/.env --json
est-hub secrets revoke api --json
```

Ack quiets the down page (recovery still buzzes and clears it);
mute quiets both directions. Secrets are tailnet-only: the vault
renders on the Mac, the hub relays per-project blobs, the deploy
pulls with a scoped token and writes `.env` 0600.

## Live Activity card per device

```sh
est-hub devices live set iphone --enable --pts HEX --checks all --min-severity normal --json
est-hub devices live show iphone --json        # config + status/started/last-push
est-hub devices live token iphone --activity ACT --token T --json   # app reports (upsert)
est-hub live test --to iphone --event update --json                 # canned push, now
est-hub devices live set iphone --disable --json                    # ends the card, stops
```

Flips, approval changes, config changes, and a 6h timer converge each
enabled feed into its card (loud 10 on a fresh down, silent 5
otherwise, push-to-start via PTS, end when clear). A 410/`BadDeviceToken`
deletes the dead token + one throttled `live.stale` row. Token values
never serve — show only ids and bits.

Beside it rides the fleet card (one per enabled device, token label
`fleet`, attributes `ESTFleetAttributes`): every agent write converges
it — live agents plus recently settled rows, hub order, capped at six;
silent priority-5 updates only when the rows move (the 15s mirror
stays quiet), push-to-start via PTS when rows exist and no card does,
end when nothing is live. The last-pushed rows persist in
`fleet.pushed.{device}` meta, so restarts never re-push; the 6h timer
converges too (it ends cards the mirror abandoned overnight).

## Tailnet-only serving

The hub serves plain HTTP on the tailnet IP (deploy: `100.120.126.23`);
access is Tailscale membership. The phone's HTTPS endpoint is
`tailscale serve` on the hub host — the hub binds no TLS listener and
holds no certificate:

```sh
tailscale serve --bg --https=8443 http://100.120.126.23:18925
tailscale serve status
```

`8443` because vps2's `443` is taken by Caddy (other apps); the
certificate is the hub's own Tailscale name either way. Needs MagicDNS
+ HTTPS certificates enabled for the tailnet. There is nothing to
rotate in the hub; Tailscale owns the certificate and renews it.

## Run one locally

```sh
est-hub serve --port 0 --db /tmp/hub-dev.sqlite
# stdout first line: {"ok":true,"v":1,"listening":"127.0.0.1:PORT"}
```

`--port 0` picks an ephemeral port and prints it: the test pattern.
Logs on stderr, `EST_LOG=debug` for detail.

## Where things are

- Deploy: `vps2`, systemd unit `est-hub`, db `/var/lib/est-hub/hub.sqlite`.
  The hub serves the tailnet only; the phone's HTTPS endpoint is
  `tailscale serve` on vps2. There is no public listener and no certbot.
- Local default db: `~/.config/est/hub/hub.sqlite` (`EST_HUB_DB` overrides).
- Port `18925` (the one tailnet API) is registered in
  `est-core/docs/ports.md`.

## herdr reporters (Mac)

One daemon — `scripts/est-herdr-watch` (launchd KeepAlive, rides
`ssh vps2`, no tailnet needed). Every 15s it pushes one snapshot per
pane (`PUT /agents/{pane}`) and deletes rows for closed panes; one
`herdr agent wait` per working agent pushes the instant it settles —
done/idle → "{title} finished", blocked → "{title} needs input", new
working panes → "{title} started" (skipped on the first cycle so
restarts stay quiet). A 10s re-check keeps mid-task flicker quiet
(running off-loop, so one pane never stalls a sibling's push),
and a settle buzzes only after 90s of continuous working (real
completions buzz every time; shorter bursts are status flicker and
stay quiet; the mirror still updates every time); `--dry-run`
previews.
(The old `herdr-*` heartbeat checks are gone: agents mirror, never
page.)

## vps reporters (each VPS, cron)

Shipped by `scripts/deploy.sh` to `/usr/local/bin`, no hub code:
`est-vps-health` speaks the hub HTTP API directly (python3 stdlib
only), so reporting hosts need no `est-hub` binary.

- `est-vps-health` (every 5 min): disk/mem/load as
  `vps-<host>-disk`, `vps-<host>-mem`, `vps-<host>-load` heartbeat
  checks (owner `sys`, `target` `<host>`) — ok/fail by threshold
  (90% disk, 10% mem, 2x load), numbers in the reason plus a numeric
  `value` (disk/mem percent used, load `100*avg5/ncpu`). `<host>` is
  `EST_VPS_HOST`, else the short hostname, lowercased.
  `--dry-run` prints metrics, touches nothing.
- `est-digest` (daily 06:00 UTC = 09:00 TRT): one broadcast push —
  DOWN names, backup age, live agents, overnight finishes.
  `--dry-run` prints, sends nothing.

Cron (root on each VPS, installed once, logs in `/var/log`):

```sh
*/5 * * * * EST_VPS_HOST=vps2 /usr/local/bin/est-vps-health >>/var/log/est-vps-health.log 2>&1
0 6 * * * /usr/local/bin/est-digest >>/var/log/est-digest.log 2>&1
```

Additional VPS (owner supplies the host list): confirm it is on the
tailnet, copy the script, add the cron line with its `EST_VPS_HOST`,
confirm its `vps-<host>-*` checks appear.
