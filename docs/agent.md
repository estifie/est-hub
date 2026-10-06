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

## Devices

```sh
est-hub devices add iphone --json
est-hub devices revoke iphone --yes
```

Registry only until mTLS (P3) enforces it.

## Run one locally

```sh
est-hub serve --port 0 --db /tmp/hub-dev.sqlite
# stdout first line: {"ok":true,"v":1,"listening":"127.0.0.1:PORT"}
```

`--port 0` picks an ephemeral port and prints it: the test pattern.
Logs on stderr, `EST_LOG=debug` for detail.

## Where things are

- Deploy: `vps2`, systemd unit `est-hub`, db `/var/lib/est-hub/hub.sqlite`.
- Local default db: `~/.config/est/hub/hub.sqlite` (`EST_HUB_DB` overrides).
- Port `18925`, registered in `est-core/docs/ports.md`, tailnet-only
  until the mTLS listener lands (P3).
