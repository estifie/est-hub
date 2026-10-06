# Agent runbook

You operate the whole hub through `est-hub` — no dashboard needed.
JSON mode everywhere, exit `0/1/2`, never interactive. This file grows
one section per slice; if a route below has no CLI twin, that is a bug.

## Is the hub alive?

```sh
est-hub ping --hub http://100.120.126.23:18925
est-hub ping --json   # local default, machine shape
```

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
- Port `18925`, registered in `est-core/docs/ports.md`, tailnet-only.
