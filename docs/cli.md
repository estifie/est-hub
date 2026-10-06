# est-hub CLI

Serve the API, or talk to it. `--help` is the short version of this file.

```sh
est-hub serve [--bind IP] [--port N] [--db PATH]
est-hub ping [--hub URL]
```

## Conventions

- **Exit codes:** `0` ok, `1` failed, `2` wrong usage.
- **Errors** go to stderr as `est-hub: ...`; data goes to stdout.
- **`--json`** rides on any command and prints one JSON object instead
  of text: `{"ok":true,"v":1,...}` or `{"ok":false,"v":1,"error":"…"}`.
- Every hub route has its CLI twin the day the route lands — agents
  operate the whole hub through this binary. See `agent.md`.

## serve

Bind and answer until Ctrl-C. Prints one line on stdout when ready:

```json
{"ok":true,"v":1,"listening":"127.0.0.1:18925"}
```

Logs go to stderr (`EST_LOG` levels). Defaults: bind `127.0.0.1`,
port `18925`, db `~/.config/est/hub/hub.sqlite` (`EST_HUB_DB` or
`--db` override). Deploy binds the tailnet IP — never `0.0.0.0`.

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
