# est-hub API

One API for the phone, the desktop, scripts, and agents. JSON everywhere,
versioned envelopes everywhere:

```json
{"ok":true,"v":1,...data...}
{"ok":false,"v":1,"error":"no such check"}
```

Success is 200 (creation: 201); misuse 400, unknown 404, name taken 409,
all envelopes. The one exception: a body that is not JSON at all gets
axum's plain 400 before any handler runs.

Every route has a CLI twin the day it lands (`est-hub …`), enforced by
`tests/cli_parity.rs`. Names everywhere match `[a-z][a-z0-9_-]{0,31}`.

## Routes

| Method | Route | Twin | Notes |
|---|---|---|---|
| GET | `/ping` | `ping` | Alive, named, versioned |
| GET | `/devices` | `devices list` | Every device, by name |
| POST | `/devices` | `devices add` | `{name, pubkey?, apns_token?}` |
| GET | `/devices/{name}` | `devices show` | |
| DELETE | `/devices/{name}` | `devices revoke` | Revocation is deletion |
| GET | `/checks` | `checks list` | `?owner=` filters; state embedded |
| POST | `/checks` | `checks add` | Definition below |
| GET | `/checks/{name}` | `checks show` | Definition + live state |
| PUT | `/checks/{name}` | `checks set` | Full replace (owner/type/target required) |
| DELETE | `/checks/{name}` | `checks delete` | Takes results + beats with it |
| POST | `/results` | `results report` | `{check, ok, code?, reason?, ts?}` |
| GET | `/checks/{name}/results` | `results list` | `?limit=` (default 20, max 1000) |
| POST | `/heartbeats` | `heartbeats beat` | `{check, ts?}` |
| POST | `/approvals` | `approvals request` | `{title, body?, reply_to?, ttl_secs?}` |
| GET | `/approvals` | `approvals list` | `?state=` filters live states |
| GET | `/approvals/{id}` | `approvals show` | Live state (expiry computed) |
| POST | `/approvals/{id}/decision` | `approvals decide` | `{approve, by?}`; once only |
| POST | `/notify` | `notify send` | `{title, body?, topic?, to?}` |
| GET | `/notifications` | `notifications list` | `?limit=` (default 20, max 500) |

## Check definition

```json
{"name":"site","owner":"estifie","type":"url","target":"https://example.com",
 "every_secs":60,"timeout_secs":10,"severity":"normal","runner":"hub",
 "source":"manual","expect":200,"contains":"…","miss_after_secs":300,
 "warn_below":5.0,"crit_below":1.0}
```

Only `name`, `owner`, `type`, `target` are required. `type` is `url`,
`api`, `heartbeat`, or `balance`; `severity` is `low`/`normal`/`high`;
`runner` is `hub`/`mac`/`both`. Timeouts cannot outrun cadence;
`crit_below` sits below `warn_below`.

## State

Every check carries `state`: `status` (`up`/`down`/`unknown`),
consecutive `fails`, `changed_ts`, last probe (`last_ts`, `last_code`,
`last_reason`), `last_beat`, and `flapping` (5+ flips/hour). Unknown
counts as up: a check down from birth alerts on its first probe.
Recorded probes prune past 30 days.
