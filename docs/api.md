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
| POST | `/devices` | `devices add` | `{name, apns_token?}` |
| GET | `/devices/{name}` | `devices show` | |
| PUT | `/devices/{name}` | `devices set` | `{apns_token?, apns_env?, apns_topic?}`; upserts (self-registration) |
| DELETE | `/devices/{name}` | `devices revoke` | Revokes the device: deletes the row and its tokens |
| GET | `/checks` | `checks list` | `?owner=` filters; state embedded |
| POST | `/checks` | `checks add` | Definition below |
| GET | `/checks/{name}` | `checks show` | Definition + live state |
| PUT | `/checks/{name}` | `checks set` | Full replace (owner/type/target required) |
| DELETE | `/checks/{name}` | `checks delete` | Takes results + beats with it |
| PUT | `/checks/{name}/ack` | `checks ack` | `{until_secs?, note?}`; quiets the down page (recovery still buzzes + clears) |
| DELETE | `/checks/{name}/ack` | `checks unack` | Lift the ack |
| PUT | `/checks/{name}/mute` | `checks mute` | `{until_secs?, note?}`; quiets both directions |
| DELETE | `/checks/{name}/mute` | `checks unmute` | Lift the mute |
| GET | `/secrets` | `secrets list` | Public faces only (never env) |
| PUT | `/secrets/{name}` | `secrets push` | `{env}` 64KB max, upsert |
| GET | `/secrets/{name}` | `secrets pull` | Bearer project token; serves `{project, sha, env}` |
| DELETE | `/secrets/{name}` | `secrets delete` | Takes the token with it |
| POST | `/secrets/{name}/token` | `secrets token` | Mints (re-mint kills old); shows once |
| DELETE | `/secrets/{name}/token` | `secrets revoke` | Quiet when none |
| GET | `/balances` | `balances list` | Display rows, by provider |
| PUT | `/balances/{name}` | `balances set` | `{amount, label?, currency?, note?}` upsert |
| DELETE | `/balances/{name}` | `balances delete` | Missing 404s |
| GET | `/agents` | `agents list` | herdr mirror (working first) |
| GET | `/agents/{name}` | `agents show` | One snapshot |
| PUT | `/agents/{name}` | `agents push` | `{status, title?, cwd?, space?, tab?, output?}` upsert, space/tab/output keep on absent |
| DELETE | `/agents/{name}` | `agents delete` | Pane closed; missing 404s |
| GET | `/projects` | `projects list` | Identity + health rollup per project |
| GET | `/projects/{name}` | `projects show` | One project + rollup |
| PUT | `/projects/{name}` | `projects set` | `{group, name, bundle_id?}` create-or-replace, icon survives |
| GET | `/projects/{name}/icon` | `projects icon` | `{icon}` base64 + `{bytes}`, 404 when missing |
| PUT | `/projects/{name}/icon` | `projects icon` | Raw PNG bytes, 1MB max, needs the row first |
| POST | `/results` | `results report` | `{check, ok, code?, reason?, ts?, value?}` — `value` is an optional finite JSON number (`null`/absent = none) |
| GET | `/checks/{name}/results` | `results list` | `?limit=` (default 20, max 1000), `?since=` (unix floor, 0 = all); rows carry `value` (`null` when none) |
| POST | `/heartbeats` | `heartbeats beat` | `{check, ts?}` |
| POST | `/approvals` | `approvals request` | `{title, body?, reply_to?, ttl_secs?}`; queues `approval.requested` + pushes it loudly (full detail, ask id, `APPROVAL` actions) |
| GET | `/approvals` | `approvals list` | `?state=` filters live states |
| GET | `/approvals/{id}` | `approvals show` | Live state (expiry computed) |
| POST | `/approvals/{id}/decision` | `approvals decide` | `{approve, by?}`; once only |
| POST | `/notify` | `notify send` | `{title, body?, topic?, to?}`; queues, then pushes when APNs is configured |
| POST | `/notify/test` | `notify test` | `{to?, title?, body?, topic?}`; sends now, queues nothing |
| POST | `/notify/alive` | `notify alive` | One watchdog round now (the loop sends every 6h); broadcast, silent |
| GET | `/notifications` | `notifications list` | `?limit=` (default 20, max 500), `?to=`, `?since_id=` |
| GET | `/apns` | `apns show` | `{configured, topic?}` (secret-free) |
| PUT | `/apns` | `apns set` | `{key_id?, team_id?, topic?}` |
| PUT | `/devices/{name}/live-activity` | `devices live set` | Feed config + PTS token |
| GET | `/devices/{name}/live-activity` | `devices live show` | Config + status/started/last-push |
| POST | `/devices/{name}/live-activity/tokens` | `devices live token` | `{activity_id, token, label?}` upsert; `incident:{check}` rows ride beside the status pointer |
| DELETE | `/devices/{name}/live-activity/tokens/{id}` | `devices live untoken` | |
| POST | `/live-activities/test` | `live test` | `{to, event}`; canned push, now |

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

## Incident cards

Down flips push-to-start one incident card per watching device
(attributes-type `ESTIncidentAttributes`, alert included); recovery ends
every token row labeled `incident:{check}` and drops the rows. Cards
already live skip re-start; muted checks pin nothing (the silence gate
runs first). The app reports each push-started card's token with its
label, and observes newly started cards as they arrive — a card whose
token never uploads is a card recovery cannot end. No refresh loop yet:
Apple retires an un-updated card after ~8h.

## State

Every check carries `state`: `status` (`up`/`down`/`unknown`),
consecutive `fails`, `changed_ts`, last probe (`last_ts`, `last_code`,
`last_reason`, `last_value` — the numeric value of the latest result,
`null` when that result carried none), `last_beat`, and `flapping` (5+ flips/hour). Unknown
counts as up: a check down from birth alerts on its first probe.
Recorded probes prune past 30 days. Non-finite or non-numeric `value`
refuses with a 400; hub-run probes (`url`, `api`) record no value.
Balance checks derive `ok` from each reported `value`: below
`crit_below` (when set, else `warn_below`) reads down and pages; an up
result still below `warn_below` keeps a `(below warn …)` suffix in the
reason. Without a value or thresholds the reporter's `ok` stands.

## Silence (ack/mute)

Checks carry `ack_until` / `mute_until` horizons (0 = none). Ack
quiets the down page for up to a day (default 2h); recovery clears it
and always buzzes. Mute quiets both directions for up to a month
(default a day); only time or unmute clears it. Silence quiets the
buzz, never the record: flips still queue for history. Horizons ride
`PUT /checks/{name}/ack|mute` (`{until_secs?, note?}`); lifts are the
matching DELETEs.

## Secrets (vault → server)

Per-project env blobs, tailnet-only. The Mac pushes
(`PUT /secrets/{project}` `{env}`, 64KB max); the deploy pulls
(`GET /secrets/{project}` with the project token as bearer) and
writes `.env`. Tokens mint via `POST /secrets/{project}/token`
(one live token per project — re-minting kills the old one, plaintext
shows once), revoke via the matching DELETE; `GET /secrets` lists
public faces only. Pulls 401 without a token and 404 on a wrong one
(never confirm what you cannot pull). The hub stores blobs as-is:
this disk already holds the live `.env` files, so the store and the
deploys share one trust zone.

## Alive watchdog

The serve loop fans a silent round (`content-available`, topic
`hub.alive`, `alive_ts` tick) every 6h; `POST /notify/alive` fires
one on demand. Phones that stop hearing ticks warn locally that the
hub went quiet — the watcher watching the watcher, with no third
service. Dead tokens clear via the usual feedback loop.

## Access control (tailnet)

The hub serves one listener: plain HTTP on the tailnet IP (`--bind`,
deployed as `100.120.126.23:18925`). Access control is Tailscale
membership — the bind address is the gate. There is no public ingress,
no client certificates, and no owner-vs-device route split: anything on
the tailnet reaches everything (single user).

The phone is a tailnet node too. On the hub host, `tailscale serve`
exposes the same API as `https://<hub>.<tailnet>.ts.net:8443`, with TLS
terminated by Tailscale against a real cert, so the app can speak HTTPS
without a client cert. Tailscale handles the certificate; the hub holds
no TLS code.

## Connecting a device

1. Device: `PUT /devices/{name} {}` — self-registration. The hub upserts
   the row (`state` is always `active`), so a fresh install names itself
   and is connected in one call.
2. Device: `PUT /devices/{name}` with `{"apns_token"?, "apns_env"?,
   "apns_topic"?}` (`development`|`production`; `apns_topic` is a
   per-device `apns-topic` override, `null` clears back to the hub-wide
   id). A nil field is omitted, so a token upload never clears the env.

Devices serialize `state` (always `active`), `apns_token`, `apns_env`,
`apns_topic` (the per-device topic override, `null` when unset), and
`apns_configured` (true when a non-empty `apns_token` is stored). The
Live Activity fields (PTS token, feed config, activity pointer) are
never serialized — the live-activity routes serve the parsed,
secret-free shape.

`DELETE /devices/{name}` drops the row (with its Live Activity tokens
and last-push stamp); the name reconnects clean.

## Push (APNs)

`POST /notify` queues first (the audit trail) and then, when the hub
is APNs-configured, pushes immediately over HTTP/2 with a fresh ES256
provider JWT per send; unconfigured hubs stay queue-only. Setup is two
parts: the `.p8` signing key as a `0600` file (`--apns-key`,
`EST_HUB_APNS_KEY`, else `apns.p8` beside the db — group/other-readable
refuses loud), and the three ids via `PUT /apns`
(`{key_id?, team_id?, topic?}` — present sets, absent keeps,
null/empty clears). `POST /notify/test` sends now and queues nothing,
answering per-device `apns_id`/`error`/`env` (`results`); unconfigured
hubs refuse in 400 with the fix. Devices push by their `apns_env`
(`development` → sandbox, anything else → production); a 410 clears
the dead token (env kept), and a queue row marks delivered when at
least one send lands. Every push resolves its `apns-topic` per device
(the device's `apns_topic` when set, else the hub-wide `apns.topic`).

## Live Activity

One hub-driven status card per device. The feed config lives on the
device row (`PUT …/live-activity`, every field present-sets,
absent-keeps):

```json
{"enabled":true,"pts_token":"ab12…","checks":["site"],"min_severity":"normal",
 "approvals":true,"alert_on_down":true}
```

`checks` is `null`/`"all"` for the whole fleet or an array of names
(unknown names read 404); `min_severity` is `low`/`normal`/`high`.
`enabled:false` ends the running card and stops. `GET` answers the
config plus `pts_configured` (never the token), `status`
(`off`/`pending`/`active`/`stale`), `activity_id`, `started_ts`,
`last_push_ts`, and the reported activity ids (never token values).

The app reports activity push tokens (`POST …/tokens
{"activity_id","token"}`, upsert — the device points at the latest as
current) and forgets them (`DELETE …/tokens/{id}`, which must belong
to the device). Token values are hub-only secrets and are never
served — the tailnet is the trust boundary.

Triggers recompute each enabled feed and converge the card: a check
flip updates watchers (priority 10 + alert on a fresh down the device
wants loud, silent 5 otherwise), push-to-starts via PTS when there is
news and no card, and ends the card when everything cleared (final
state + dismissal date). Approval asks/decisions refresh counters
quietly; config changes converge at once; a 6h timer re-pushes every
card and restarts aging ones before Apple's ~8h auto-end. A
410/`BadDeviceToken` deletes the dead token and queues one throttled
`live.stale` notice (1/hour per device).

`POST /live-activities/test {"to","event"}` (owner-only) pushes a
canned card now — `update`, `end`, or `start` — and answers `apns_id`
or the per-device `error`; unconfigured hubs refuse in 400 with the
fix. The wire contract is pinned: content-state keys exactly
`down_count`, `worst`, `pending_approvals`, `updated_ts`, attributes
exactly `device_name`, `title`, `attributes-type ESTStatusAttributes`,
`apns-push-type: liveactivity`, `apns-expiration: 0`, topic
`<resolved>.push-type.liveactivity`.
