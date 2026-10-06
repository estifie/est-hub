# est-hub API

One API for the phone, the desktop, scripts, and agents. JSON everywhere,
versioned envelopes everywhere:

```json
{"ok":true,"v":1,...data...}
{"ok":false,"v":1,"error":"no such route"}
```

Success is HTTP 200 (creation: 201); wrong usage is 400, unknown is 404,
all with `"ok":false` bodies. No HTML error pages, ever.

## Routes

| Method | Route | Since | Notes |
|---|---|---|---|
| GET | `/ping` | 0.1.0 | Alive, named, versioned |

## GET /ping

No auth, no state. Load balancers and `est-hub ping` use it; deploy
checks block on it.

```json
{"ok":true,"v":1,"name":"est-hub","version":"0.1.0"}
```
