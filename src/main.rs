//! est-hub: serve the API, or talk to it.
//!
//! `serve` binds (tailnet in deploy, loopback for local work), probes
//! its hub-run checks on their own cadence, and answers until Ctrl-C.
//! Every other command is a twin of a hub route — agents operate the
//! whole hub through this binary. JSON mode prints one object and
//! nothing else, per the EST CLI contract.

use std::collections::HashMap;
use std::path::PathBuf;

use base64::Engine as _;
use est_core::{cli, log, paths};
use est_hub::{api, db, live, model, sync};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PORT: u16 = 18925;
const DEFAULT_BIND: &str = "127.0.0.1";

const HELP: &str = "est-hub: one API on the tailnet for the ecosystem

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
  est-hub checks ack NAME [--for DUR] [--note TEXT]
  est-hub checks unack NAME
  est-hub checks mute NAME [--for DUR] [--note TEXT]
  est-hub checks unmute NAME
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
  est-hub notify alive
  est-hub notifications list [--limit N] [--to D] [--since ID]
  est-hub apns show
  est-hub apns set [--key-id K] [--team-id T] [--topic P]
  est-hub secrets list
  est-hub secrets push PROJECT --file PATH
  est-hub secrets pull PROJECT --token T --out PATH
  est-hub secrets token PROJECT
  est-hub secrets revoke PROJECT
  est-hub secrets delete PROJECT --yes
  est-hub balances list
  est-hub balances set PROVIDER --amount X [--label L] [--currency C] [--note N]
  est-hub balances delete PROVIDER --yes
  est-hub agents list
  est-hub agents show PANE
  est-hub agents push PANE --status S [--title T] [--cwd C] [--space S] [--tab T] [--output O]
  est-hub agents delete PANE --yes
  est-hub help

checks options: --every S --timeout S --severity S --runner S --source S
  --expect C --contains S --miss-after S --warn-below F --crit-below F.
serve binds 127.0.0.1:18925 unless told otherwise; deploy binds the
tailnet IP, never 0.0.0.0. Client commands read --hub, EST_HUB_URL,
else the local default. --json rides any command and prints one
object. Destructive commands ask first unless --yes. Full reference:
docs/cli.md.";

fn fail(json: bool, msg: &str) -> i32 {
    if json {
        println!("{}", cli::err(msg));
    } else {
        eprintln!("est-hub: {msg}");
    }
    1
}

/// `--db`, `EST_HUB_DB`, `~/.config/est/hub/hub.sqlite`, else the cwd.
fn resolve_db(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit.map(str::trim).filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("EST_HUB_DB")
        && !p.trim().is_empty()
    {
        return PathBuf::from(p.trim());
    }
    if let Some(dir) = paths::product_config_dir("hub") {
        return dir.join("hub.sqlite");
    }
    PathBuf::from("hub.sqlite")
}

/// `--hub`, `EST_HUB_URL`, else the local default.
fn hub_url(explicit: Option<&str>) -> String {
    if let Some(u) = explicit.map(str::trim).filter(|u| !u.is_empty()) {
        return u.trim_end_matches('/').to_string();
    }
    if let Ok(u) = std::env::var("EST_HUB_URL")
        && !u.trim().is_empty()
    {
        return u.trim().trim_end_matches('/').to_string();
    }
    format!("http://{DEFAULT_BIND}:{DEFAULT_PORT}")
}

/// Pull `name`/`version` out of a ping body without failing the run
/// when the shape drifts — ping reports liveness, not schema.
fn parse_ping(body: &str) -> Option<(&str, &str)> {
    fn field<'a>(body: &'a str, key: &str) -> Option<&'a str> {
        let at = body.find(key)? + key.len();
        let rest = body[at..]
            .trim_start()
            .strip_prefix(':')?
            .trim_start()
            .strip_prefix('"')?;
        rest.split('"').next()
    }
    Some((field(body, "\"name\"")?, field(body, "\"version\"")?))
}

/// Ask first unless `--yes`; a non-terminal stdin refuses rather than
/// guesses. Agents: always pass `--yes` (you already decided).
fn confirm(what: &str, yes: bool) -> bool {
    if yes {
        return true;
    }
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        eprintln!("est-hub: refusing {what} without --yes on a non-terminal stdin");
        return false;
    }
    eprint!("{what}? [y/N] ");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

// ---------------------------------------------------------------- HTTP

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("no HTTP client: {e}"))
}

async fn api(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    body: Option<serde_json::Value>,
) -> Result<(u16, String), String> {
    let mut req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        _ => return Err(format!("bad method {method}")),
    };
    if let Some(b) = body {
        req = req.json(&b);
    }
    let res = req
        .send()
        .await
        .map_err(|e| format!("no hub at {url} ({e})"))?;
    let status = res.status().as_u16();
    let text = res.text().await.unwrap_or_default();
    Ok((status, text))
}

/// [`api`] with a bearer (the secrets puller's project token).
async fn api_bearer(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    token: &str,
) -> Result<(u16, String), String> {
    let req = match method {
        "GET" => client.get(url),
        _ => return Err(format!("bad method {method}")),
    };
    let res = req
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| format!("no hub at {url} ({e})"))?;
    let status = res.status().as_u16();
    let text = res.text().await.unwrap_or_default();
    Ok((status, text))
}

fn api_error(body: &str, status: u16) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body)
        && let Some(e) = v.get("error").and_then(|e| e.as_str())
    {
        return e.to_string();
    }
    if body.trim().is_empty() {
        format!("HTTP {status}")
    } else {
        format!(
            "HTTP {status}: {}",
            body.trim().chars().take(160).collect::<String>()
        )
    }
}

fn value(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or(serde_json::Value::Null)
}

fn str_field(body: &serde_json::Value, ptr: &str) -> String {
    body.pointer(ptr)
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string()
}

// ---------------------------------------------------------------- serve

async fn cmd_serve_async(args: &[String], json: bool) -> i32 {
    let mut bind = DEFAULT_BIND.to_string();
    let mut port = DEFAULT_PORT;
    let mut db_opt: Option<String> = None;
    let mut apns_key: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                bind = args
                    .get(i)
                    .map(String::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if bind.is_empty() {
                    eprintln!("est-hub serve: --bind needs an IP");
                    return 2;
                }
            }
            "--port" => {
                i += 1;
                match args
                    .get(i)
                    .map(String::as_str)
                    .unwrap_or("")
                    .trim()
                    .parse::<u16>()
                {
                    Ok(p) => port = p,
                    Err(_) => {
                        eprintln!("est-hub serve: --port needs 0-65535");
                        return 2;
                    }
                }
            }
            "--db" => {
                i += 1;
                let p = args.get(i).map(String::as_str).unwrap_or("").trim();
                if p.is_empty() {
                    eprintln!("est-hub serve: --db needs a path");
                    return 2;
                }
                db_opt = Some(p.to_string());
            }
            "--apns-key" => {
                i += 1;
                let p = args.get(i).map(String::as_str).unwrap_or("").trim();
                if p.is_empty() {
                    eprintln!("est-hub serve: --apns-key needs a path");
                    return 2;
                }
                apns_key = Some(p.to_string());
            }
            flag if flag.starts_with("--") => {
                eprintln!("est-hub serve: unexpected {flag:?}");
                return 2;
            }
            t => {
                eprintln!("est-hub serve: unexpected {t:?}");
                return 2;
            }
        }
        i += 1;
    }
    let ip: std::net::IpAddr = match bind.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("est-hub serve: --bind needs an IP, got {bind:?}");
            return 2;
        }
    };
    let db_path = resolve_db(db_opt.as_deref());
    if let Err(e) = db::open(&db_path) {
        return fail(json, &e.to_string());
    }
    let mut state = api::AppState::new(db_path.clone());
    state.apns_key = apns_key.map(PathBuf::from);
    let listener = match tokio::net::TcpListener::bind((ip, port)).await {
        Ok(l) => l,
        Err(e) => return fail(json, &format!("cannot bind {bind}:{port}: {e}")),
    };
    let addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    println!(
        "{}",
        cli::ok(&format!("\"listening\":\"{}\"", cli::esc(&addr)))
    );
    log::info(&format!("serving on {addr} (db {})", db_path.display()));
    let live_ctx = live::Ctx::new(
        state.apns.clone(),
        state.apns_key.clone(),
        state.throttle.clone(),
    );
    let probe_db = db_path.clone();
    let probe_live = live_ctx.clone();
    let prober = tokio::spawn(async move {
        let client = reqwest::Client::new();
        let mut due: HashMap<String, u64> = HashMap::new();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let checks = db::open(&probe_db)
                .ok()
                .and_then(|c| db::check_list(&c).ok())
                .unwrap_or_default();
            let names: std::collections::HashSet<String> =
                checks.iter().map(|c| c.name.clone()).collect();
            due.retain(|n, _| names.contains(n));
            let now = model::now_epoch();
            for c in checks.iter().filter(|c| {
                (c.runner == "hub" || c.runner == "both")
                    && matches!(c.ctype.as_str(), "url" | "api" | "heartbeat")
            }) {
                if now < due.get(&c.name).copied().unwrap_or(0) {
                    continue;
                }
                due.insert(c.name.clone(), now + c.every_secs);
                if let Some(flip) = est_hub::probe::probe_check(&client, &probe_db, &c.name).await {
                    live::on_flip(
                        &probe_live,
                        &probe_db,
                        &flip.name,
                        flip.went_down,
                        &flip.note,
                        flip.row.as_ref(),
                    )
                    .await;
                }
            }
        }
    });
    // The 6h Live Activity refresh: re-push every enabled card, and
    // restart aging ones before Apple's ~8h auto-end.
    let refresh_live = live_ctx.clone();
    let refresh_db = db_path.clone();
    let refresher = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(live::REFRESH_SECS)).await;
            live::refresh_all(&refresh_live, &refresh_db).await;
        }
    });
    // The watchdog tick: one silent round every 6h, so a phone that
    // stops hearing ticks knows the hub went quiet. Unconfigured
    // APNs skips the round (the drill route says so out loud).
    let alive_apns = state.apns.clone();
    let alive_key = state.apns_key.clone();
    let alive_db = db_path.clone();
    let aliver = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(est_hub::apns::ALIVE_SECS)).await;
            let conn = match db::open(&alive_db) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let cfg = match est_hub::apns::load(alive_key.as_deref(), &alive_db, &conn) {
                Ok(Some(cfg)) => cfg,
                _ => continue,
            };
            drop(conn);
            let out = est_hub::apns::deliver_alive(&alive_apns, &alive_db, &cfg).await;
            log::info(&format!("alive round: {} device(s)", out.len()));
        }
    });
    let plain = axum::serve(listener, api::router(state.clone())).with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    let code = match plain.await {
        Ok(()) => 0,
        Err(e) => fail(json, &format!("serve failed: {e}")),
    };
    prober.abort();
    refresher.abort();
    aliver.abort();
    code
}

// ---------------------------------------------------------------- ping

async fn cmd_ping_async(args: &[String], json: bool) -> i32 {
    let mut hub: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--hub" => {
                i += 1;
                let u = args.get(i).map(String::as_str).unwrap_or("").trim();
                if u.is_empty() {
                    eprintln!("est-hub ping: --hub needs a URL");
                    return 2;
                }
                hub = Some(u.to_string());
            }
            flag if flag.starts_with("--") => {
                eprintln!("est-hub ping: unexpected {flag:?}");
                return 2;
            }
            t => {
                eprintln!("est-hub ping: unexpected {t:?}");
                return 2;
            }
        }
        i += 1;
    }
    let base = hub_url(hub.as_deref());
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    let (status, body) = match api(&client, "GET", &format!("{base}/ping"), None).await {
        Ok(r) => r,
        Err(e) => return fail(json, &e),
    };
    if !(200..300).contains(&status) {
        return fail(json, &api_error(&body, status));
    }
    if json {
        println!("{}", body.trim());
        return 0;
    }
    let (name, version) = parse_ping(&body).unwrap_or(("?", "?"));
    println!("hub ok ({name} {version})");
    0
}

// ---------------------------------------------------------------- flag helpers

/// Value of `--flag X`; usage error (exit 2) when missing or blank.
fn need(args: &[String], i: &mut usize, cmd: &str, flag: &str) -> Result<String, i32> {
    *i += 1;
    let v = args
        .get(*i)
        .map(String::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if v.is_empty() {
        eprintln!("est-hub {cmd}: {flag} needs a value");
        return Err(2);
    }
    Ok(v)
}

fn opt(args: &[String], i: &mut usize, flag: &str) -> Option<String> {
    let _ = flag;
    *i += 1;
    args.get(*i)
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Split `--hub` out of client args; returns (hub base, rest).
fn split_hub(args: &[String], cmd: &str) -> Result<(String, Vec<String>), i32> {
    let mut hub: Option<String> = None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--hub" {
            i += 1;
            let u = args.get(i).map(String::as_str).unwrap_or("").trim();
            if u.is_empty() {
                eprintln!("est-hub {cmd}: --hub needs a URL");
                return Err(2);
            }
            hub = Some(u.to_string());
        } else {
            rest.push(args[i].clone());
        }
        i += 1;
    }
    Ok((hub_url(hub.as_deref()), rest))
}

// ---------------------------------------------------------------- devices

async fn cmd_devices_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "devices") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    match verb {
        "add" => {
            let mut name = "";
            let mut apns: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--apns" => apns = opt(rest, &mut i, "--apns"),
                    f if f.starts_with("--") => {
                        eprintln!("est-hub devices add: unexpected {f:?}");
                        return 2;
                    }
                    n if name.is_empty() => name = n,
                    n => {
                        eprintln!("est-hub devices add: unexpected {n:?}");
                        return 2;
                    }
                }
                i += 1;
            }
            if name.is_empty() {
                eprintln!("est-hub devices add: NAME first");
                return 2;
            }
            let (status, body) = match api(
                &client,
                "POST",
                &format!("{base}/devices"),
                Some(serde_json::json!({"name": name, "apns_token": apns})),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&body, status));
            }
            if json {
                println!("{}", body.trim());
            } else {
                println!("added device {name}");
            }
            0
        }
        "list" => {
            if !rest.is_empty() {
                eprintln!("est-hub devices list: no arguments");
                return 2;
            }
            let (status, body) = match api(&client, "GET", &format!("{base}/devices"), None).await {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&body, status));
            }
            if json {
                println!("{}", body.trim());
                return 0;
            }
            let v = value(&body);
            let n = v
                .pointer("/devices")
                .and_then(|d| d.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            if n == 0 {
                println!("no devices");
                return 0;
            }
            for d in v.pointer("/devices").and_then(|d| d.as_array()).unwrap() {
                println!("{}", d.get("name").and_then(|n| n.as_str()).unwrap_or("?"));
            }
            0
        }
        "show" => {
            if rest.len() != 1 {
                eprintln!("est-hub devices show: NAME");
                return 2;
            }
            let (status, body) = match api(
                &client,
                "GET",
                &format!("{}/devices/{}", base, rest[0]),
                None,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&body, status));
            }
            if json {
                println!("{}", body.trim());
                return 0;
            }
            let v = value(&body);
            println!("device:  {}", str_field(&v, "/device/name"));
            println!(
                "apns:    {}",
                if v.pointer("/device/apns_token")
                    .and_then(|t| t.as_str())
                    .is_some()
                {
                    "set"
                } else {
                    "-"
                }
            );
            0
        }
        "revoke" => {
            let mut name = "";
            let mut yes = false;
            for a in rest {
                if a == "--yes" {
                    yes = true;
                } else if !a.starts_with("--") && name.is_empty() {
                    name = a;
                } else {
                    eprintln!("est-hub devices revoke: NAME --yes");
                    return 2;
                }
            }
            if name.is_empty() {
                eprintln!("est-hub devices revoke: NAME --yes");
                return 2;
            }
            if !confirm(&format!("revoke device {name}"), yes) {
                return 1;
            }
            let (status, body) = match api(
                &client,
                "DELETE",
                &format!("{}/devices/{}", base, name),
                None,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&body, status));
            }
            if json {
                println!("{}", body.trim());
            } else {
                println!("revoked device {name}");
            }
            0
        }
        "set" => {
            let mut name = "";
            let mut apns: Option<String> = None;
            let mut env: Option<String> = None;
            let mut topic: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--apns" => match need(rest, &mut i, "devices set", "--apns") {
                        Ok(v) => apns = Some(v),
                        Err(c) => return c,
                    },
                    "--apns-env" => match need(rest, &mut i, "devices set", "--apns-env") {
                        Ok(v) => env = Some(v),
                        Err(c) => return c,
                    },
                    "--apns-topic" => match need(rest, &mut i, "devices set", "--apns-topic") {
                        Ok(v) => topic = Some(v),
                        Err(c) => return c,
                    },
                    f if f.starts_with("--") => {
                        eprintln!("est-hub devices set: unexpected {f:?}");
                        return 2;
                    }
                    n if name.is_empty() => name = n,
                    n => {
                        eprintln!("est-hub devices set: unexpected {n:?}");
                        return 2;
                    }
                }
                i += 1;
            }
            if name.is_empty() {
                eprintln!("est-hub devices set: NAME [--apns T] [--apns-env E] [--apns-topic P]");
                return 2;
            }
            // Absent flags stay absent: the route keeps what it has.
            // Sending nulls used to wipe push state (Part 3 folds the fix).
            let mut fields = serde_json::Map::new();
            if let Some(a) = apns {
                fields.insert("apns_token".to_string(), a.into());
            }
            if let Some(e) = env {
                fields.insert("apns_env".to_string(), e.into());
            }
            if let Some(t) = topic {
                fields.insert("apns_topic".to_string(), t.into());
            }
            let (status, body) = match api(
                &client,
                "PUT",
                &format!("{base}/devices/{name}"),
                Some(serde_json::Value::Object(fields)),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&body, status));
            }
            if json {
                println!("{}", body.trim());
            } else {
                println!("updated device {name}");
            }
            0
        }
        "live" => cmd_devices_live(&base, &client, rest, json).await,
        _ => {
            eprintln!("est-hub devices: add, list, show, revoke, set, live (try: help)");
            2
        }
    }
}

/// `devices live …`: the Live Activity feed per device — configure it,
/// read it back, and register/forget activity push tokens.
async fn cmd_devices_live(
    base: &str,
    client: &reqwest::Client,
    rest: &[String],
    json: bool,
) -> i32 {
    let verb = rest.first().map(String::as_str).unwrap_or("");
    let rest = if rest.is_empty() { &[][..] } else { &rest[1..] };
    match verb {
        "set" => cmd_live_set(base, client, rest, json).await,
        "show" => cmd_live_show(base, client, rest, json).await,
        "token" => cmd_live_token(base, client, rest, json).await,
        "untoken" => cmd_live_untoken(base, client, rest, json).await,
        _ => {
            eprintln!("est-hub devices live: set, show, token, untoken (try: help)");
            2
        }
    }
}

async fn cmd_live_set(base: &str, client: &reqwest::Client, rest: &[String], json: bool) -> i32 {
    let mut name = "";
    let mut enabled: Option<bool> = None;
    let mut pts: Option<String> = None;
    let mut checks: Option<serde_json::Value> = None;
    let mut min_severity: Option<String> = None;
    let mut approvals: Option<bool> = None;
    let mut alert_on_down: Option<bool> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--enable" => enabled = Some(true),
            "--disable" => enabled = Some(false),
            "--pts" => match need(rest, &mut i, "devices live set", "--pts") {
                Ok(v) => pts = Some(v),
                Err(c) => return c,
            },
            "--checks" => match need(rest, &mut i, "devices live set", "--checks") {
                Ok(v) if v.trim() == "all" => checks = Some(serde_json::Value::Null),
                Ok(v) => {
                    let list: Vec<serde_json::Value> = v
                        .split(',')
                        .map(str::trim)
                        .filter(|n| !n.is_empty())
                        .map(|n| serde_json::Value::String(n.to_string()))
                        .collect();
                    checks = Some(serde_json::Value::Array(list));
                }
                Err(c) => return c,
            },
            "--min-severity" => match need(rest, &mut i, "devices live set", "--min-severity") {
                Ok(v) => min_severity = Some(v),
                Err(c) => return c,
            },
            "--approvals" => approvals = Some(true),
            "--no-approvals" => approvals = Some(false),
            "--alert-on-down" => alert_on_down = Some(true),
            "--no-alert-on-down" => alert_on_down = Some(false),
            f if f.starts_with("--") => {
                eprintln!("est-hub devices live set: unexpected {f:?}");
                return 2;
            }
            n if name.is_empty() => name = n,
            n => {
                eprintln!("est-hub devices live set: unexpected {n:?}");
                return 2;
            }
        }
        i += 1;
    }
    if name.is_empty() {
        eprintln!("est-hub devices live set: NAME [--enable|--disable] …");
        return 2;
    }
    // Absent flags stay absent: the route keeps what it has.
    let mut fields = serde_json::Map::new();
    if let Some(v) = enabled {
        fields.insert("enabled".to_string(), v.into());
    }
    if let Some(v) = pts {
        fields.insert("pts_token".to_string(), v.into());
    }
    if let Some(v) = checks {
        fields.insert("checks".to_string(), v);
    }
    if let Some(v) = min_severity {
        fields.insert("min_severity".to_string(), v.into());
    }
    if let Some(v) = approvals {
        fields.insert("approvals".to_string(), v.into());
    }
    if let Some(v) = alert_on_down {
        fields.insert("alert_on_down".to_string(), v.into());
    }
    let (status, out) = match api(
        client,
        "PUT",
        &format!("{base}/devices/{name}/live-activity"),
        Some(serde_json::Value::Object(fields)),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return fail(json, &e),
    };
    if !(200..300).contains(&status) {
        return fail(json, &api_error(&out, status));
    }
    if json {
        println!("{}", out.trim());
        return 0;
    }
    println!(
        "live activity for {name}: {}",
        str_field(&value(&out), "/status")
    );
    0
}

async fn cmd_live_show(base: &str, client: &reqwest::Client, rest: &[String], json: bool) -> i32 {
    if rest.len() != 1 {
        eprintln!("est-hub devices live show: NAME");
        return 2;
    }
    let (status, out) = match api(
        client,
        "GET",
        &format!("{}/devices/{}/live-activity", base, rest[0]),
        None,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return fail(json, &e),
    };
    if !(200..300).contains(&status) {
        return fail(json, &api_error(&out, status));
    }
    if json {
        println!("{}", out.trim());
        return 0;
    }
    let v = value(&out);
    let flag = |ptr: &str| {
        v.pointer(ptr)
            .and_then(|b| b.as_bool())
            .map(|b| if b { "on" } else { "off" })
            .unwrap_or("?")
    };
    let checks = match v.pointer("/config/checks") {
        None | Some(serde_json::Value::Null) => "all".to_string(),
        Some(serde_json::Value::Array(items)) if items.is_empty() => "-".to_string(),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|n| n.as_str())
            .collect::<Vec<_>>()
            .join(","),
        _ => "?".to_string(),
    };
    let stamp = |ptr: &str| {
        v.pointer(ptr)
            .and_then(|t| t.as_u64())
            .map(|t| t.to_string())
            .unwrap_or("-".to_string())
    };
    println!("device:        {}", str_field(&v, "/device"));
    println!("status:        {}", str_field(&v, "/status"));
    println!("enabled:       {}", flag("/config/enabled"));
    println!("checks:        {checks}");
    println!("min_severity:  {}", str_field(&v, "/config/min_severity"));
    println!("approvals:     {}", flag("/config/approvals"));
    println!("alert_on_down: {}", flag("/config/alert_on_down"));
    println!(
        "pts:           {}",
        if v.pointer("/pts_configured")
            .and_then(|b| b.as_bool())
            .unwrap_or(false)
        {
            "set"
        } else {
            "-"
        }
    );
    println!(
        "activity:      {}",
        v.pointer("/activity_id")
            .and_then(|a| a.as_str())
            .unwrap_or("-")
    );
    println!("started:       {}", stamp("/started_ts"));
    println!("last_push:     {}", stamp("/last_push_ts"));
    println!(
        "tokens:        {}",
        v.pointer("/tokens")
            .and_then(|t| t.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    );
    0
}

async fn cmd_live_token(base: &str, client: &reqwest::Client, rest: &[String], json: bool) -> i32 {
    let mut name = "";
    let mut activity: Option<String> = None;
    let mut token: Option<String> = None;
    let mut label: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--activity" => match need(rest, &mut i, "devices live token", "--activity") {
                Ok(v) => activity = Some(v),
                Err(c) => return c,
            },
            "--token" => match need(rest, &mut i, "devices live token", "--token") {
                Ok(v) => token = Some(v),
                Err(c) => return c,
            },
            "--label" => match need(rest, &mut i, "devices live token", "--label") {
                Ok(v) => label = Some(v),
                Err(c) => return c,
            },
            f if f.starts_with("--") => {
                eprintln!("est-hub devices live token: unexpected {f:?}");
                return 2;
            }
            n if name.is_empty() => name = n,
            n => {
                eprintln!("est-hub devices live token: unexpected {n:?}");
                return 2;
            }
        }
        i += 1;
    }
    let (Some(activity), Some(token)) = (activity, token) else {
        eprintln!("est-hub devices live token: NAME --activity ID --token T [--label L]");
        return 2;
    };
    if name.is_empty() {
        eprintln!("est-hub devices live token: NAME --activity ID --token T [--label L]");
        return 2;
    }
    let mut fields = serde_json::Map::new();
    fields.insert("activity_id".to_string(), serde_json::json!(activity));
    fields.insert("token".to_string(), serde_json::json!(token));
    if let Some(label) = label {
        fields.insert("label".to_string(), serde_json::json!(label));
    }
    let (status, out) = match api(
        client,
        "POST",
        &format!("{base}/devices/{name}/live-activity/tokens"),
        Some(serde_json::Value::Object(fields)),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return fail(json, &e),
    };
    if !(200..300).contains(&status) {
        return fail(json, &api_error(&out, status));
    }
    if json {
        println!("{}", out.trim());
    } else {
        println!("registered activity {activity} for {name}");
    }
    0
}

async fn cmd_live_untoken(
    base: &str,
    client: &reqwest::Client,
    rest: &[String],
    json: bool,
) -> i32 {
    if rest.len() != 2 {
        eprintln!("est-hub devices live untoken: NAME ID");
        return 2;
    }
    let (status, out) = match api(
        client,
        "DELETE",
        &format!(
            "{}/devices/{}/live-activity/tokens/{}",
            base, rest[0], rest[1]
        ),
        None,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return fail(json, &e),
    };
    if !(200..300).contains(&status) {
        return fail(json, &api_error(&out, status));
    }
    if json {
        println!("{}", out.trim());
    } else {
        println!("removed activity {} from {}", rest[1], rest[0]);
    }
    0
}

// ---------------------------------------------------------------- checks

struct CheckFlags {
    ctype: Option<String>,
    target: Option<String>,
    owner: Option<String>,
    every: Option<String>,
    timeout: Option<String>,
    severity: Option<String>,
    runner: Option<String>,
    source: Option<String>,
    expect: Option<String>,
    contains: Option<String>,
    miss_after: Option<String>,
    warn_below: Option<String>,
    crit_below: Option<String>,
}

fn parse_check_flags(rest: &[String], cmd: &str) -> Result<(String, CheckFlags), i32> {
    let mut name = String::new();
    let mut f = CheckFlags {
        ctype: None,
        target: None,
        owner: None,
        every: None,
        timeout: None,
        severity: None,
        runner: None,
        source: None,
        expect: None,
        contains: None,
        miss_after: None,
        warn_below: None,
        crit_below: None,
    };
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--type" => f.ctype = Some(need(rest, &mut i, cmd, "--type")?),
            "--target" => f.target = Some(need(rest, &mut i, cmd, "--target")?),
            "--owner" => f.owner = Some(need(rest, &mut i, cmd, "--owner")?),
            "--every" => f.every = Some(need(rest, &mut i, cmd, "--every")?),
            "--timeout" => f.timeout = Some(need(rest, &mut i, cmd, "--timeout")?),
            "--severity" => f.severity = Some(need(rest, &mut i, cmd, "--severity")?),
            "--runner" => f.runner = Some(need(rest, &mut i, cmd, "--runner")?),
            "--source" => f.source = Some(need(rest, &mut i, cmd, "--source")?),
            "--expect" => f.expect = Some(need(rest, &mut i, cmd, "--expect")?),
            "--contains" => f.contains = Some(need(rest, &mut i, cmd, "--contains")?),
            "--miss-after" => f.miss_after = Some(need(rest, &mut i, cmd, "--miss-after")?),
            "--warn-below" => f.warn_below = Some(need(rest, &mut i, cmd, "--warn-below")?),
            "--crit-below" => f.crit_below = Some(need(rest, &mut i, cmd, "--crit-below")?),
            x if x.starts_with("--") => {
                eprintln!("est-hub {cmd}: unexpected {x:?}");
                return Err(2);
            }
            n if name.is_empty() => name = n.to_string(),
            n => {
                eprintln!("est-hub {cmd}: unexpected {n:?}");
                return Err(2);
            }
        }
        i += 1;
    }
    if name.is_empty() {
        eprintln!("est-hub {cmd}: NAME first");
        return Err(2);
    }
    Ok((name, f))
}

fn num<T: std::str::FromStr>(cmd: &str, flag: &str, v: Option<String>) -> Result<Option<T>, i32> {
    match v {
        None => Ok(None),
        Some(s) => match s.parse::<T>() {
            Ok(n) => Ok(Some(n)),
            Err(_) => {
                eprintln!("est-hub {cmd}: {flag} needs a number, got {s:?}");
                Err(2)
            }
        },
    }
}

fn check_body(
    cmd: &str,
    name: &str,
    f: CheckFlags,
    require_core: bool,
) -> Result<serde_json::Value, i32> {
    if require_core && (f.ctype.is_none() || f.target.is_none() || f.owner.is_none()) {
        eprintln!("est-hub {cmd}: --type, --target, --owner are required");
        return Err(2);
    }
    let mut m = serde_json::Map::new();
    m.insert(
        "name".to_string(),
        serde_json::Value::String(name.to_string()),
    );
    if let Some(v) = f.ctype {
        m.insert("type".to_string(), v.into());
    }
    if let Some(v) = f.target {
        m.insert("target".to_string(), v.into());
    }
    if let Some(v) = f.owner {
        m.insert("owner".to_string(), v.into());
    }
    if let Some(v) = num::<u64>(cmd, "--every", f.every)? {
        m.insert("every_secs".to_string(), v.into());
    }
    if let Some(v) = num::<u64>(cmd, "--timeout", f.timeout)? {
        m.insert("timeout_secs".to_string(), v.into());
    }
    if let Some(v) = f.severity {
        m.insert("severity".to_string(), v.into());
    }
    if let Some(v) = f.runner {
        m.insert("runner".to_string(), v.into());
    }
    if let Some(v) = f.source {
        m.insert("source".to_string(), v.into());
    }
    if let Some(v) = num::<u16>(cmd, "--expect", f.expect)? {
        m.insert("expect".to_string(), v.into());
    }
    if let Some(v) = f.contains {
        m.insert("contains".to_string(), v.into());
    }
    if let Some(v) = num::<u64>(cmd, "--miss-after", f.miss_after)? {
        m.insert("miss_after_secs".to_string(), v.into());
    }
    if let Some(v) = num::<f64>(cmd, "--warn-below", f.warn_below)? {
        m.insert("warn_below".to_string(), serde_json::json!(v));
    }
    if let Some(v) = num::<f64>(cmd, "--crit-below", f.crit_below)? {
        m.insert("crit_below".to_string(), serde_json::json!(v));
    }
    Ok(serde_json::Value::Object(m))
}

/// The sync's unchanged test: definition fields equal (live state
/// ignored). `expect` nests under `config` on stored checks.
fn same_definition(cur: &serde_json::Value, want: &serde_json::Value) -> bool {
    [
        "type",
        "target",
        "owner",
        "every_secs",
        "timeout_secs",
        "severity",
        "runner",
        "source",
    ]
    .iter()
    .all(|k| cur.pointer(&format!("/{k}")) == want.pointer(&format!("/{k}")))
        && cur.pointer("/config/expect") == want.pointer("/expect")
}

async fn cmd_checks_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "checks") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    match verb {
        "add" => {
            let (name, f) = match parse_check_flags(rest, "checks add") {
                Ok(r) => r,
                Err(c) => return c,
            };
            let body = match check_body("checks add", &name, f, true) {
                Ok(b) => b,
                Err(c) => return c,
            };
            let (status, out) =
                match api(&client, "POST", &format!("{base}/checks"), Some(body)).await {
                    Ok(r) => r,
                    Err(e) => return fail(json, &e),
                };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                println!("added check {name}");
            }
            0
        }
        "list" => {
            let mut owner: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                if rest[i] == "--owner" {
                    match need(rest, &mut i, "checks list", "--owner") {
                        Ok(o) => owner = Some(o),
                        Err(c) => return c,
                    }
                } else {
                    eprintln!("est-hub checks list: [--owner O]");
                    return 2;
                }
                i += 1;
            }
            let url = match owner {
                Some(o) => format!("{base}/checks?owner={o}"),
                None => format!("{base}/checks"),
            };
            let (status, out) = match api(&client, "GET", &url, None).await {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
                return 0;
            }
            let v = value(&out);
            let list = v.pointer("/checks").and_then(|c| c.as_array());
            if list.is_none_or(|l| l.is_empty()) {
                println!("no checks");
                return 0;
            }
            for c in list.unwrap() {
                let g = |p: &str| c.pointer(p).and_then(|x| x.as_str()).unwrap_or("?");
                println!(
                    "{} {} {} {}",
                    g("/name"),
                    g("/type"),
                    g("/state/status"),
                    g("/owner")
                );
            }
            0
        }
        "show" => {
            if rest.len() != 1 {
                eprintln!("est-hub checks show: NAME");
                return 2;
            }
            let (status, out) = match api(
                &client,
                "GET",
                &format!("{}/checks/{}", base, rest[0]),
                None,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
                return 0;
            }
            let v = value(&out);
            println!("check:   {}", str_field(&v, "/check/name"));
            println!(
                "type:    {} {}",
                str_field(&v, "/check/type"),
                str_field(&v, "/check/target")
            );
            println!(
                "owner:   {}  severity: {}",
                str_field(&v, "/check/owner"),
                str_field(&v, "/check/severity")
            );
            println!("status:  {}", str_field(&v, "/check/state/status"));
            println!("reason:  {}", str_field(&v, "/check/state/last_reason"));
            let horizon = |p: &str| v.pointer(p).and_then(|u| u.as_u64()).unwrap_or(0);
            let ack = horizon("/check/ack_until");
            let mute = horizon("/check/mute_until");
            if ack > 0 || mute > 0 {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let words = |until: u64| {
                    if until <= now {
                        "expired".to_string()
                    } else {
                        let s = until - now;
                        if s < 3600 {
                            format!("{}m left", s / 60)
                        } else if s < 86400 {
                            format!("{}h left", s / 3600)
                        } else {
                            format!("{}d left", s / 86400)
                        }
                    }
                };
                if ack > 0 {
                    println!("ack:     {}", words(ack));
                }
                if mute > 0 {
                    println!("mute:    {}", words(mute));
                }
            }
            0
        }
        "set" => {
            let (name, f) = match parse_check_flags(rest, "checks set") {
                Ok(r) => r,
                Err(c) => return c,
            };
            let body = match check_body("checks set", &name, f, true) {
                Ok(b) => b,
                Err(c) => return c,
            };
            let (status, out) =
                match api(&client, "PUT", &format!("{base}/checks/{name}"), Some(body)).await {
                    Ok(r) => r,
                    Err(e) => return fail(json, &e),
                };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                println!("updated check {name}");
            }
            0
        }
        "delete" => {
            let mut name = "";
            let mut yes = false;
            for a in rest {
                if a == "--yes" {
                    yes = true;
                } else if !a.starts_with("--") && name.is_empty() {
                    name = a;
                } else {
                    eprintln!("est-hub checks delete: NAME --yes");
                    return 2;
                }
            }
            if name.is_empty() {
                eprintln!("est-hub checks delete: NAME --yes");
                return 2;
            }
            if !confirm(&format!("delete check {name}"), yes) {
                return 1;
            }
            let (status, out) =
                match api(&client, "DELETE", &format!("{base}/checks/{name}"), None).await {
                    Ok(r) => r,
                    Err(e) => return fail(json, &e),
                };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                println!("deleted check {name}");
            }
            0
        }
        "sync" => {
            let mut ios_root: Option<String> = None;
            let mut backend_root: Option<String> = None;
            let mut backend_url: Option<String> = None;
            let mut every = "300".to_string();
            let mut timeout = "15".to_string();
            let mut prune = false;
            let mut dry_run = false;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--ios-root" => {
                        ios_root = Some(match need(rest, &mut i, "checks sync", "--ios-root") {
                            Ok(v) => v,
                            Err(c) => return c,
                        });
                    }
                    "--backend-root" => {
                        backend_root =
                            Some(match need(rest, &mut i, "checks sync", "--backend-root") {
                                Ok(v) => v,
                                Err(c) => return c,
                            });
                    }
                    "--backend-url" => {
                        backend_url =
                            Some(match need(rest, &mut i, "checks sync", "--backend-url") {
                                Ok(v) => v,
                                Err(c) => return c,
                            });
                    }
                    "--every" => {
                        every = match need(rest, &mut i, "checks sync", "--every") {
                            Ok(v) => v,
                            Err(c) => return c,
                        };
                    }
                    "--timeout" => {
                        timeout = match need(rest, &mut i, "checks sync", "--timeout") {
                            Ok(v) => v,
                            Err(c) => return c,
                        };
                    }
                    "--prune" => prune = true,
                    "--dry-run" => dry_run = true,
                    x => {
                        eprintln!("est-hub checks sync: unexpected {x:?}");
                        return 2;
                    }
                }
                i += 1;
            }
            if ios_root.is_none() && backend_root.is_none() {
                eprintln!("est-hub checks sync: --ios-root and/or --backend-root is required");
                return 2;
            }
            if backend_root.is_some() != backend_url.is_some() {
                eprintln!("est-hub checks sync: --backend-root needs --backend-url");
                return 2;
            }
            let every_secs: u64 = match every.parse() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("est-hub checks sync: --every needs a number, got {every:?}");
                    return 2;
                }
            };
            let timeout_secs: u64 = match timeout.parse() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("est-hub checks sync: --timeout needs a number, got {timeout:?}");
                    return 2;
                }
            };
            let mut wants: Vec<sync::Want> = Vec::new();
            let mut warnings: Vec<String> = Vec::new();
            let mut projects: Vec<sync::ProjectMeta> = Vec::new();
            if let Some(r) = &ios_root {
                let root = PathBuf::from(r);
                if !root.join("apps").is_dir() {
                    eprintln!("est-hub checks sync: {r} has no apps/ dir");
                    return 2;
                }
                let scanned = sync::scan_ios_apps(&root, every_secs, timeout_secs);
                wants.extend(scanned.wants);
                warnings.extend(scanned.warnings);
                let (metas, mut w) = sync::scan_ios_projects(&root);
                warnings.append(&mut w);
                projects.extend(metas);
            }
            if let (Some(r), Some(u)) = (&backend_root, &backend_url) {
                let root = PathBuf::from(r);
                if !root.join("internal/apps").is_dir() {
                    eprintln!("est-hub checks sync: {r} has no internal/apps/ dir");
                    return 2;
                }
                let (keys, mut w) = sync::scan_backend_apps(&root);
                warnings.append(&mut w);
                wants.extend(sync::backend_wants(u, &keys, every_secs, timeout_secs));
            }
            for w in &warnings {
                eprintln!("warning: {w}");
            }
            let (status, out) = match api(&client, "GET", &format!("{base}/checks"), None).await {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            let existing: Vec<serde_json::Value> = value(&out)
                .pointer("/checks")
                .and_then(|c| c.as_array())
                .cloned()
                .unwrap_or_default();
            let mut added: Vec<String> = Vec::new();
            let mut updated: Vec<String> = Vec::new();
            let mut unchanged = 0u32;
            let mut pruned: Vec<String> = Vec::new();
            let mut stale: Vec<String> = Vec::new();
            let mut failed: Vec<serde_json::Value> = Vec::new();
            for w in &wants {
                let body = serde_json::json!({
                    "name": w.name,
                    "type": "url",
                    "target": w.target,
                    "owner": w.owner,
                    "every_secs": w.every_secs,
                    "timeout_secs": w.timeout_secs,
                    "severity": w.severity,
                    "runner": "hub",
                    "source": "auto",
                    "expect": w.expect,
                });
                let cur = existing
                    .iter()
                    .find(|c| c.pointer("/name").and_then(|n| n.as_str()) == Some(w.name.as_str()));
                match cur {
                    Some(c) if same_definition(c, &body) => unchanged += 1,
                    Some(_) => {
                        if dry_run {
                            updated.push(w.name.clone());
                        } else {
                            let url = format!("{base}/checks/{}", w.name);
                            match api(&client, "PUT", &url, Some(body)).await {
                                Ok((s, _)) if (200..300).contains(&s) => {
                                    updated.push(w.name.clone());
                                }
                                Ok((s, o)) => failed.push(
                                    serde_json::json!({"name": w.name, "error": api_error(&o, s)}),
                                ),
                                Err(e) => {
                                    failed.push(serde_json::json!({"name": w.name, "error": e}));
                                }
                            }
                        }
                    }
                    None => {
                        if dry_run {
                            added.push(w.name.clone());
                        } else {
                            match api(
                                &client,
                                "POST",
                                &format!("{base}/checks"),
                                Some(body.clone()),
                            )
                            .await
                            {
                                Ok((s, _)) if (200..300).contains(&s) => {
                                    added.push(w.name.clone());
                                }
                                Ok((409, _)) => {
                                    let url = format!("{base}/checks/{}", w.name);
                                    match api(&client, "PUT", &url, Some(body)).await {
                                        Ok((s, _)) if (200..300).contains(&s) => {
                                            updated.push(w.name.clone());
                                        }
                                        Ok((s, o)) => failed.push(serde_json::json!({"name": w.name, "error": api_error(&o, s)})),
                                        Err(e) => {
                                            failed.push(serde_json::json!({"name": w.name, "error": e}));
                                        }
                                    }
                                }
                                Ok((s, o)) => failed.push(
                                    serde_json::json!({"name": w.name, "error": api_error(&o, s)}),
                                ),
                                Err(e) => {
                                    failed.push(serde_json::json!({"name": w.name, "error": e}));
                                }
                            }
                        }
                    }
                }
            }
            // Stale only counts what this run scanned: a backend-only
            // run must not call the iOS checks gone.
            let scans_ios = ios_root.is_some();
            let scans_backend = backend_root.is_some();
            for c in &existing {
                let name = c.pointer("/name").and_then(|n| n.as_str()).unwrap_or("");
                let source = c.pointer("/source").and_then(|s| s.as_str()).unwrap_or("");
                let managed = sync::sync_manages(name, source, scans_ios, scans_backend);
                if !managed || wants.iter().any(|w| w.name == name) {
                    continue;
                }
                if dry_run {
                    if prune {
                        pruned.push(name.to_string());
                    } else {
                        stale.push(name.to_string());
                    }
                } else if !prune {
                    stale.push(name.to_string());
                } else {
                    match api(&client, "DELETE", &format!("{base}/checks/{name}"), None).await {
                        Ok((s, _)) if (200..300).contains(&s) => pruned.push(name.to_string()),
                        Ok((s, o)) => failed
                            .push(serde_json::json!({"name": name, "error": api_error(&o, s)})),
                        Err(e) => failed.push(serde_json::json!({"name": name, "error": e})),
                    }
                }
            }
            // Projects ride the iOS walk: metadata upserts plus icon
            // uploads only when the bytes changed (sha-compared).
            let mut p_upserted: Vec<String> = Vec::new();
            let mut p_unchanged = 0u32;
            let mut p_icons: Vec<String> = Vec::new();
            if !projects.is_empty() {
                let (p_status, p_out) =
                    match api(&client, "GET", &format!("{base}/projects"), None).await {
                        Ok(r) => r,
                        Err(e) => return fail(json, &e),
                    };
                if !(200..300).contains(&p_status) {
                    return fail(json, &api_error(&p_out, p_status));
                }
                let stored: Vec<serde_json::Value> = value(&p_out)
                    .pointer("/projects")
                    .and_then(|p| p.as_array())
                    .cloned()
                    .unwrap_or_default();
                for m in &projects {
                    let cur = stored.iter().find(|p| {
                        p.pointer("/slug").and_then(|s| s.as_str()) == Some(m.slug.as_str())
                    });
                    let same = cur.is_some_and(|p| {
                        p.pointer("/group").and_then(|s| s.as_str()) == Some(m.group.as_str())
                            && p.pointer("/name").and_then(|s| s.as_str()) == Some(m.name.as_str())
                            && p.pointer("/bundle_id").and_then(|s| s.as_str())
                                == Some(m.bundle_id.as_str())
                    });
                    if same {
                        p_unchanged += 1;
                    } else if dry_run {
                        p_upserted.push(m.slug.clone());
                    } else {
                        let body = serde_json::json!({
                            "group": m.group,
                            "name": m.name,
                            "bundle_id": m.bundle_id,
                        });
                        match api(
                            &client,
                            "PUT",
                            &format!("{base}/projects/{}", m.slug),
                            Some(body),
                        )
                        .await
                        {
                            Ok((s, _)) if (200..300).contains(&s) => {
                                p_upserted.push(m.slug.clone());
                            }
                            Ok((s, o)) => failed.push(
                                serde_json::json!({"name": m.slug, "error": api_error(&o, s)}),
                            ),
                            Err(e) => {
                                failed.push(serde_json::json!({"name": m.slug, "error": e}));
                            }
                        }
                    }
                    if let Some(path) = &m.icon_path {
                        // Bytes first: JPEGs convert via sips, and the
                        // sha compares upload bytes (converted), so a
                        // converted icon does not re-upload every run.
                        let bytes = match sync::png_upload_bytes(path) {
                            Ok(b) => b,
                            Err(e) => {
                                failed.push(serde_json::json!({"name": m.slug, "error": e}));
                                continue;
                            }
                        };
                        if bytes.len() > 1024 * 1024 {
                            failed.push(
                                serde_json::json!({"name": m.slug, "error": "icon is 1MB max"}),
                            );
                            continue;
                        }
                        let remote_sha = cur
                            .and_then(|p| p.pointer("/icon_sha256"))
                            .and_then(|s| s.as_str())
                            .unwrap_or("");
                        if sync::sha256_hex(&bytes) == remote_sha {
                            continue;
                        }
                        if dry_run {
                            p_icons.push(m.slug.clone());
                            continue;
                        }
                        let res = client
                            .put(format!("{base}/projects/{}/icon", m.slug))
                            .header("content-type", "image/png")
                            .body(bytes)
                            .send()
                            .await;
                        match res {
                            Ok(r) => {
                                let s = r.status().as_u16();
                                let o = r.text().await.unwrap_or_default();
                                if (200..300).contains(&s) {
                                    p_icons.push(m.slug.clone());
                                } else {
                                    failed.push(serde_json::json!({"name": m.slug, "error": api_error(&o, s)}));
                                }
                            }
                            Err(e) => failed
                                .push(serde_json::json!({"name": m.slug, "error": e.to_string()})),
                        }
                    }
                }
            }
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": failed.is_empty(),
                        "v": 1,
                        "dry_run": dry_run,
                        "added": added,
                        "updated": updated,
                        "unchanged": unchanged,
                        "pruned": pruned,
                        "stale": stale,
                        "projects": serde_json::json!({
                            "upserted": p_upserted,
                            "unchanged": p_unchanged,
                            "icons": p_icons,
                        }),
                        "failed": failed,
                        "warnings": warnings,
                    })
                );
            } else {
                let verb = if dry_run { "would add" } else { "added" };
                for n in &added {
                    println!("{verb} check {n}");
                }
                let verb = if dry_run { "would update" } else { "updated" };
                for n in &updated {
                    println!("{verb} check {n}");
                }
                let verb = if dry_run { "would prune" } else { "pruned" };
                for n in &pruned {
                    println!("{verb} check {n}");
                }
                for n in &stale {
                    println!("stale check {n} (gone from repos; --prune deletes)");
                }
                let verb = if dry_run { "would upsert" } else { "upserted" };
                for n in &p_upserted {
                    println!("{verb} project {n}");
                }
                let verb = if dry_run { "would upload" } else { "uploaded" };
                for n in &p_icons {
                    println!("{verb} icon {n}");
                }
                for f in &failed {
                    println!(
                        "failed {}: {}",
                        str_field(f, "/name"),
                        str_field(f, "/error")
                    );
                }
                if dry_run {
                    println!(
                        "dry-run: {} to add, {} to update, {} to prune, {} stale ({} unchanged); {} projects to upsert, {} icons to upload",
                        added.len(),
                        updated.len(),
                        pruned.len(),
                        stale.len(),
                        unchanged,
                        p_upserted.len(),
                        p_icons.len()
                    );
                } else {
                    println!(
                        "sync: {} added, {} updated, {} unchanged, {} pruned, {} stale, {} failed; {} projects upserted ({} unchanged), {} icons",
                        added.len(),
                        updated.len(),
                        unchanged,
                        pruned.len(),
                        stale.len(),
                        failed.len(),
                        p_upserted.len(),
                        p_unchanged,
                        p_icons.len()
                    );
                }
            }
            if failed.is_empty() { 0 } else { 1 }
        }
        "ack" => cmd_checks_silence(&base, &client, rest, json, "ack", false).await,
        "unack" => cmd_checks_silence(&base, &client, rest, json, "ack", true).await,
        "mute" => cmd_checks_silence(&base, &client, rest, json, "mute", false).await,
        "unmute" => cmd_checks_silence(&base, &client, rest, json, "mute", true).await,
        _ => {
            eprintln!(
                "est-hub checks: add, list, show, set, delete, sync, ack, unack, mute, unmute (try: help)"
            );
            2
        }
    }
}

/// `checks ack|mute NAME [--for DUR] [--note TEXT]` and the `un*`
/// lifts. `--for` parses `30m`/`2h`/`7d`/seconds; absent lets the
/// server read the kind's default.
async fn cmd_checks_silence(
    base: &str,
    client: &reqwest::Client,
    rest: &[String],
    json: bool,
    kind: &str,
    lift: bool,
) -> i32 {
    let mut name = "";
    let mut dur: Option<String> = None;
    let mut note: Option<String> = None;
    let mut i = 0;
    let usage = if lift {
        format!("est-hub checks un{kind}: NAME")
    } else {
        format!("est-hub checks {kind}: NAME [--for DUR] [--note TEXT]")
    };
    while i < rest.len() {
        match rest[i].as_str() {
            "--for" if !lift => match need(rest, &mut i, &format!("checks {kind}"), "--for") {
                Ok(v) => dur = Some(v),
                Err(c) => return c,
            },
            "--note" if !lift => match need(rest, &mut i, &format!("checks {kind}"), "--note") {
                Ok(v) => note = Some(v),
                Err(c) => return c,
            },
            f if f.starts_with("--") => {
                eprintln!("{usage}");
                return 2;
            }
            n if name.is_empty() => name = n,
            _ => {
                eprintln!("{usage}");
                return 2;
            }
        }
        i += 1;
    }
    if name.is_empty() {
        eprintln!("{usage}");
        return 2;
    }
    if lift {
        let (status, out) = match api(
            client,
            "DELETE",
            &format!("{base}/checks/{name}/{kind}"),
            None,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => return fail(json, &e),
        };
        if !(200..300).contains(&status) {
            return fail(json, &api_error(&out, status));
        }
        if json {
            println!("{}", out.trim());
        } else {
            println!("un{kind}ed {name}");
        }
        return 0;
    }
    let until_secs = match dur.as_deref().map(parse_dur) {
        None => None,
        Some(Ok(secs)) => Some(secs),
        Some(Err(why)) => {
            eprintln!("est-hub checks {kind}: --for {why}");
            return 2;
        }
    };
    let mut fields = serde_json::Map::new();
    if let Some(secs) = until_secs {
        fields.insert("until_secs".to_string(), serde_json::json!(secs));
    }
    if let Some(note) = note {
        fields.insert("note".to_string(), serde_json::json!(note));
    }
    let (status, out) = match api(
        client,
        "PUT",
        &format!("{base}/checks/{name}/{kind}"),
        Some(serde_json::Value::Object(fields)),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return fail(json, &e),
    };
    if !(200..300).contains(&status) {
        return fail(json, &api_error(&out, status));
    }
    if json {
        println!("{}", out.trim());
        return 0;
    }
    let until = value(&out)
        .pointer(&format!("/check/{kind}_until"))
        .and_then(|u| u.as_u64())
        .unwrap_or(0);
    println!("{kind}ed {name} until {until}");
    0
}

/// `30m` / `2h` / `7d` / `1w` / bare seconds into seconds. Rejects
/// zero, negatives, and unknown suffixes — `--for` typos must fail
/// loud, not silence for a surprise span.
fn parse_dur(raw: &str) -> Result<u64, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("is empty".to_string());
    }
    let (num, mult) = match raw.chars().last() {
        Some(c) if c.is_ascii_digit() => (raw, 1),
        Some('s') => (&raw[..raw.len() - 1], 1),
        Some('m') => (&raw[..raw.len() - 1], 60),
        Some('h') => (&raw[..raw.len() - 1], 3600),
        Some('d') => (&raw[..raw.len() - 1], 86400),
        Some('w') => (&raw[..raw.len() - 1], 7 * 86400),
        _ => return Err(format!("{raw:?} needs a number with s/m/h/d/w")),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("{raw:?} needs a number with s/m/h/d/w"))?;
    if n == 0 {
        return Err("is 0 (silence always ends)".to_string());
    }
    n.checked_mul(mult)
        .ok_or_else(|| format!("{raw:?} overflows"))
}

/// Epoch seconds into `3d ago` words (the list form of `seen_ago`).
fn seen_words(ts: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(ts);
    let ago = now.saturating_sub(ts);
    if ago < 60 {
        format!("{ago}s ago")
    } else if ago < 3600 {
        format!("{}m ago", ago / 60)
    } else if ago < 86400 {
        format!("{}h ago", ago / 3600)
    } else {
        format!("{}d ago", ago / 86400)
    }
}

// ---------------------------------------------------------------- projects

async fn cmd_projects_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "projects") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    match verb {
        "list" => {
            if !rest.is_empty() {
                eprintln!("est-hub projects list: no arguments");
                return 2;
            }
            let (status, out) = match api(&client, "GET", &format!("{base}/projects"), None).await {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                let list = value(&out)
                    .pointer("/projects")
                    .and_then(|p| p.as_array())
                    .cloned()
                    .unwrap_or_default();
                if list.is_empty() {
                    println!("no projects");
                }
                for p in &list {
                    let h = |k: &str| {
                        p.pointer(&format!("/health/{k}"))
                            .and_then(|n| n.as_u64())
                            .unwrap_or(0)
                    };
                    let bundle = str_field(p, "/bundle_id");
                    let bundle = if bundle.is_empty() { "-" } else { &bundle };
                    println!(
                        "{} [{}] {} {}/{}/{} {} ({bundle})",
                        str_field(p, "/slug"),
                        str_field(p, "/group"),
                        str_field(p, "/state"),
                        h("up"),
                        h("down"),
                        h("unknown"),
                        str_field(p, "/name"),
                    );
                }
            }
            0
        }
        "show" => {
            if rest.len() != 1 {
                eprintln!("est-hub projects show: SLUG");
                return 2;
            }
            let (status, out) = match api(
                &client,
                "GET",
                &format!("{}/projects/{}", base, rest[0]),
                None,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                let v = value(&out);
                let h = |k: &str| {
                    v.pointer(&format!("/project/health/{k}"))
                        .and_then(|n| n.as_u64())
                        .unwrap_or(0)
                };
                let icon = v
                    .pointer("/project/has_icon")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false);
                println!("slug:   {}", str_field(&v, "/project/slug"));
                println!("group:  {}", str_field(&v, "/project/group"));
                println!("name:   {}", str_field(&v, "/project/name"));
                println!("bundle: {}", str_field(&v, "/project/bundle_id"));
                println!("icon:   {}", if icon { "set" } else { "-" });
                println!("state:  {}", str_field(&v, "/project/state"));
                println!(
                    "health: {} up, {} down, {} unknown",
                    h("up"),
                    h("down"),
                    h("unknown")
                );
            }
            0
        }
        "set" => {
            let mut slug = String::new();
            let mut group: Option<String> = None;
            let mut name: Option<String> = None;
            let mut bundle = String::new();
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--group" => {
                        group = Some(match need(rest, &mut i, "projects set", "--group") {
                            Ok(v) => v,
                            Err(c) => return c,
                        });
                    }
                    "--name" => {
                        name = Some(match need(rest, &mut i, "projects set", "--name") {
                            Ok(v) => v,
                            Err(c) => return c,
                        });
                    }
                    "--bundle-id" => {
                        bundle = match need(rest, &mut i, "projects set", "--bundle-id") {
                            Ok(v) => v,
                            Err(c) => return c,
                        };
                    }
                    x if x.starts_with("--") => {
                        eprintln!("est-hub projects set: unexpected {x:?}");
                        return 2;
                    }
                    n if slug.is_empty() => slug = n.to_string(),
                    n => {
                        eprintln!("est-hub projects set: unexpected {n:?}");
                        return 2;
                    }
                }
                i += 1;
            }
            if slug.is_empty() || group.is_none() || name.is_none() {
                eprintln!("est-hub projects set: SLUG --group G --name N [--bundle-id B]");
                return 2;
            }
            let body = serde_json::json!({
                "group": group.unwrap(),
                "name": name.unwrap(),
                "bundle_id": bundle,
            });
            let (status, out) = match api(
                &client,
                "PUT",
                &format!("{base}/projects/{slug}"),
                Some(body),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                println!("set project {slug}");
            }
            0
        }
        "icon" => {
            let mut slug = String::new();
            let mut file: Option<String> = None;
            let mut out_path: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--file" => {
                        file = Some(match need(rest, &mut i, "projects icon", "--file") {
                            Ok(v) => v,
                            Err(c) => return c,
                        });
                    }
                    "--out" => {
                        out_path = Some(match need(rest, &mut i, "projects icon", "--out") {
                            Ok(v) => v,
                            Err(c) => return c,
                        });
                    }
                    x if x.starts_with("--") => {
                        eprintln!("est-hub projects icon: unexpected {x:?}");
                        return 2;
                    }
                    n if slug.is_empty() => slug = n.to_string(),
                    n => {
                        eprintln!("est-hub projects icon: unexpected {n:?}");
                        return 2;
                    }
                }
                i += 1;
            }
            if slug.is_empty() || file.is_some() == out_path.is_some() {
                eprintln!("est-hub projects icon: SLUG --file P | --out P");
                return 2;
            }
            if let Some(path) = file {
                let bytes = match std::fs::read(&path) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("est-hub projects icon: cannot read {path}: {e}");
                        return 1;
                    }
                };
                let res = client
                    .put(format!("{base}/projects/{slug}/icon"))
                    .header("content-type", "image/png")
                    .body(bytes)
                    .send()
                    .await;
                let res = match res {
                    Ok(r) => r,
                    Err(e) => return fail(json, &format!("no hub at {base} ({e})")),
                };
                let status = res.status().as_u16();
                let out = res.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return fail(json, &api_error(&out, status));
                }
                if json {
                    println!("{}", out.trim());
                } else {
                    println!("icon set {slug}");
                }
                return 0;
            }
            let path = out_path.unwrap();
            let (status, body) = match api(
                &client,
                "GET",
                &format!("{base}/projects/{slug}/icon"),
                None,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&body, status));
            }
            let b64 = value(&body)
                .pointer("/icon")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let bytes = match base64::engine::general_purpose::STANDARD.decode(&b64) {
                Ok(b) => b,
                Err(e) => return fail(json, &format!("icon is not base64: {e}")),
            };
            if let Err(e) = std::fs::write(&path, &bytes) {
                eprintln!("est-hub projects icon: cannot write {path}: {e}");
                return 1;
            }
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "v": 1, "path": path, "bytes": bytes.len()})
                );
            } else {
                println!("wrote {} bytes to {path}", bytes.len());
            }
            0
        }
        _ => {
            eprintln!("est-hub projects: list, show, set, icon (try: help)");
            2
        }
    }
}

// ---------------------------------------------------------------- results

async fn cmd_results_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "results") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    match verb {
        "report" => {
            let mut check: Option<String> = None;
            let mut ok_flag: Option<bool> = None;
            let mut code: Option<u16> = None;
            let mut reason: Option<String> = None;
            let mut num: Option<serde_json::Value> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--check" => match need(rest, &mut i, "results report", "--check") {
                        Ok(v) => check = Some(v),
                        Err(c) => return c,
                    },
                    "--ok" => ok_flag = Some(true),
                    "--fail" => ok_flag = Some(false),
                    "--code" => match need(rest, &mut i, "results report", "--code") {
                        Ok(v) => match v.parse::<u16>() {
                            Ok(n) => code = Some(n),
                            Err(_) => {
                                eprintln!("est-hub results report: --code needs 100-599");
                                return 2;
                            }
                        },
                        Err(c) => return c,
                    },
                    "--reason" => match need(rest, &mut i, "results report", "--reason") {
                        Ok(v) => reason = Some(v),
                        Err(c) => return c,
                    },
                    "--value" => match need(rest, &mut i, "results report", "--value") {
                        Ok(v) => match v.parse::<f64>() {
                            Ok(n) if n.is_finite() => {
                                num = Some(serde_json::Value::from(n));
                            }
                            _ => {
                                eprintln!("est-hub results report: --value needs a finite number");
                                return 2;
                            }
                        },
                        Err(c) => return c,
                    },
                    x => {
                        eprintln!("est-hub results report: unexpected {x:?}");
                        return 2;
                    }
                }
                i += 1;
            }
            let (Some(check), Some(ok_flag)) = (check, ok_flag) else {
                eprintln!("est-hub results report: --check NAME and --ok|--fail");
                return 2;
            };
            let (status, out) = match api(
                &client,
                "POST",
                &format!("{base}/results"),
                Some(serde_json::json!({"check": check, "ok": ok_flag, "code": code, "reason": reason, "value": num})),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                let flipped = value(&out)
                    .pointer("/flipped")
                    .and_then(|f| f.as_bool())
                    .unwrap_or(false);
                println!(
                    "recorded {check} {} ({})",
                    if ok_flag { "ok" } else { "fail" },
                    if flipped { "flipped" } else { "steady" }
                );
            }
            0
        }
        "list" => {
            let mut check: Option<String> = None;
            let mut limit: Option<String> = None;
            let mut since: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--check" => match need(rest, &mut i, "results list", "--check") {
                        Ok(v) => check = Some(v),
                        Err(c) => return c,
                    },
                    "--limit" => match need(rest, &mut i, "results list", "--limit") {
                        Ok(v) => limit = Some(v),
                        Err(c) => return c,
                    },
                    "--since" => match need(rest, &mut i, "results list", "--since") {
                        Ok(v) => since = Some(v),
                        Err(c) => return c,
                    },
                    x => {
                        eprintln!("est-hub results list: unexpected {x:?}");
                        return 2;
                    }
                }
                i += 1;
            }
            let Some(check) = check else {
                eprintln!("est-hub results list: --check NAME");
                return 2;
            };
            if let Some(l) = limit.as_deref()
                && l.parse::<u64>().is_err()
            {
                eprintln!("est-hub results list: --limit needs a number");
                return 2;
            }
            if let Some(s) = since.as_deref()
                && s.parse::<u64>().is_err()
            {
                eprintln!("est-hub results list: --since needs unix seconds");
                return 2;
            }
            let mut url = format!("{base}/checks/{check}/results");
            let mut sep = '?';
            for (key, val) in [("limit", &limit), ("since", &since)] {
                if let Some(v) = val {
                    url.push(sep);
                    sep = '&';
                    url.push_str(&format!("{key}={v}"));
                }
            }
            let (status, out) = match api(&client, "GET", &url, None).await {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
                return 0;
            }
            let v = value(&out);
            let list = v.pointer("/results").and_then(|r| r.as_array());
            if list.is_none_or(|l| l.is_empty()) {
                println!("no results for {check}");
                return 0;
            }
            for r in list.unwrap() {
                let ok_mark = if r.get("ok").and_then(|o| o.as_bool()).unwrap_or(false) {
                    "ok"
                } else {
                    "FAIL"
                };
                let ts = r.get("ts").and_then(|t| t.as_u64()).unwrap_or(0);
                let code = r
                    .get("code")
                    .and_then(|c| c.as_u64())
                    .map(|c| c.to_string())
                    .unwrap_or("-".to_string());
                let reason = r.get("reason").and_then(|x| x.as_str()).unwrap_or("");
                println!("{ts} {ok_mark} {code} {reason}");
            }
            0
        }
        _ => {
            eprintln!("est-hub results: report, list (try: help)");
            2
        }
    }
}

// ---------------------------------------------------------------- heartbeats

async fn cmd_heartbeats_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "heartbeats") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    if verb != "beat" {
        eprintln!("est-hub heartbeats: beat (try: help)");
        return 2;
    }
    let mut check: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--check" => match need(rest, &mut i, "heartbeats beat", "--check") {
                Ok(v) => check = Some(v),
                Err(c) => return c,
            },
            x => {
                eprintln!("est-hub heartbeats beat: unexpected {x:?}");
                return 2;
            }
        }
        i += 1;
    }
    let Some(check) = check else {
        eprintln!("est-hub heartbeats beat: --check NAME");
        return 2;
    };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    let (status, out) = match api(
        &client,
        "POST",
        &format!("{base}/heartbeats"),
        Some(serde_json::json!({"check": check})),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return fail(json, &e),
    };
    if !(200..300).contains(&status) {
        return fail(json, &api_error(&out, status));
    }
    if json {
        println!("{}", out.trim());
    } else {
        println!("beat {check}");
    }
    0
}

// ---------------------------------------------------------------- approvals

async fn cmd_approvals_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "approvals") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    match verb {
        "request" => {
            let mut title: Option<String> = None;
            let mut body: Option<String> = None;
            let mut reply_to: Option<String> = None;
            let mut ttl: Option<u64> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--title" => match need(rest, &mut i, "approvals request", "--title") {
                        Ok(v) => title = Some(v),
                        Err(c) => return c,
                    },
                    "--body" => match need(rest, &mut i, "approvals request", "--body") {
                        Ok(v) => body = Some(v),
                        Err(c) => return c,
                    },
                    "--reply-to" => match need(rest, &mut i, "approvals request", "--reply-to") {
                        Ok(v) => reply_to = Some(v),
                        Err(c) => return c,
                    },
                    "--ttl" => match need(rest, &mut i, "approvals request", "--ttl") {
                        Ok(v) => match v.parse::<u64>() {
                            Ok(n) => ttl = Some(n),
                            Err(_) => {
                                eprintln!("est-hub approvals request: --ttl needs seconds");
                                return 2;
                            }
                        },
                        Err(c) => return c,
                    },
                    x => {
                        eprintln!("est-hub approvals request: unexpected {x:?}");
                        return 2;
                    }
                }
                i += 1;
            }
            let Some(title) = title else {
                eprintln!("est-hub approvals request: --title T");
                return 2;
            };
            let (status, out) = match api(
                &client,
                "POST",
                &format!("{base}/approvals"),
                Some(serde_json::json!({"title": title, "body": body, "reply_to": reply_to, "ttl_secs": ttl})),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                let id = value(&out)
                    .pointer("/approval/id")
                    .and_then(|x| x.as_i64())
                    .unwrap_or(0);
                println!("approval #{id} pending");
            }
            0
        }
        "list" => {
            let mut state: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--state" => match need(rest, &mut i, "approvals list", "--state") {
                        Ok(v) => state = Some(v),
                        Err(c) => return c,
                    },
                    x => {
                        eprintln!("est-hub approvals list: unexpected {x:?}");
                        return 2;
                    }
                }
                i += 1;
            }
            let url = match state {
                Some(s) => format!("{base}/approvals?state={s}"),
                None => format!("{base}/approvals"),
            };
            let (status, out) = match api(&client, "GET", &url, None).await {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
                return 0;
            }
            let v = value(&out);
            let list = v.pointer("/approvals").and_then(|a| a.as_array());
            if list.is_none_or(|l| l.is_empty()) {
                println!("no approvals");
                return 0;
            }
            for a in list.unwrap() {
                let id = a.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
                let st = a.get("state").and_then(|x| x.as_str()).unwrap_or("?");
                let title = a.get("title").and_then(|x| x.as_str()).unwrap_or("?");
                println!("#{id} {st} {title}");
            }
            0
        }
        "show" => {
            if rest.len() != 1 || rest[0].parse::<i64>().is_err() {
                eprintln!("est-hub approvals show: ID");
                return 2;
            }
            let (status, out) = match api(
                &client,
                "GET",
                &format!("{}/approvals/{}", base, rest[0]),
                None,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
                return 0;
            }
            let v = value(&out);
            let id = v
                .pointer("/approval/id")
                .and_then(|x| x.as_i64())
                .unwrap_or(0);
            println!("approval #{id}");
            println!("state: {}", str_field(&v, "/approval/state"));
            println!("title: {}", str_field(&v, "/approval/title"));
            let body = v
                .pointer("/approval/body")
                .and_then(|b| b.as_str())
                .unwrap_or("");
            if !body.is_empty() {
                println!("body:  {body}");
            }
            0
        }
        "decide" => {
            let mut id = "";
            let mut approve: Option<bool> = None;
            let mut by: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--approve" => approve = Some(true),
                    "--reject" => approve = Some(false),
                    "--by" => match need(rest, &mut i, "approvals decide", "--by") {
                        Ok(v) => by = Some(v),
                        Err(c) => return c,
                    },
                    x if x.starts_with("--") => {
                        eprintln!("est-hub approvals decide: unexpected {x:?}");
                        return 2;
                    }
                    n if id.is_empty() => id = n,
                    n => {
                        eprintln!("est-hub approvals decide: unexpected {n:?}");
                        return 2;
                    }
                }
                i += 1;
            }
            if id.parse::<i64>().is_err() {
                eprintln!("est-hub approvals decide: ID --approve|--reject");
                return 2;
            }
            let Some(approve) = approve else {
                eprintln!("est-hub approvals decide: ID --approve|--reject");
                return 2;
            };
            let (status, out) = match api(
                &client,
                "POST",
                &format!("{base}/approvals/{id}/decision"),
                Some(serde_json::json!({"approve": approve, "by": by})),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                println!(
                    "approval #{id} {}",
                    if approve { "approved" } else { "rejected" }
                );
            }
            0
        }
        _ => {
            eprintln!("est-hub approvals: request, list, show, decide (try: help)");
            2
        }
    }
}

// ---------------------------------------------------------------- notify

async fn cmd_notify_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "notify") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    match verb {
        "send" => cmd_notify_send(&base, &client, rest, json).await,
        "test" => cmd_notify_test(&base, &client, rest, json).await,
        "alive" => cmd_notify_alive(&base, &client, rest, json).await,
        _ => {
            eprintln!("est-hub notify: send, test, alive (try: help)");
            2
        }
    }
}

async fn cmd_notify_alive(
    base: &str,
    client: &reqwest::Client,
    rest: &[String],
    json: bool,
) -> i32 {
    if !rest.is_empty() {
        eprintln!("est-hub notify alive: no arguments");
        return 2;
    }
    let (status, out) = match api(
        client,
        "POST",
        &format!("{base}/notify/alive"),
        Some(serde_json::json!({})),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return fail(json, &e),
    };
    if !(200..300).contains(&status) {
        return fail(json, &api_error(&out, status));
    }
    if json {
        println!("{}", out.trim());
        return 0;
    }
    let v = value(&out);
    let results = v.pointer("/results").and_then(|r| r.as_array());
    if results.is_none_or(|r| r.is_empty()) {
        println!("alive: no tokened devices");
        return 0;
    }
    for r in results.unwrap() {
        let device = r.pointer("/device").and_then(|d| d.as_str()).unwrap_or("?");
        if let Some(id) = r.pointer("/apns_id").and_then(|a| a.as_str()) {
            println!("{device}: sent {id}");
        } else {
            let why = r.pointer("/error").and_then(|e| e.as_str()).unwrap_or("?");
            println!("{device}: {why}");
        }
    }
    0
}

async fn cmd_notify_send(base: &str, client: &reqwest::Client, rest: &[String], json: bool) -> i32 {
    let mut title: Option<String> = None;
    let mut body: Option<String> = None;
    let mut topic: Option<String> = None;
    let mut to: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--title" => match need(rest, &mut i, "notify send", "--title") {
                Ok(v) => title = Some(v),
                Err(c) => return c,
            },
            "--body" => match need(rest, &mut i, "notify send", "--body") {
                Ok(v) => body = Some(v),
                Err(c) => return c,
            },
            "--topic" => match need(rest, &mut i, "notify send", "--topic") {
                Ok(v) => topic = Some(v),
                Err(c) => return c,
            },
            "--to" => match need(rest, &mut i, "notify send", "--to") {
                Ok(v) => to = Some(v),
                Err(c) => return c,
            },
            x => {
                eprintln!("est-hub notify send: unexpected {x:?}");
                return 2;
            }
        }
        i += 1;
    }
    let Some(title) = title else {
        eprintln!("est-hub notify send: --title T");
        return 2;
    };
    let (status, out) = match api(
        client,
        "POST",
        &format!("{base}/notify"),
        Some(serde_json::json!({"title": title, "body": body, "topic": topic, "to": to})),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return fail(json, &e),
    };
    if !(200..300).contains(&status) {
        return fail(json, &api_error(&out, status));
    }
    if json {
        println!("{}", out.trim());
    } else {
        let id = value(&out)
            .pointer("/notification/id")
            .and_then(|x| x.as_i64())
            .unwrap_or(0);
        println!("notified #{id}");
    }
    0
}

/// Direct push, no queue: one device, now. Prints per-device `sent
/// <apns-id>` or the hub's refusal.
async fn cmd_notify_test(base: &str, client: &reqwest::Client, rest: &[String], json: bool) -> i32 {
    let mut to: Option<String> = None;
    let mut title: Option<String> = None;
    let mut body: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--to" => match need(rest, &mut i, "notify test", "--to") {
                Ok(v) => to = Some(v),
                Err(c) => return c,
            },
            "--title" => match need(rest, &mut i, "notify test", "--title") {
                Ok(v) => title = Some(v),
                Err(c) => return c,
            },
            "--body" => match need(rest, &mut i, "notify test", "--body") {
                Ok(v) => body = Some(v),
                Err(c) => return c,
            },
            x => {
                eprintln!("est-hub notify test: unexpected {x:?}");
                return 2;
            }
        }
        i += 1;
    }
    let Some(to) = to else {
        eprintln!("est-hub notify test: --to DEV");
        return 2;
    };
    let (status, out) = match api(
        client,
        "POST",
        &format!("{base}/notify/test"),
        Some(serde_json::json!({"to": to, "title": title, "body": body})),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return fail(json, &e),
    };
    if !(200..300).contains(&status) {
        return fail(json, &api_error(&out, status));
    }
    if json {
        println!("{}", out.trim());
        return 0;
    }
    let v = value(&out);
    let results = v.pointer("/results").and_then(|r| r.as_array());
    if results.is_none_or(|l| l.is_empty()) {
        println!("no devices have apns tokens");
        return 0;
    }
    for r in results.unwrap() {
        let device = r.get("device").and_then(|d| d.as_str()).unwrap_or("?");
        let env = r.get("env").and_then(|e| e.as_str()).unwrap_or("?");
        if let Some(id) = r.get("apns_id").and_then(|a| a.as_str()) {
            println!("{device} [{env}]: sent {id}");
        } else {
            let why = r.get("error").and_then(|e| e.as_str()).unwrap_or("?");
            println!("{device} [{env}]: {why}");
        }
    }
    0
}

async fn cmd_notifications_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "notifications") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    if verb != "list" {
        eprintln!("est-hub notifications: list (try: help)");
        return 2;
    }
    let mut limit: Option<String> = None;
    let mut to: Option<String> = None;
    let mut since: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--limit" => match need(rest, &mut i, "notifications list", "--limit") {
                Ok(v) => limit = Some(v),
                Err(c) => return c,
            },
            "--to" => match need(rest, &mut i, "notifications list", "--to") {
                Ok(v) => to = Some(v),
                Err(c) => return c,
            },
            "--since" => match need(rest, &mut i, "notifications list", "--since") {
                Ok(v) => since = Some(v),
                Err(c) => return c,
            },
            x => {
                eprintln!("est-hub notifications list: unexpected {x:?}");
                return 2;
            }
        }
        i += 1;
    }
    if let Some(l) = limit.as_deref()
        && l.parse::<u64>().is_err()
    {
        eprintln!("est-hub notifications list: --limit needs a number");
        return 2;
    }
    if let Some(s) = since.as_deref()
        && s.parse::<i64>().is_err()
    {
        eprintln!("est-hub notifications list: --since needs a notification id");
        return 2;
    }
    // Device names match [a-z0-9_-]: no URL encoding needed.
    let mut query = Vec::new();
    if let Some(l) = limit {
        query.push(format!("limit={l}"));
    }
    if let Some(t) = to {
        query.push(format!("to={t}"));
    }
    if let Some(s) = since {
        query.push(format!("since_id={s}"));
    }
    let url = if query.is_empty() {
        format!("{base}/notifications")
    } else {
        format!("{base}/notifications?{}", query.join("&"))
    };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    let (status, out) = match api(&client, "GET", &url, None).await {
        Ok(r) => r,
        Err(e) => return fail(json, &e),
    };
    if !(200..300).contains(&status) {
        return fail(json, &api_error(&out, status));
    }
    if json {
        println!("{}", out.trim());
        return 0;
    }
    let v = value(&out);
    let list = v.pointer("/notifications").and_then(|n| n.as_array());
    if list.is_none_or(|l| l.is_empty()) {
        println!("no notifications");
        return 0;
    }
    for n in list.unwrap() {
        let id = n.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
        let topic = n.get("topic").and_then(|x| x.as_str()).unwrap_or("?");
        let title = n.get("title").and_then(|x| x.as_str()).unwrap_or("?");
        println!("#{id} {topic} {title}");
    }
    0
}

// ---------------------------------------------------------------- apns

/// Write the APNs sender ids (`PUT /apns`' twin). Absent flags stay
/// absent — the route keeps what it has.
async fn cmd_apns_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "apns") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    match verb {
        "show" => {
            if !rest.is_empty() {
                eprintln!("est-hub apns show: no arguments");
                return 2;
            }
            let (status, out) = match api(&client, "GET", &format!("{base}/apns"), None).await {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
                return 0;
            }
            let v = value(&out);
            let on = v
                .pointer("/apns/configured")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            let topic = v
                .pointer("/apns/topic")
                .and_then(|x| x.as_str())
                .unwrap_or("-");
            println!("pushes:  {}", if on { "on" } else { "off" });
            println!("topic:   {topic}");
            0
        }
        "set" => {
            let mut key_id: Option<String> = None;
            let mut team_id: Option<String> = None;
            let mut topic: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--key-id" => match need(rest, &mut i, "apns set", "--key-id") {
                        Ok(v) => key_id = Some(v),
                        Err(c) => return c,
                    },
                    "--team-id" => match need(rest, &mut i, "apns set", "--team-id") {
                        Ok(v) => team_id = Some(v),
                        Err(c) => return c,
                    },
                    "--topic" => match need(rest, &mut i, "apns set", "--topic") {
                        Ok(v) => topic = Some(v),
                        Err(c) => return c,
                    },
                    x => {
                        eprintln!("est-hub apns set: unexpected {x:?}");
                        return 2;
                    }
                }
                i += 1;
            }
            let mut fields = serde_json::Map::new();
            if let Some(v) = key_id {
                fields.insert("key_id".to_string(), v.into());
            }
            if let Some(v) = team_id {
                fields.insert("team_id".to_string(), v.into());
            }
            if let Some(v) = topic {
                fields.insert("topic".to_string(), v.into());
            }
            let (status, out) = match api(
                &client,
                "PUT",
                &format!("{base}/apns"),
                Some(serde_json::Value::Object(fields)),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
                return 0;
            }
            let v = value(&out);
            let show = |ptr: &str| v.pointer(ptr).and_then(|x| x.as_str()).unwrap_or("-");
            println!("key_id:  {}", show("/apns/key_id"));
            println!("team_id: {}", show("/apns/team_id"));
            println!("topic:   {}", show("/apns/topic"));
            0
        }
        _ => {
            eprintln!("est-hub apns: show, set (try: help)");
            2
        }
    }
}

// ---------------------------------------------------------------- live

/// Direct Live Activity push, no feed (`POST /live-activities/test`'s
/// twin): a canned card to one device, now. Prints `sent <apns-id>` or
/// the hub's refusal, like `notify test`.
async fn cmd_live_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "live") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    if verb != "test" {
        eprintln!("est-hub live: test (try: help)");
        return 2;
    }
    let mut to: Option<String> = None;
    let mut event: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--to" => match need(rest, &mut i, "live test", "--to") {
                Ok(v) => to = Some(v),
                Err(c) => return c,
            },
            "--event" => match need(rest, &mut i, "live test", "--event") {
                Ok(v) => event = Some(v),
                Err(c) => return c,
            },
            x => {
                eprintln!("est-hub live test: unexpected {x:?}");
                return 2;
            }
        }
        i += 1;
    }
    let (Some(to), Some(event)) = (to, event) else {
        eprintln!("est-hub live test: --to DEV --event update|end|start");
        return 2;
    };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    let (status, out) = match api(
        &client,
        "POST",
        &format!("{base}/live-activities/test"),
        Some(serde_json::json!({"to": to, "event": event})),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return fail(json, &e),
    };
    if !(200..300).contains(&status) {
        return fail(json, &api_error(&out, status));
    }
    if json {
        println!("{}", out.trim());
        return 0;
    }
    let v = value(&out);
    let device = str_field(&v, "/device");
    let env = v.pointer("/env").and_then(|e| e.as_str()).unwrap_or("?");
    if let Some(id) = v.pointer("/apns_id").and_then(|a| a.as_str()) {
        println!("{device} [{env}]: sent {id}");
    } else {
        let why = v.pointer("/error").and_then(|e| e.as_str()).unwrap_or("?");
        println!("{device} [{env}]: {why}");
    }
    0
}

// ---------------------------------------------------------------- secrets

async fn cmd_secrets_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "secrets") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    match verb {
        "list" => {
            if !rest.is_empty() {
                eprintln!("est-hub secrets list: no arguments");
                return 2;
            }
            let (status, out) = match api(&client, "GET", &format!("{base}/secrets"), None).await {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
                return 0;
            }
            let v = value(&out);
            let list = v.pointer("/secrets").and_then(|s| s.as_array());
            if list.is_none_or(|l| l.is_empty()) {
                println!("no secrets");
                return 0;
            }
            for s in list.unwrap() {
                let g = |p: &str| s.pointer(p).and_then(|x| x.as_str()).unwrap_or("?");
                let token = s
                    .pointer("/has_token")
                    .and_then(|t| t.as_bool())
                    .unwrap_or(false);
                println!(
                    "{} {} {}",
                    g("/project"),
                    g("/sha").chars().take(12).collect::<String>(),
                    if token { "token" } else { "-" }
                );
            }
            0
        }
        "push" => {
            let mut project = "";
            let mut file: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--file" => match need(rest, &mut i, "secrets push", "--file") {
                        Ok(v) => file = Some(v),
                        Err(c) => return c,
                    },
                    f if f.starts_with("--") => {
                        eprintln!("est-hub secrets push: PROJECT --file PATH");
                        return 2;
                    }
                    n if project.is_empty() => project = n,
                    _ => {
                        eprintln!("est-hub secrets push: PROJECT --file PATH");
                        return 2;
                    }
                }
                i += 1;
            }
            let Some(file) = file else {
                eprintln!("est-hub secrets push: PROJECT --file PATH");
                return 2;
            };
            if project.is_empty() {
                eprintln!("est-hub secrets push: PROJECT --file PATH");
                return 2;
            }
            // The env rides a file, never argv: process lists leak.
            let env = match std::fs::read_to_string(&file) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("est-hub secrets push: cannot read {file}: {e}");
                    return 1;
                }
            };
            let (status, out) = match api(
                &client,
                "PUT",
                &format!("{base}/secrets/{project}"),
                Some(serde_json::json!({"env": env})),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                println!("pushed secret {project}");
            }
            0
        }
        "pull" => {
            let mut project = "";
            let mut token: Option<String> = None;
            let mut out: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--token" => match need(rest, &mut i, "secrets pull", "--token") {
                        Ok(v) => token = Some(v),
                        Err(c) => return c,
                    },
                    "--out" => match need(rest, &mut i, "secrets pull", "--out") {
                        Ok(v) => out = Some(v),
                        Err(c) => return c,
                    },
                    f if f.starts_with("--") => {
                        eprintln!("est-hub secrets pull: PROJECT --token T --out PATH");
                        return 2;
                    }
                    n if project.is_empty() => project = n,
                    _ => {
                        eprintln!("est-hub secrets pull: PROJECT --token T --out PATH");
                        return 2;
                    }
                }
                i += 1;
            }
            let (Some(token), Some(out)) = (token, out) else {
                eprintln!("est-hub secrets pull: PROJECT --token T --out PATH");
                return 2;
            };
            if project.is_empty() {
                eprintln!("est-hub secrets pull: PROJECT --token T --out PATH");
                return 2;
            }
            let (status, body) = match api_bearer(
                &client,
                "GET",
                &format!("{base}/secrets/{project}"),
                &token,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&body, status));
            }
            let v = value(&body);
            let Some(env) = v.pointer("/env").and_then(|e| e.as_str()) else {
                return fail(json, "the hub answered without an env");
            };
            // 0600 or nothing: a pulled env must never land world-readable.
            if let Err(e) = std::fs::write(&out, env) {
                eprintln!("est-hub secrets pull: cannot write {out}: {e}");
                return 1;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600));
            }
            if json {
                // One object: the blob went to the file, so the envelope
                // carries identity only (never the env on stdout).
                let sha = v.pointer("/sha").and_then(|s| s.as_str()).unwrap_or("");
                println!(
                    "{}",
                    cli::ok(&format!(
                        "\"project\":{},\"sha\":{},\"out\":{}",
                        serde_json::json!(project),
                        serde_json::json!(sha),
                        serde_json::json!(out)
                    ))
                );
            } else {
                println!("pulled secret {project} to {out}");
            }
            0
        }
        "token" => {
            if rest.len() != 1 {
                eprintln!("est-hub secrets token: PROJECT");
                return 2;
            }
            let (status, out) = match api(
                &client,
                "POST",
                &format!("{}/secrets/{}/token", base, rest[0]),
                Some(serde_json::json!({})),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
                return 0;
            }
            // The one and only showing: print it bare for capture.
            println!("{}", str_field(&value(&out), "/token"));
            0
        }
        "revoke" => {
            if rest.len() != 1 {
                eprintln!("est-hub secrets revoke: PROJECT");
                return 2;
            }
            let (status, out) = match api(
                &client,
                "DELETE",
                &format!("{}/secrets/{}/token", base, rest[0]),
                None,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                println!("revoked secret token {}", rest[0]);
            }
            0
        }
        "delete" => {
            let mut project = "";
            let mut yes = false;
            for a in rest {
                if a == "--yes" {
                    yes = true;
                } else if !a.starts_with("--") && project.is_empty() {
                    project = a;
                } else {
                    eprintln!("est-hub secrets delete: PROJECT --yes");
                    return 2;
                }
            }
            if project.is_empty() {
                eprintln!("est-hub secrets delete: PROJECT --yes");
                return 2;
            }
            if !confirm(&format!("delete secret {project}"), yes) {
                return 1;
            }
            let (status, out) = match api(
                &client,
                "DELETE",
                &format!("{base}/secrets/{project}"),
                None,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                println!("deleted secret {project}");
            }
            0
        }
        _ => {
            eprintln!("est-hub secrets: list, push, pull, token, revoke, delete (try: help)");
            2
        }
    }
}

// ---------------------------------------------------------------- balances

async fn cmd_balances_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "balances") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    match verb {
        "list" => {
            if !rest.is_empty() {
                eprintln!("est-hub balances list: no arguments");
                return 2;
            }
            let (status, out) = match api(&client, "GET", &format!("{base}/balances"), None).await {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
                return 0;
            }
            let v = value(&out);
            let list = v.pointer("/balances").and_then(|b| b.as_array());
            if list.is_none_or(|l| l.is_empty()) {
                println!("no balances");
                return 0;
            }
            for b in list.unwrap() {
                let g = |p: &str| b.pointer(p).and_then(|x| x.as_str()).unwrap_or("");
                let updated = b
                    .pointer("/updated_ts")
                    .and_then(|u| u.as_u64())
                    .map(seen_words)
                    .unwrap_or("-".to_string());
                println!(
                    "{} {} {} ({})",
                    g("/label"),
                    g("/amount"),
                    g("/currency"),
                    updated
                );
            }
            0
        }
        "set" => {
            let mut provider = "";
            let mut label: Option<String> = None;
            let mut amount: Option<String> = None;
            let mut currency: Option<String> = None;
            let mut note: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--label" => match need(rest, &mut i, "balances set", "--label") {
                        Ok(v) => label = Some(v),
                        Err(c) => return c,
                    },
                    "--amount" => match need(rest, &mut i, "balances set", "--amount") {
                        Ok(v) => amount = Some(v),
                        Err(c) => return c,
                    },
                    "--currency" => match need(rest, &mut i, "balances set", "--currency") {
                        Ok(v) => currency = Some(v),
                        Err(c) => return c,
                    },
                    "--note" => match need(rest, &mut i, "balances set", "--note") {
                        Ok(v) => note = Some(v),
                        Err(c) => return c,
                    },
                    f if f.starts_with("--") => {
                        eprintln!(
                            "est-hub balances set: PROVIDER --amount X [--label L] [--currency C] [--note N]"
                        );
                        return 2;
                    }
                    n if provider.is_empty() => provider = n,
                    _ => {
                        eprintln!(
                            "est-hub balances set: PROVIDER --amount X [--label L] [--currency C] [--note N]"
                        );
                        return 2;
                    }
                }
                i += 1;
            }
            if provider.is_empty() || amount.is_none() {
                eprintln!(
                    "est-hub balances set: PROVIDER --amount X [--label L] [--currency C] [--note N]"
                );
                return 2;
            }
            let mut fields = serde_json::Map::new();
            fields.insert("amount".to_string(), serde_json::json!(amount.unwrap()));
            if let Some(label) = label {
                fields.insert("label".to_string(), serde_json::json!(label));
            }
            if let Some(currency) = currency {
                fields.insert("currency".to_string(), serde_json::json!(currency));
            }
            if let Some(note) = note {
                fields.insert("note".to_string(), serde_json::json!(note));
            }
            let (status, out) = match api(
                &client,
                "PUT",
                &format!("{base}/balances/{provider}"),
                Some(serde_json::Value::Object(fields)),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                println!("set balance {provider}");
            }
            0
        }
        "delete" => {
            let mut provider = "";
            let mut yes = false;
            for a in rest {
                if a == "--yes" {
                    yes = true;
                } else if !a.starts_with("--") && provider.is_empty() {
                    provider = a;
                } else {
                    eprintln!("est-hub balances delete: PROVIDER --yes");
                    return 2;
                }
            }
            if provider.is_empty() {
                eprintln!("est-hub balances delete: PROVIDER --yes");
                return 2;
            }
            if !confirm(&format!("delete balance {provider}"), yes) {
                return 1;
            }
            let (status, out) = match api(
                &client,
                "DELETE",
                &format!("{base}/balances/{provider}"),
                None,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                println!("deleted balance {provider}");
            }
            0
        }
        _ => {
            eprintln!("est-hub balances: list, set, delete (try: help)");
            2
        }
    }
}

// ---------------------------------------------------------------- agents

async fn cmd_agents_async(args: &[String], json: bool) -> i32 {
    let (base, args) = match split_hub(args, "agents") {
        Ok(r) => r,
        Err(c) => return c,
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    match verb {
        "list" => {
            if !rest.is_empty() {
                eprintln!("est-hub agents list: no arguments");
                return 2;
            }
            let (status, out) = match api(&client, "GET", &format!("{base}/agents"), None).await {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
                return 0;
            }
            let v = value(&out);
            let list = v.pointer("/agents").and_then(|b| b.as_array());
            if list.is_none_or(|l| l.is_empty()) {
                println!("no agents");
                return 0;
            }
            for a in list.unwrap() {
                let g = |p: &str| a.pointer(p).and_then(|x| x.as_str()).unwrap_or("");
                let stale = a
                    .pointer("/stale")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
                let updated = a
                    .pointer("/updated_ts")
                    .and_then(|u| u.as_u64())
                    .map(seen_words)
                    .unwrap_or("-".to_string());
                println!(
                    "{} {} {}{} ({})",
                    g("/pane"),
                    g("/status"),
                    g("/title"),
                    if stale { " STALE" } else { "" },
                    updated
                );
            }
            0
        }
        "show" => {
            if rest.len() != 1 {
                eprintln!("est-hub agents show: PANE");
                return 2;
            }
            let (status, out) =
                match api(&client, "GET", &format!("{base}/agents/{}", rest[0]), None).await {
                    Ok(r) => r,
                    Err(e) => return fail(json, &e),
                };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
                return 0;
            }
            let v = value(&out);
            let g = |p: &str| v.pointer(p).and_then(|x| x.as_str()).unwrap_or("");
            println!("pane: {}", g("/agent/pane"));
            println!("status: {}", g("/agent/status"));
            println!("title: {}", g("/agent/title"));
            println!("cwd: {}", g("/agent/cwd"));
            println!("space: {}", g("/agent/space"));
            println!("tab: {}", g("/agent/tab"));
            let updated = v
                .pointer("/agent/updated_ts")
                .and_then(|u| u.as_u64())
                .map(seen_words)
                .unwrap_or("-".to_string());
            let stale = v
                .pointer("/agent/stale")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            println!("updated: {updated}{}", if stale { " STALE" } else { "" });
            let since = v
                .pointer("/agent/status_since_ts")
                .and_then(|u| u.as_u64())
                .map(seen_words)
                .unwrap_or("-".to_string());
            println!("in status: {since}");
            let output = g("/agent/output");
            if !output.is_empty() {
                println!("output:\n{output}");
            }
            0
        }
        "push" => {
            let mut pane = "";
            let mut status: Option<String> = None;
            let mut title: Option<String> = None;
            let mut cwd: Option<String> = None;
            let mut space: Option<String> = None;
            let mut tab: Option<String> = None;
            let mut output: Option<String> = None;
            let usage = "est-hub agents push: PANE --status S [--title T] [--cwd C] [--space S] [--tab T] [--output O]";
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--status" => match need(rest, &mut i, "agents push", "--status") {
                        Ok(v) => status = Some(v),
                        Err(c) => return c,
                    },
                    "--title" => match need(rest, &mut i, "agents push", "--title") {
                        Ok(v) => title = Some(v),
                        Err(c) => return c,
                    },
                    "--cwd" => match need(rest, &mut i, "agents push", "--cwd") {
                        Ok(v) => cwd = Some(v),
                        Err(c) => return c,
                    },
                    "--space" => match need(rest, &mut i, "agents push", "--space") {
                        Ok(v) => space = Some(v),
                        Err(c) => return c,
                    },
                    "--tab" => match need(rest, &mut i, "agents push", "--tab") {
                        Ok(v) => tab = Some(v),
                        Err(c) => return c,
                    },
                    "--output" => match need(rest, &mut i, "agents push", "--output") {
                        Ok(v) => output = Some(v),
                        Err(c) => return c,
                    },
                    f if f.starts_with("--") => {
                        eprintln!("{usage}");
                        return 2;
                    }
                    n if pane.is_empty() => pane = n,
                    _ => {
                        eprintln!("{usage}");
                        return 2;
                    }
                }
                i += 1;
            }
            if pane.is_empty() || status.is_none() {
                eprintln!("{usage}");
                return 2;
            }
            let mut fields = serde_json::Map::new();
            fields.insert("status".to_string(), serde_json::json!(status.unwrap()));
            if let Some(title) = title {
                fields.insert("title".to_string(), serde_json::json!(title));
            }
            if let Some(cwd) = cwd {
                fields.insert("cwd".to_string(), serde_json::json!(cwd));
            }
            if let Some(space) = space {
                fields.insert("space".to_string(), serde_json::json!(space));
            }
            if let Some(tab) = tab {
                fields.insert("tab".to_string(), serde_json::json!(tab));
            }
            if let Some(output) = output {
                fields.insert("output".to_string(), serde_json::json!(output));
            }
            let (status, out) = match api(
                &client,
                "PUT",
                &format!("{base}/agents/{pane}"),
                Some(serde_json::Value::Object(fields)),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => return fail(json, &e),
            };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                println!("pushed agent {pane}");
            }
            0
        }
        "delete" => {
            let mut pane = "";
            let mut yes = false;
            for a in rest {
                if a == "--yes" {
                    yes = true;
                } else if !a.starts_with("--") && pane.is_empty() {
                    pane = a;
                } else {
                    eprintln!("est-hub agents delete: PANE --yes");
                    return 2;
                }
            }
            if pane.is_empty() {
                eprintln!("est-hub agents delete: PANE --yes");
                return 2;
            }
            if !confirm(&format!("delete agent {pane}"), yes) {
                return 1;
            }
            let (status, out) =
                match api(&client, "DELETE", &format!("{base}/agents/{pane}"), None).await {
                    Ok(r) => r,
                    Err(e) => return fail(json, &e),
                };
            if !(200..300).contains(&status) {
                return fail(json, &api_error(&out, status));
            }
            if json {
                println!("{}", out.trim());
            } else {
                println!("deleted agent {pane}");
            }
            0
        }
        _ => {
            eprintln!("est-hub agents: list, show, push, delete (try: help)");
            2
        }
    }
}

// ---------------------------------------------------------------- dispatch

#[tokio::main(flavor = "current_thread")]
async fn main() {
    log::init();
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let json = raw.iter().any(|a| a == "--json");
    let args: Vec<String> = raw.into_iter().filter(|a| a != "--json").collect();
    let code = match args.first().map(String::as_str) {
        None | Some("help") | Some("--help") | Some("-h") => {
            println!("{HELP}");
            0
        }
        Some("--version") | Some("version") => {
            println!("est-hub {VERSION}");
            0
        }
        Some("serve") => cmd_serve_async(&args[1..], json).await,
        Some("ping") => cmd_ping_async(&args[1..], json).await,
        Some("devices") => cmd_devices_async(&args[1..], json).await,
        Some("checks") => cmd_checks_async(&args[1..], json).await,
        Some("projects") => cmd_projects_async(&args[1..], json).await,
        Some("results") => cmd_results_async(&args[1..], json).await,
        Some("heartbeats") => cmd_heartbeats_async(&args[1..], json).await,
        Some("approvals") => cmd_approvals_async(&args[1..], json).await,
        Some("notify") => cmd_notify_async(&args[1..], json).await,
        Some("live") => cmd_live_async(&args[1..], json).await,
        Some("notifications") => cmd_notifications_async(&args[1..], json).await,
        Some("apns") => cmd_apns_async(&args[1..], json).await,
        Some("secrets") => cmd_secrets_async(&args[1..], json).await,
        Some("balances") => cmd_balances_async(&args[1..], json).await,
        Some("agents") => cmd_agents_async(&args[1..], json).await,
        Some(other) => {
            eprintln!("est-hub: unknown command {other:?} (try: help)");
            2
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_fields_parse_and_tolerate_drift() {
        let body = r#"{"ok":true,"v":1,"name":"est-hub","version":"0.1.0"}"#;
        assert_eq!(parse_ping(body), Some(("est-hub", "0.1.0")));
        assert_eq!(parse_ping("{}"), None);
        assert_eq!(parse_ping("not json"), None);
    }

    #[test]
    fn hub_url_prefers_flag_then_env_then_default() {
        assert_eq!(hub_url(Some("http://x:1/")), "http://x:1");
        assert_eq!(
            hub_url(Some("  ")),
            format!("http://{DEFAULT_BIND}:{DEFAULT_PORT}")
        );
    }

    #[test]
    fn help_lists_every_cli_twin() {
        // The parity gate checks this live; the unit test pins the habit:
        // a twin merged without a help line breaks here first.
        for twin in [
            "ping",
            "devices add",
            "devices list",
            "devices show",
            "devices revoke",
            "devices set",
            "devices live set",
            "devices live show",
            "devices live token",
            "devices live untoken",
            "live test",
            "checks add",
            "checks list",
            "checks show",
            "checks set",
            "checks delete",
            "checks ack",
            "checks unack",
            "checks mute",
            "checks unmute",
            "checks sync",
            "projects list",
            "projects show",
            "projects set",
            "projects icon",
            "results report",
            "results list",
            "heartbeats beat",
            "approvals request",
            "approvals list",
            "approvals show",
            "approvals decide",
            "notify send",
            "notify test",
            "notify alive",
            "notifications list",
            "apns show",
            "apns set",
            "secrets list",
            "secrets push",
            "secrets pull",
            "secrets token",
            "secrets revoke",
            "secrets delete",
            "balances list",
            "balances set",
            "balances delete",
        ] {
            assert!(HELP.contains(twin), "help lacks {twin:?}");
        }
        // The pairing and TLS surfaces are gone: help must not list them.
        for gone in [
            "devices ticket",
            "devices pair",
            "devices confirm",
            "devices stale",
            "tls ",
        ] {
            assert!(!HELP.contains(gone), "help still lists {gone:?}");
        }
    }

    #[test]
    fn parse_dur_reads_suffixes_and_seconds() {
        assert_eq!(parse_dur("30m"), Ok(1800));
        assert_eq!(parse_dur("2h"), Ok(7200));
        assert_eq!(parse_dur("7d"), Ok(604800));
        assert_eq!(parse_dur("1w"), Ok(604800));
        assert_eq!(parse_dur("45s"), Ok(45));
        assert_eq!(parse_dur("90"), Ok(90));
        assert_eq!(parse_dur(" 2h "), Ok(7200));
        assert!(parse_dur("").is_err());
        assert!(parse_dur("0").is_err());
        assert!(parse_dur("0h").is_err());
        assert!(parse_dur("-5m").is_err());
        assert!(parse_dur("2x").is_err());
        assert!(parse_dur("abc").is_err());
    }

    #[test]
    fn seen_words_reads() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(seen_words(now), "0s ago");
        assert_eq!(seen_words(now - 90), "1m ago");
        assert_eq!(seen_words(now - 7200), "2h ago");
        assert_eq!(seen_words(now - 3 * 86400), "3d ago");
    }
}
