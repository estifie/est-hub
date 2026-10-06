//! est-hub: serve the API, or talk to it.
//!
//! `serve` binds (tailnet in deploy, loopback for local work), probes
//! its hub-run checks on their own cadence, and answers until Ctrl-C.
//! Every other command is a twin of a hub route — agents operate the
//! whole hub through this binary. JSON mode prints one object and
//! nothing else, per the EST CLI contract.

use std::collections::HashMap;
use std::path::PathBuf;

use est_core::{cli, log, paths};
use est_hub::{db, model};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PORT: u16 = 18925;
const DEFAULT_BIND: &str = "127.0.0.1";

const HELP: &str = "est-hub: one API on the tailnet for the ecosystem

  est-hub serve [--bind IP] [--port N] [--db PATH]
  est-hub ping [--hub URL]
  est-hub devices add NAME [--pubkey K] [--apns T]
  est-hub devices list
  est-hub devices show NAME
  est-hub devices revoke NAME --yes
  est-hub checks add NAME --type T --target U --owner O [options]
  est-hub checks list [--owner O]
  est-hub checks show NAME
  est-hub checks set NAME --type T --target U --owner O [options]
  est-hub checks delete NAME --yes
  est-hub results report --check NAME --ok|--fail [--code C] [--reason R]
  est-hub results list --check NAME [--limit N]
  est-hub heartbeats beat --check NAME
  est-hub approvals request --title T [--body B] [--reply-to R] [--ttl S]
  est-hub approvals list [--state S]
  est-hub approvals show ID
  est-hub approvals decide ID --approve|--reject [--by WHO]
  est-hub notify send --title T [--body B] [--topic T] [--to DEV]
  est-hub notifications list [--limit N]
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
    let probe_db = db_path.clone();
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
                est_hub::probe::probe_check(&client, &probe_db, &c.name).await;
            }
        }
    });
    let code = match axum::serve(
        listener,
        est_hub::api::router(est_hub::api::AppState {
            db_path: db_path.clone(),
        }),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    {
        Ok(()) => 0,
        Err(e) => fail(json, &format!("serve failed: {e}")),
    };
    prober.abort();
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
            let mut pubkey: Option<String> = None;
            let mut apns: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--pubkey" => pubkey = opt(rest, &mut i, "--pubkey"),
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
            if pubkey.is_none() && apns.is_none() {
                // Allowed (registry entry), nothing required.
            }
            let (status, body) = match api(
                &client,
                "POST",
                &format!("{base}/devices"),
                Some(serde_json::json!({"name": name, "pubkey": pubkey, "apns_token": apns})),
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
                "pubkey:  {}",
                v.pointer("/device/pubkey")
                    .and_then(|p| p.as_str())
                    .unwrap_or("-")
            );
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
        _ => {
            eprintln!("est-hub devices: add, list, show, revoke (try: help)");
            2
        }
    }
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
        _ => {
            eprintln!("est-hub checks: add, list, show, set, delete (try: help)");
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
                Some(serde_json::json!({"check": check, "ok": ok_flag, "code": code, "reason": reason})),
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
            let url = match limit {
                Some(l) => format!("{base}/checks/{check}/results?limit={l}"),
                None => format!("{base}/checks/{check}/results"),
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
    if verb != "send" {
        eprintln!("est-hub notify: send (try: help)");
        return 2;
    }
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
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => return fail(json, &e),
    };
    let (status, out) = match api(
        &client,
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
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--limit" => match need(rest, &mut i, "notifications list", "--limit") {
                Ok(v) => limit = Some(v),
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
    let url = match limit {
        Some(l) => format!("{base}/notifications?limit={l}"),
        None => format!("{base}/notifications"),
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
        Some("results") => cmd_results_async(&args[1..], json).await,
        Some("heartbeats") => cmd_heartbeats_async(&args[1..], json).await,
        Some("approvals") => cmd_approvals_async(&args[1..], json).await,
        Some("notify") => cmd_notify_async(&args[1..], json).await,
        Some("notifications") => cmd_notifications_async(&args[1..], json).await,
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
            "checks add",
            "checks list",
            "checks show",
            "checks set",
            "checks delete",
            "results report",
            "results list",
            "heartbeats beat",
            "approvals request",
            "approvals list",
            "approvals show",
            "approvals decide",
            "notify send",
            "notifications list",
        ] {
            assert!(HELP.contains(twin), "help lacks {twin:?}");
        }
    }
}
