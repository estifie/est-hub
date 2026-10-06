//! est-hub: serve the API, or talk to it.
//!
//! `serve` binds the tailnet (or loopback for local work) and answers
//! until Ctrl-C; `ping` asks a hub if it is alive. JSON mode prints one
//! object and nothing else, per the EST CLI contract.

use std::path::PathBuf;

use est_core::{cli, log, paths};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PORT: u16 = 18925;
const DEFAULT_BIND: &str = "127.0.0.1";

const HELP: &str = "est-hub: one API on the tailnet for the ecosystem

  est-hub serve [--bind IP] [--port N] [--db PATH]
                                     bind and answer until Ctrl-C
  est-hub ping [--hub URL]           ask a hub if it is alive
  est-hub help                       this text

serve binds 127.0.0.1:18925 unless told otherwise; deploy binds the
tailnet IP, never 0.0.0.0. ping reads --hub, EST_HUB_URL, else the
local default. --json rides any command and prints one object.
Exit codes: 0 ok, 1 failed, 2 wrong usage. Full reference: docs/cli.md.";

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

async fn cmd_serve_async(args: &[String], json: bool) -> i32 {
    let mut bind = DEFAULT_BIND.to_string();
    let mut port = DEFAULT_PORT;
    let mut db: Option<String> = None;
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
                db = Some(p.to_string());
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
    let db_path = resolve_db(db.as_deref());
    if let Err(e) = est_hub::db::open(&db_path) {
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
    if let Err(e) = axum::serve(listener, est_hub::api::router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    {
        return fail(json, &format!("serve failed: {e}"));
    }
    0
}

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
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => return fail(json, &format!("no HTTP client: {e}")),
    };
    let url = format!("{base}/ping");
    let body = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => match r.text().await {
            Ok(t) => t,
            Err(e) => return fail(json, &format!("no hub at {base} ({e})")),
        },
        Ok(r) => return fail(json, &format!("no hub at {base} (HTTP {})", r.status())),
        Err(e) => return fail(json, &format!("no hub at {base} ({e})")),
    };
    if json {
        println!("{}", body.trim());
        return 0;
    }
    let (name, version) = parse_ping(&body).unwrap_or(("?", "?"));
    println!("hub ok ({name} {version})");
    0
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
}
