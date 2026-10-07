//! Apple Push Notification delivery: token-authenticated (ES256
//! provider JWT) alert pushes over HTTP/2, plus the queue fan-out.
//!
//! The sender identity is split on purpose: the `.p8` signing key is a
//! `0600` file next to the db (a bearer secret, never in SQLite), while
//! the three Apple ids (`key_id`, `team_id`, `topic`) live in `meta`
//! and are set once via `PUT /apns`. `notify_send` queues first (the
//! audit trail) and then best-effort delivers through [`deliver`];
//! `POST /notify/test` sends now and queues nothing. A 410 from Apple
//! clears the dead token via the existing `device_update_apns` path,
//! keeping the env — the feedback loop.

use std::path::{Path, PathBuf};

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm};
use base64::Engine;

/// `meta` key for the Apple Key ID (the `.p8` file's `kid`).
pub const META_KEY_ID: &str = "apns.key_id";
/// `meta` key for the Apple Team ID (the JWT `iss`).
pub const META_TEAM_ID: &str = "apns.team_id";
/// `meta` key for the app bundle id (the `apns-topic` header).
pub const META_TOPIC: &str = "apns.topic";

/// Production push host (TestFlight and the App Store both push here).
pub const PROD_HOST: &str = "https://api.push.apple.com";
/// Sandbox push host (local Debug builds only).
pub const DEV_HOST: &str = "https://api.sandbox.push.apple.com";

/// Apple's payload ceiling, bytes. [`payload`] trims the body so the
/// whole JSON stays inside it.
pub const MAX_PAYLOAD_BYTES: usize = 4096;

/// The push host for a device env: sandbox for `development`,
/// production for everything else (unknown and unset included —
/// anything the owner runs outside Xcode pushes production).
pub fn host_for_env(env: Option<&str>) -> &'static str {
    match env {
        Some("development") => DEV_HOST,
        _ => PROD_HOST,
    }
}

/// Suffix turning a bundle id into its Live Activity topic:
/// `<bid>.push-type.liveactivity`.
pub const LA_TOPIC_SUFFIX: &str = ".push-type.liveactivity";

/// The `attributes-type` every start push carries: the Swift
/// `ActivityAttributes` type the app decodes. Never rename it.
pub const LA_ATTRIBUTES_TYPE: &str = "ESTStatusAttributes";

/// The `attributes-type` of an incident card's start push: one pinned
/// card per down check. Same never-rename rule.
pub const INCIDENT_ATTRIBUTES_TYPE: &str = "ESTIncidentAttributes";

/// The `attributes-type` of the fleet card's start push: one card per
/// device, every live agent a row. Same never-rename rule — the Swift
/// `ESTFleetAttributes` must match it byte-for-byte.
pub const FLEET_ATTRIBUTES_TYPE: &str = "ESTFleetAttributes";

/// The `apns-topic` base for one device: its own override when set,
/// else the hub-wide `apns.topic` from `meta`. Alerts send on this
/// as-is; Live Activity pushes add [`LA_TOPIC_SUFFIX`].
pub fn resolve_topic(device_topic: Option<&str>, meta_topic: &str) -> String {
    match device_topic.map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => t.to_string(),
        None => meta_topic.to_string(),
    }
}

/// One bundle id's Live Activity topic.
pub fn live_topic(base: &str) -> String {
    format!("{base}{LA_TOPIC_SUFFIX}")
}

/// One shared Apple client: HTTP/2 (the `http2` reqwest feature speaks
/// it over the rustls ALPN the tree already builds) with a 10s send
/// budget. `serve` builds one and shares it via [`crate::api::AppState`].
pub fn shared_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// The loaded sender identity: Apple's three ids plus the P-256
/// signing key (PKCS#8 DER, parsed from the `.p8` file).
pub struct Config {
    // Debug is manual below: the key bytes never print.
    /// Apple Key ID: the JWT `kid` header.
    pub key_id: String,
    /// Apple Team ID: the JWT `iss` claim.
    pub team_id: String,
    /// App bundle id: the `apns-topic` header.
    pub topic: String,
    /// The `.p8` key, PKCS#8 DER.
    pub key_der: Vec<u8>,
}

/// Where the `.p8` lives: `--apns-key` first, then `EST_HUB_APNS_KEY`,
/// then `apns.p8` beside the db.
pub fn key_path(explicit: Option<&Path>, db_path: &Path) -> PathBuf {
    key_path_with_env(explicit, db_path, env_key_path().as_deref())
}

/// The env fallback, trimmed and non-blank, if set.
fn env_key_path() -> Option<String> {
    std::env::var("EST_HUB_APNS_KEY")
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
}

/// The resolution order as a pure function (the env arrives as a
/// value, so tests never touch process state).
fn key_path_with_env(explicit: Option<&Path>, db_path: &Path, env: Option<&str>) -> PathBuf {
    if let Some(p) = explicit.filter(|p| !p.as_os_str().is_empty()) {
        return p.to_path_buf();
    }
    if let Some(p) = env.filter(|p| !p.trim().is_empty()) {
        return PathBuf::from(p.trim());
    }
    crate::util::key_dir(db_path).join("apns.p8")
}

/// Load the sender identity, or `None` when APNs was never set up (no
/// key file at the default path and no ids in `meta` — tests and dev).
/// Anything half-configured refuses loudly in one human line: a
/// group/other-readable key, an explicit path that is missing, a key
/// that is not P-256, or a missing id.
pub fn load(
    explicit: Option<&Path>,
    db_path: &Path,
    conn: &rusqlite::Connection,
) -> Result<Option<Config>, String> {
    load_with(explicit, db_path, conn, env_key_path().as_deref())
}

/// [`load`] with the env fallback as a value, so tests stay hermetic
/// (process env is unreadable to mutation under `unsafe_code = forbid`).
fn load_with(
    explicit: Option<&Path>,
    db_path: &Path,
    conn: &rusqlite::Connection,
    env: Option<&str>,
) -> Result<Option<Config>, String> {
    let path = key_path_with_env(explicit, db_path, env);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if explicit.is_some() || env.is_some() {
                return Err(format!("cannot read {}: {e}", path.display()));
            }
            if [META_KEY_ID, META_TEAM_ID, META_TOPIC]
                .iter()
                .any(|k| crate::db::meta_get(conn, k).is_some())
            {
                return Err(format!(
                    "apns ids are set but {} is missing — install the .p8 key (0600) there",
                    path.display()
                ));
            }
            return Ok(None);
        }
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    // The key is a bearer secret: refuse group/other-readable, loudly.
    let mode = std::fs::metadata(&path)
        .map(|m| {
            use std::os::unix::fs::PermissionsExt;
            m.permissions().mode() & 0o777
        })
        .unwrap_or(0o777);
    if mode & 0o077 != 0 {
        return Err(format!(
            "{} is readable by group/other (mode {mode:o}) — chmod 600 {}",
            path.display(),
            path.display()
        ));
    }
    let key_der = parse_p8(&bytes).ok_or_else(|| {
        format!(
            "{} is not a .p8 key — install the Apple PKCS#8 file (0600) there",
            path.display()
        )
    })?;
    EcdsaKeyPair::from_pkcs8(signing_alg(), &key_der)
        .map_err(|_| format!("{} is not a P-256 APNs key", path.display()))?;
    let key_id = meta_line(conn, META_KEY_ID, "--key-id")?;
    let team_id = meta_line(conn, META_TEAM_ID, "--team-id")?;
    let topic = meta_line(conn, META_TOPIC, "--topic")?;
    Ok(Some(Config {
        key_id,
        team_id,
        topic,
        key_der,
    }))
}

/// One id from `meta`, or the one-human-line fix for setting it.
fn meta_line(conn: &rusqlite::Connection, key: &str, flag: &str) -> Result<String, String> {
    match crate::db::meta_get(conn, key).map(|v| v.trim().to_string()) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(format!(
            "{key} is not set — set it with `est-hub apns set {flag} …`"
        )),
    }
}

/// The `.p8` bytes to PKCS#8 DER: Apple's PEM armor first, raw DER
/// (a `0x30` SEQUENCE) as the fallback.
fn parse_p8(bytes: &[u8]) -> Option<Vec<u8>> {
    if let Ok(text) = std::str::from_utf8(bytes)
        && text.contains("-----BEGIN")
    {
        let body: String = text
            .lines()
            .filter(|l| !l.contains("-----"))
            .flat_map(|l| l.chars().filter(|c| !c.is_whitespace()))
            .collect();
        return base64::engine::general_purpose::STANDARD.decode(&body).ok();
    }
    if bytes.first() == Some(&0x30) {
        return Some(bytes.to_vec());
    }
    None
}

/// Fixed (raw R‖S) P-256 signing: JWS-ready, no ASN.1 re-encoding.
fn signing_alg() -> &'static EcdsaSigningAlgorithm {
    &ECDSA_P256_SHA256_FIXED_SIGNING
}

impl Config {
    /// Mint one provider JWT: ES256, `kid` header, `iss`/`iat` claims,
    /// 64-byte raw signature. Sends never call this directly — they go
    /// through [`provider_jwt_cached`], which reuses the token.
    pub fn provider_jwt(&self) -> Result<String, String> {
        jwt_for(&self.key_der, &self.key_id, &self.team_id)
    }
}

/// Freshness horizon for the cached provider JWT, seconds. Apple
/// allows a 60-minute token lifetime and throttles providers that mint
/// too often (`429 TooManyProviderTokenUpdates`) — so the hub mints
/// once and reuses the token for 50 minutes, refreshing proactively
/// before Apple could call it stale.
const PROVIDER_JWT_REUSE_SECS: u64 = 3000;

/// The process-wide provider JWT: `(key fingerprint, token, minted
/// epoch)`. One mint per 50 minutes per key — Apple's throttle never
/// trips, and a rotated `.p8` fails over on the next send (the
/// fingerprint won't match, so the stale token is never reused).
static PROVIDER_JWT: std::sync::Mutex<Option<(u64, String, u64)>> = std::sync::Mutex::new(None);

/// FNV-1a over the signing material: cheap, stable within a process,
/// enough to notice a rotated key.
fn key_fingerprint(cfg: &Config) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in cfg
        .key_der
        .iter()
        .chain(cfg.key_id.as_bytes())
        .chain(cfg.team_id.as_bytes())
    {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// True when the cached token is still good for this key at `now`.
/// A future `minted` (clock jumped back) reads stale — re-minting with
/// the current `iat` is the safe answer, never serving the old token.
fn jwt_fresh(cached_print: u64, minted: u64, print: u64, now: u64) -> bool {
    cached_print == print && minted <= now && now - minted < PROVIDER_JWT_REUSE_SECS
}

/// The provider JWT for this send: the cached token while it is fresh
/// for this key, else a fresh mint. The lock never crosses an await —
/// clone under it and drop.
fn provider_jwt_cached(cfg: &Config) -> Result<String, String> {
    let now = crate::model::now_epoch();
    let print = key_fingerprint(cfg);
    if let Ok(guard) = PROVIDER_JWT.lock()
        && let Some((cached_print, jwt, minted)) = guard.as_ref()
        && jwt_fresh(*cached_print, *minted, print, now)
    {
        return Ok(jwt.clone());
    }
    let jwt = cfg.provider_jwt()?;
    if let Ok(mut guard) = PROVIDER_JWT.lock() {
        *guard = Some((print, jwt.clone(), now));
    }
    Ok(jwt)
}

impl std::fmt::Debug for Config {
    /// Ids print, key bytes never do.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("key_id", &self.key_id)
            .field("team_id", &self.team_id)
            .field("topic", &self.topic)
            .field("key_der", &format!("<{} bytes>", self.key_der.len()))
            .finish()
    }
}

/// Mint the JWT: header, claims, and the P-256 signature over
/// `header.claims`, all base64url.
fn jwt_for(key_der: &[u8], key_id: &str, team_id: &str) -> Result<String, String> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = b64.encode(format!(r#"{{"alg":"ES256","kid":"{key_id}"}}"#));
    let claims = b64.encode(format!(
        r#"{{"iss":"{team_id}","iat":{}}}"#,
        crate::model::now_epoch()
    ));
    let message = format!("{header}.{claims}");
    let key = EcdsaKeyPair::from_pkcs8(signing_alg(), key_der)
        .map_err(|_| "the apns key would not parse".to_string())?;
    let sig = key
        .sign(&aws_lc_rs::rand::SystemRandom::new(), message.as_bytes())
        .map_err(|_| "the apns key refused to sign".to_string())?;
    Ok(format!("{message}.{}", b64.encode(sig.as_ref())))
}

/// The push body: an alert (title + body), the default sound, and the
/// hub topic for client routing. The body shrinks (then the title, in
/// extremis) until the whole JSON fits Apple's 4KB ceiling.
pub fn payload(title: &str, body: &str, est_topic: &str) -> serde_json::Value {
    payload_inner(title, body, est_topic, None, None)
}

/// An approval ask as a push: the full title + body (the phone decides
/// off this, so nothing is summarized away), the ask id for the
/// banner's Approve/Reject actions, and the `APPROVAL` category that
/// arms them. Same 4KB ceiling, counted with the extras in.
pub fn payload_approval(title: &str, body: &str, approval_id: i64) -> serde_json::Value {
    payload_inner(
        title,
        body,
        "approval.requested",
        Some(approval_id),
        Some("APPROVAL"),
    )
}

fn payload_inner(
    title: &str,
    body: &str,
    est_topic: &str,
    approval_id: Option<i64>,
    category: Option<&str>,
) -> serde_json::Value {
    let mut title = title.to_string();
    let mut body = body.to_string();
    loop {
        let mut aps =
            serde_json::json!({"alert": {"title": title, "body": body}, "sound": "default"});
        if let Some(category) = category {
            aps["category"] = category.into();
        }
        let mut value = serde_json::json!({
            "aps": aps,
            "est_topic": est_topic,
        });
        if let Some(id) = approval_id {
            value["approval_id"] = id.into();
        }
        let len = serde_json::to_vec(&value).map(|b| b.len()).unwrap_or(0);
        if len <= MAX_PAYLOAD_BYTES {
            return value;
        }
        let over = len - MAX_PAYLOAD_BYTES;
        if !body.is_empty() {
            trim_end(&mut body, over + 16);
        } else if !title.is_empty() {
            trim_end(&mut title, over + 16);
        } else {
            return value;
        }
    }
}

/// Drop `n` bytes off the end, on a char boundary.
fn trim_end(s: &mut String, n: usize) {
    let keep = s.len().saturating_sub(n);
    let mut at = keep.min(s.len());
    while at > 0 && !s.is_char_boundary(at) {
        at -= 1;
    }
    s.truncate(at);
}

// ---------------------------------------------------------------- live activity

/// The card's content state: the pinned wire contract. Keys are EXACTLY
/// `down_count`, `worst`, `pending_approvals`, `updated_ts` (the Swift
/// `ContentState` decodes them with a default `JSONDecoder`, so names
/// and shapes must never drift). Epoch seconds throughout.
pub fn live_content_state(
    down_count: u32,
    worst: &str,
    pending_approvals: u32,
    updated_ts: u64,
) -> serde_json::Value {
    serde_json::json!({
        "down_count": down_count,
        "worst": worst,
        "pending_approvals": pending_approvals,
        "updated_ts": updated_ts,
    })
}

/// An update push: new state, plus an alert only on essential
/// transitions (a fresh down, when the device wants the buzz).
pub fn live_update_payload(
    state: &serde_json::Value,
    alert: Option<(&str, &str)>,
    now_ts: u64,
) -> serde_json::Value {
    let mut aps = serde_json::Map::new();
    aps.insert("timestamp".to_string(), serde_json::json!(now_ts));
    aps.insert("event".to_string(), serde_json::json!("update"));
    aps.insert("content-state".to_string(), state.clone());
    if let Some((title, body)) = alert {
        aps.insert(
            "alert".to_string(),
            serde_json::json!({"title": title, "body": body}),
        );
    }
    serde_json::Value::Object({
        let mut root = serde_json::Map::new();
        root.insert("aps".to_string(), serde_json::Value::Object(aps));
        root
    })
}

/// An end push: the final state plus a dismissal date, so a dead card
/// never looks live. Both stamps are epoch seconds.
pub fn live_end_payload(
    state: &serde_json::Value,
    dismissal_ts: u64,
    now_ts: u64,
) -> serde_json::Value {
    serde_json::json!({
        "aps": {
            "timestamp": now_ts,
            "event": "end",
            "content-state": state,
            "dismissal-date": dismissal_ts,
        }
    })
}

/// A push-to-start push: attributes, first state, and the alert Apple
/// requires on every start (a start without one is refused).
pub fn live_start_payload(
    device_name: &str,
    title: &str,
    state: &serde_json::Value,
    alert_title: &str,
    alert_body: &str,
    now_ts: u64,
) -> serde_json::Value {
    serde_json::json!({
        "aps": {
            "timestamp": now_ts,
            "event": "start",
            "attributes-type": LA_ATTRIBUTES_TYPE,
            "attributes": {"device_name": device_name, "title": title},
            "content-state": state,
            "alert": {"title": alert_title, "body": alert_body},
        }
    })
}

/// Update priority: 10 when something just went down (it must arrive
/// now), else 5 — recovery and info rides cheap, outside the unpublished
/// hourly budget. Starts and ends always send at 10.
pub fn live_update_priority(newly_down: bool) -> u8 {
    if newly_down { 10 } else { 5 }
}

/// An incident card's content state: the pinned wire contract. Keys are
/// EXACTLY `reason`/`since_ts` (the Swift `ContentState` decodes them
/// with a default `JSONDecoder`, so names and shapes must never drift).
pub fn incident_content_state(reason: &str, since_ts: u64) -> serde_json::Value {
    serde_json::json!({
        "reason": reason,
        "since_ts": since_ts,
    })
}

/// An incident start push: the check as attributes, the first state,
/// and the alert Apple requires on every start. The card pins to the
/// lock screen until the recovery end drops it.
pub fn incident_start_payload(
    check: &str,
    reason: &str,
    since_ts: u64,
    now_ts: u64,
) -> serde_json::Value {
    serde_json::json!({
        "aps": {
            "timestamp": now_ts,
            "event": "start",
            "attributes-type": INCIDENT_ATTRIBUTES_TYPE,
            "attributes": {"check_name": check},
            "content-state": incident_content_state(reason, since_ts),
            "alert": {"title": format!("🔴 {check} is DOWN"), "body": reason},
        }
    })
}

/// An incident end push: the final state plus immediate dismissal, so
/// a recovered card never lingers.
pub fn incident_end_payload(reason: &str, since_ts: u64, now_ts: u64) -> serde_json::Value {
    serde_json::json!({
        "aps": {
            "timestamp": now_ts,
            "event": "end",
            "content-state": incident_content_state(reason, since_ts),
            "dismissal-date": now_ts,
        }
    })
}

/// A fleet card's content state: the pinned wire contract. Keys are
/// EXACTLY `rows`/`updated_ts`; each row is EXACTLY
/// `pane`/`name`/`status` (the Swift `ContentState` decodes them with
/// a default `JSONDecoder`, so names and shapes must never drift).
pub fn fleet_content_state(rows: &[crate::model::FleetRow], updated_ts: u64) -> serde_json::Value {
    serde_json::json!({
        "rows": rows,
        "updated_ts": updated_ts,
    })
}

/// A fleet push-to-start push: empty attributes (one card per device,
/// no per-card identity), the first rows, and the alert Apple requires
/// on every start.
pub fn fleet_start_payload(
    state: &serde_json::Value,
    alert_title: &str,
    alert_body: &str,
    now_ts: u64,
) -> serde_json::Value {
    serde_json::json!({
        "aps": {
            "timestamp": now_ts,
            "event": "start",
            "attributes-type": FLEET_ATTRIBUTES_TYPE,
            "attributes": {},
            "content-state": state,
            "alert": {"title": alert_title, "body": alert_body},
        }
    })
}

/// A fleet end push: the final rows plus immediate dismissal, so an
/// emptied card never lingers.
pub fn fleet_end_payload(state: &serde_json::Value, now_ts: u64) -> serde_json::Value {
    serde_json::json!({
        "aps": {
            "timestamp": now_ts,
            "event": "end",
            "content-state": state,
            "dismissal-date": now_ts,
        }
    })
}

/// What one Apple send came back with.
pub enum SendOutcome {
    /// Apple took it; the `apns-id` response header echoes here.
    Sent {
        /// The `apns-id` header (empty when Apple omitted it).
        apns_id: String,
    },
    /// HTTP 410: the token is dead — the caller clears it.
    Unregistered,
    /// Apple refused (400/403/429…): status plus its `reason`.
    Rejected {
        /// The HTTP status.
        status: u16,
        /// Apple's `reason` (or the raw body, trimmed).
        reason: String,
    },
    /// Never reached Apple: key trouble or a network failure.
    Transport(String),
}

impl SendOutcome {
    /// Was it accepted?
    pub fn sent(&self) -> bool {
        matches!(self, SendOutcome::Sent { .. })
    }

    /// The human line for the per-device `error` field. `Sent` has no
    /// error — it renders `apns_id` instead.
    pub fn error_line(&self) -> String {
        match self {
            SendOutcome::Sent { .. } => String::new(),
            SendOutcome::Unregistered => "unregistered (token cleared)".to_string(),
            SendOutcome::Rejected { status, reason } => {
                format!("apns {status}: {reason}")
            }
            SendOutcome::Transport(why) => why.clone(),
        }
    }
}

/// Map one Apple response: 200 sends, 410 unregisters, everything
/// else rejects with Apple's reason.
pub fn outcome_for(status: u16, reason: &str, apns_id: Option<&str>) -> SendOutcome {
    match status {
        200 => SendOutcome::Sent {
            apns_id: apns_id.unwrap_or("").to_string(),
        },
        410 => SendOutcome::Unregistered,
        _ => SendOutcome::Rejected {
            status,
            reason: if reason.is_empty() {
                format!("http {status}")
            } else {
                reason.to_string()
            },
        },
    }
}

/// Map one Apple response on the Live Activity path: 410 unregisters,
/// and so does a 400 `BadDeviceToken` (a dead activity token reads the
/// same as a dead device token — both get deleted). Everything else
/// maps exactly like [`outcome_for`].
pub fn outcome_for_live(status: u16, reason: &str, apns_id: Option<&str>) -> SendOutcome {
    if status == 410 || (status == 400 && reason == "BadDeviceToken") {
        return SendOutcome::Unregistered;
    }
    outcome_for(status, reason, apns_id)
}

/// Apple's `reason` out of a response body, else the raw body trimmed.
fn apple_reason(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body)
        && let Some(reason) = v.get("reason").and_then(|r| r.as_str())
    {
        return reason.to_string();
    }
    body.trim().chars().take(120).collect()
}

/// Push one payload to one token: bearer JWT (fresh per send),
/// `apns-topic`, `apns-push-type: alert`, priority 10, host by env.
/// The topic arrives resolved per device ([`resolve_topic`]) — alerts
/// send on it as-is.
pub async fn send_to(
    client: &reqwest::Client,
    cfg: &Config,
    token: &str,
    env: Option<&str>,
    topic: &str,
    payload: &[u8],
) -> SendOutcome {
    let outcome = post_push(
        client,
        cfg,
        &format!("{}/3/device/{token}", host_for_env(env)),
        &[
            ("apns-topic", topic),
            ("apns-push-type", "alert"),
            ("apns-priority", "10"),
        ],
        payload,
    )
    .await;
    map_post(outcome, false)
}

/// One Live Activity push: token, env, topic (already suffixed), priority.
pub struct LiveSend<'a> {
    /// The activity (or push-to-start) token.
    pub token: &'a str,
    /// The device's `apns_env` (host selector).
    pub env: Option<&'a str>,
    /// Full `apns-topic`, suffix included ([`live_topic`]).
    pub topic: &'a str,
    /// 10 for down/start/end, 5 for recovery/info.
    pub priority: u8,
    /// The JSON payload bytes.
    pub payload: &'a [u8],
    /// Test override for the Apple host (`None` in prod). The live.rs
    /// trigger tests point this at a mock and assert the wire bytes.
    pub base_override: Option<&'a str>,
}

/// Push one Live Activity payload: fresh provider JWT, `apns-push-type:
/// liveactivity`, the per-device topic, the caller's priority, and
/// `apns-expiration: 0` (a stale card must never resurrect).
pub async fn send_live(client: &reqwest::Client, cfg: &Config, send: &LiveSend<'_>) -> SendOutcome {
    let base = send.base_override.unwrap_or_else(|| host_for_env(send.env));
    let priority = send.priority.to_string();
    let outcome = post_push(
        client,
        cfg,
        &format!("{base}/3/device/{}", send.token),
        &[
            ("apns-topic", send.topic),
            ("apns-push-type", "liveactivity"),
            ("apns-priority", &priority),
            ("apns-expiration", "0"),
        ],
        send.payload,
    )
    .await;
    map_post(outcome, true)
}

/// One POST to Apple: the cached provider JWT plus the caller's headers.
/// Returns the JWT/transport failure, or the (status, reason, apns-id)
/// triple the outcome mappers read.
async fn post_push(
    client: &reqwest::Client,
    cfg: &Config,
    url: &str,
    headers: &[(&str, &str)],
    payload: &[u8],
) -> Result<(u16, String, Option<String>), String> {
    let jwt = match provider_jwt_cached(cfg) {
        Ok(j) => j,
        Err(e) => return Err(e),
    };
    let mut req = client.post(url);
    req = req.header(reqwest::header::AUTHORIZATION, format!("bearer {jwt}"));
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let res = match req.body(payload.to_vec()).send().await {
        Ok(r) => r,
        Err(e) => {
            return Err(format!("apns unreachable: {e}").chars().take(160).collect());
        }
    };
    let status = res.status().as_u16();
    let apns_id = res
        .headers()
        .get("apns-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = res.text().await.unwrap_or_default();
    Ok((status, apple_reason(&body), apns_id))
}

/// The posted triple to an outcome: transport failures stay transport,
/// Live Activity responses map via [`outcome_for_live`], alerts via
/// [`outcome_for`].
fn map_post(outcome: Result<(u16, String, Option<String>), String>, live: bool) -> SendOutcome {
    match outcome {
        Err(why) => SendOutcome::Transport(why),
        Ok((status, reason, apns_id)) if live => {
            outcome_for_live(status, &reason, apns_id.as_deref())
        }
        Ok((status, reason, apns_id)) => outcome_for(status, &reason, apns_id.as_deref()),
    }
}

/// One device's send result: name, env, and what Apple said.
pub struct Delivery {
    /// Device address.
    pub device: String,
    /// Its `apns_env` (host selector, echoed for the caller).
    pub env: Option<String>,
    /// What the send came back with.
    pub outcome: SendOutcome,
}

impl Delivery {
    /// The per-device JSON: `apns_id` on success, `error` otherwise.
    pub fn to_json(&self) -> serde_json::Value {
        match &self.outcome {
            SendOutcome::Sent { apns_id } => serde_json::json!({
                "device": self.device, "env": self.env, "apns_id": apns_id,
            }),
            other => serde_json::json!({
                "device": self.device, "env": self.env, "error": other.error_line(),
            }),
        }
    }
}

/// Who a send reaches: the named device, or — empty `to` — every
/// device holding a token. Unknown names refuse; tokenless devices
/// never send (broadcast skips them).
pub fn resolve_targets(
    conn: &rusqlite::Connection,
    to: &str,
) -> Result<Vec<crate::model::Device>, String> {
    let to = to.trim();
    if to.is_empty() {
        let all = crate::db::device_list(conn).map_err(|e| e.to_string())?;
        return Ok(all.into_iter().filter(|d| d.apns_configured()).collect());
    }
    crate::db::device_get(conn, to)
        .map(|d| vec![d])
        .map_err(|_| format!("no such device {to}"))
}

/// Push to devices, now: one payload, one send each, dead tokens
/// cleared (env kept) via `device_update_apns`. Tokenless devices are
/// skipped — the caller reports those. Queues nothing, marks nothing.
pub async fn deliver_to(
    client: &reqwest::Client,
    db_path: &Path,
    cfg: &Config,
    devices: &[crate::model::Device],
    title: &str,
    body: &str,
    est_topic: &str,
) -> Vec<Delivery> {
    let bytes = serde_json::to_vec(&payload(title, body, est_topic)).unwrap_or_default();
    deliver_bytes(client, db_path, cfg, devices, &bytes).await
}

/// One approval ask to devices, now: the full title + body plus the
/// ask id and `APPROVAL` category arming the banner's Approve/Reject
/// actions. Same dead-token feedback as `deliver_to`.
pub async fn deliver_approval_to(
    client: &reqwest::Client,
    db_path: &Path,
    cfg: &Config,
    devices: &[crate::model::Device],
    title: &str,
    body: &str,
    approval_id: i64,
) -> Vec<Delivery> {
    let bytes = serde_json::to_vec(&payload_approval(title, body, approval_id)).unwrap_or_default();
    deliver_bytes(client, db_path, cfg, devices, &bytes).await
}

async fn deliver_bytes(
    client: &reqwest::Client,
    db_path: &Path,
    cfg: &Config,
    devices: &[crate::model::Device],
    bytes: &[u8],
) -> Vec<Delivery> {
    let mut out = Vec::with_capacity(devices.len());
    for device in devices {
        let Some(token) = device.apns_token.as_deref().filter(|t| !t.is_empty()) else {
            continue;
        };
        let topic = resolve_topic(device.apns_topic.as_deref(), &cfg.topic);
        let outcome = send_to(
            client,
            cfg,
            token,
            device.apns_env.as_deref(),
            &topic,
            bytes,
        )
        .await;
        if matches!(outcome, SendOutcome::Unregistered)
            && let Ok(conn) = crate::db::open(db_path)
        {
            // The feedback loop: the token died, the env and topic stay.
            let _ = crate::db::device_update_apns(
                &conn,
                &device.name,
                None,
                device.apns_env.as_deref(),
                device.apns_topic.as_deref(),
            );
        }
        out.push(Delivery {
            device: device.name.clone(),
            env: device.apns_env.clone(),
            outcome,
        });
    }
    out
}

/// Fan a queued notification out: resolve its `to` (empty broadcasts),
/// send, and mark it delivered when at least one send lands. Best
/// effort throughout — unknown names and dead tokens resolve to
/// nothing sent, never to an error.
pub async fn deliver(
    client: &reqwest::Client,
    db_path: &Path,
    cfg: &Config,
    note: &crate::model::Notification,
) -> Vec<Delivery> {
    let targets = match crate::db::open(db_path)
        .map_err(|e| e.to_string())
        .and_then(|conn| resolve_targets(&conn, &note.to_device))
    {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let out = deliver_to(
        client,
        db_path,
        cfg,
        &targets,
        &note.title,
        &note.body,
        &note.topic,
    )
    .await;
    if out.iter().any(|d| d.outcome.sent())
        && let Ok(conn) = crate::db::open(db_path)
    {
        let _ = crate::db::notification_delivered(&conn, note.id);
    }
    out
}

/// Fan one approval ask out: like `deliver`, but the push carries the
/// ask id and `APPROVAL` category arming the banner's Approve/Reject
/// actions. Best effort throughout, marks delivered on any send.
pub async fn deliver_approval(
    client: &reqwest::Client,
    db_path: &Path,
    cfg: &Config,
    note: &crate::model::Notification,
    approval_id: i64,
) -> Vec<Delivery> {
    let targets = match crate::db::open(db_path)
        .map_err(|e| e.to_string())
        .and_then(|conn| resolve_targets(&conn, &note.to_device))
    {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let bytes = serde_json::to_vec(&payload_approval(&note.title, &note.body, approval_id))
        .unwrap_or_default();
    let out = deliver_bytes(client, db_path, cfg, &targets, &bytes).await;
    if out.iter().any(|d| d.outcome.sent())
        && let Ok(conn) = crate::db::open(db_path)
    {
        let _ = crate::db::notification_delivered(&conn, note.id);
    }
    out
}

// ---------------------------------------------------------------- alive

/// Ticks between alive rounds: 4 silent wakes a day, ~10s each —
/// the watchdog that notices a dead hub from the phone side.
pub const ALIVE_SECS: u64 = 6 * 3600;

/// The watchdog body: no alert, just `content-available` plus the
/// tick for client-side silence math. Never queued — a stale alive
/// must never resurrect.
pub fn alive_payload(alive_ts: u64) -> serde_json::Value {
    serde_json::json!({
        "aps": {"content-available": 1},
        "est_topic": "hub.alive",
        "alive_ts": alive_ts,
    })
}

/// One background POST: `apns-push-type: background`, priority 5,
/// expiration 0 (deliver now or drop — yesterday's alive is noise).
pub async fn send_background(
    client: &reqwest::Client,
    cfg: &Config,
    token: &str,
    env: Option<&str>,
    topic: &str,
    payload: &[u8],
) -> SendOutcome {
    let outcome = post_push(
        client,
        cfg,
        &format!("{}/3/device/{token}", host_for_env(env)),
        &[
            ("apns-topic", topic),
            ("apns-push-type", "background"),
            ("apns-priority", "5"),
            ("apns-expiration", "0"),
        ],
        payload,
    )
    .await;
    map_post(outcome, false)
}

/// Fan one alive round out: every tokened device, dead tokens
/// cleared (env kept) via the same feedback loop as alerts.
/// Queues nothing, marks nothing.
pub async fn deliver_alive(
    client: &reqwest::Client,
    db_path: &Path,
    cfg: &Config,
) -> Vec<Delivery> {
    let targets = match crate::db::open(db_path)
        .map_err(|e| e.to_string())
        .and_then(|conn| resolve_targets(&conn, ""))
    {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let bytes = serde_json::to_vec(&alive_payload(crate::model::now_epoch())).unwrap_or_default();
    let mut out = Vec::with_capacity(targets.len());
    for device in &targets {
        let Some(token) = device.apns_token.as_deref().filter(|t| !t.is_empty()) else {
            continue;
        };
        let topic = resolve_topic(device.apns_topic.as_deref(), &cfg.topic);
        let outcome = send_background(
            client,
            cfg,
            token,
            device.apns_env.as_deref(),
            &topic,
            &bytes,
        )
        .await;
        if matches!(outcome, SendOutcome::Unregistered)
            && let Ok(conn) = crate::db::open(db_path)
        {
            let _ = crate::db::device_update_apns(
                &conn,
                &device.name,
                None,
                device.apns_env.as_deref(),
                device.apns_topic.as_deref(),
            );
        }
        out.push(Delivery {
            device: device.name.clone(),
            env: device.apns_env.clone(),
            outcome,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key_der() -> Vec<u8> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        EcdsaKeyPair::generate_pkcs8(signing_alg(), &rng)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    fn test_config() -> Config {
        Config {
            key_id: "KEY1234567".to_string(),
            team_id: "TEAM123456".to_string(),
            topic: "com.estifie.hub".to_string(),
            key_der: test_key_der(),
        }
    }

    fn b64url(part: &str) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .unwrap()
    }

    #[test]
    fn provider_jwt_has_three_segments_and_verifies() {
        let key = EcdsaKeyPair::generate(signing_alg()).unwrap();
        let cfg = Config {
            key_der: key.to_pkcs8v1().unwrap().as_ref().to_vec(),
            ..test_config()
        };
        let jwt = cfg.provider_jwt().unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value = serde_json::from_slice(&b64url(parts[0])).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEY1234567");
        let claims: serde_json::Value = serde_json::from_slice(&b64url(parts[1])).unwrap();
        assert_eq!(claims["iss"], "TEAM123456");
        assert!(claims["iat"].as_u64().unwrap() > 1_700_000_000);
        // The signature is 64 raw bytes, and verifies under the key.
        let sig = b64url(parts[2]);
        assert_eq!(sig.len(), 64);
        use aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED;
        use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey};
        let public = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key().as_ref());
        let message = format!("{}.{}", parts[0], parts[1]);
        public.verify(message.as_bytes(), &sig).unwrap();
    }

    #[test]
    fn jwt_fresh_holds_key_and_fifty_minutes() {
        assert!(jwt_fresh(7, 1_000, 7, 1_000));
        assert!(jwt_fresh(7, 1_000, 7, 1_000 + PROVIDER_JWT_REUSE_SECS - 1));
        assert!(!jwt_fresh(7, 1_000, 7, 1_000 + PROVIDER_JWT_REUSE_SECS));
        assert!(!jwt_fresh(7, 1_000, 8, 1_000));
        assert!(!jwt_fresh(7, 2_000, 7, 1_000));
    }

    #[test]
    fn jwt_cache_reuses_per_key_and_fails_over_on_rotation() {
        let key_a = EcdsaKeyPair::generate(signing_alg()).unwrap();
        let key_b = EcdsaKeyPair::generate(signing_alg()).unwrap();
        let cfg_a = Config {
            key_der: key_a.to_pkcs8v1().unwrap().as_ref().to_vec(),
            ..test_config()
        };
        let cfg_b = Config {
            key_der: key_b.to_pkcs8v1().unwrap().as_ref().to_vec(),
            ..test_config()
        };
        // Same key twice: one mint, byte-identical reuse.
        let first = provider_jwt_cached(&cfg_a).unwrap();
        let second = provider_jwt_cached(&cfg_a).unwrap();
        assert_eq!(first, second);
        // Rotated key: the stale token never serves another key.
        let rotated = provider_jwt_cached(&cfg_b).unwrap();
        assert_ne!(first, rotated);
        assert_eq!(provider_jwt_cached(&cfg_b).unwrap(), rotated);
    }

    #[test]
    fn alive_payload_is_silent_with_a_tick() {
        let v = alive_payload(1_700_000_000);
        assert_eq!(v["aps"]["content-available"], 1);
        assert!(v["aps"].get("alert").is_none());
        assert!(v["aps"].get("sound").is_none());
        assert_eq!(v["est_topic"], "hub.alive");
        assert_eq!(v["alive_ts"], 1_700_000_000);
    }

    #[tokio::test]
    async fn alive_round_with_no_devices_sends_nothing() {
        let dir = std::env::temp_dir().join(format!("est-hub-alive-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db_path = dir.join("hub.sqlite");
        let _ = crate::db::open(&db_path).unwrap();
        let out = deliver_alive(&reqwest::Client::new(), &db_path, &test_config()).await;
        assert!(out.is_empty());
    }

    #[test]
    fn payload_carries_alert_sound_and_topic() {
        let v = payload("hi", "there", "health.flip");
        assert_eq!(v["aps"]["alert"]["title"], "hi");
        assert_eq!(v["aps"]["alert"]["body"], "there");
        assert_eq!(v["aps"]["sound"], "default");
        assert_eq!(v["est_topic"], "health.flip");
        // Empty bodies ride along, never vanish.
        let v = payload("hi", "", "notify");
        assert_eq!(v["aps"]["alert"]["body"], "");
        assert_eq!(v["aps"]["alert"]["title"], "hi");
    }

    #[test]
    fn payload_trims_into_the_4k_ceiling() {
        let big = "x".repeat(6000);
        let v = payload("title", &big, "notify");
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(bytes.len() <= MAX_PAYLOAD_BYTES, "{}", bytes.len());
        assert_eq!(v["aps"]["alert"]["title"], "title");
        assert!(!v["aps"]["alert"]["body"].as_str().unwrap().is_empty());
        // Multibyte bodies trim on char boundaries.
        let big = "é".repeat(3000);
        let v = payload("t", &big, "notify");
        assert!(serde_json::to_vec(&v).unwrap().len() <= MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn approval_payload_carries_id_category_and_full_detail() {
        let v = payload_approval("Deploy?", "restart api on vps2", 7);
        assert_eq!(v["aps"]["alert"]["title"], "Deploy?");
        assert_eq!(v["aps"]["alert"]["body"], "restart api on vps2");
        assert_eq!(v["aps"]["category"], "APPROVAL");
        assert_eq!(v["approval_id"], 7);
        assert_eq!(v["est_topic"], "approval.requested");
        // Oversized detail still fits the ceiling, id and category intact.
        let big = "y".repeat(6000);
        let v = payload_approval("Deploy?", &big, 7);
        assert!(serde_json::to_vec(&v).unwrap().len() <= MAX_PAYLOAD_BYTES);
        assert_eq!(v["approval_id"], 7);
        assert_eq!(v["aps"]["category"], "APPROVAL");
    }

    #[test]
    fn outcomes_map_apple_statuses() {
        assert!(matches!(
            outcome_for(200, "", Some("abc")),
            SendOutcome::Sent { apns_id } if apns_id == "abc"
        ));
        assert!(matches!(
            outcome_for(200, "", None),
            SendOutcome::Sent { apns_id } if apns_id.is_empty()
        ));
        assert!(matches!(
            outcome_for(410, "Unregistered", None),
            SendOutcome::Unregistered
        ));
        for (status, reason) in [
            (400, "BadDeviceToken"),
            (403, "InvalidProviderToken"),
            (429, "TooManyRequests"),
        ] {
            match outcome_for(status, reason, None) {
                SendOutcome::Rejected {
                    status: s,
                    reason: r,
                } => {
                    assert_eq!(s, status);
                    assert_eq!(r, reason);
                }
                other => panic!("{status} mapped to {}", other.error_line()),
            }
        }
        // Empty reasons still read human.
        match outcome_for(500, "", None) {
            SendOutcome::Rejected { reason, .. } => assert_eq!(reason, "http 500"),
            other => panic!("500 mapped to {}", other.error_line()),
        }
        assert_eq!(
            SendOutcome::Unregistered.error_line(),
            "unregistered (token cleared)"
        );
    }

    #[test]
    fn apple_reasons_parse_or_trim() {
        assert_eq!(
            apple_reason(r#"{"reason":"BadDeviceToken"}"#),
            "BadDeviceToken"
        );
        assert_eq!(apple_reason("plain 500 page"), "plain 500 page");
        assert_eq!(apple_reason(""), "");
    }

    #[test]
    fn hosts_follow_the_env() {
        assert_eq!(host_for_env(Some("development")), DEV_HOST);
        assert_eq!(host_for_env(Some("production")), PROD_HOST);
        assert_eq!(host_for_env(None), PROD_HOST);
        assert_eq!(host_for_env(Some("weird")), PROD_HOST);
    }

    #[test]
    fn key_path_prefers_flag_then_env_then_default() {
        let db = PathBuf::from("/tmp/x/hub.sqlite");
        assert_eq!(
            key_path_with_env(Some(Path::new("/k.p8")), &db, Some("/env.p8")),
            PathBuf::from("/k.p8")
        );
        assert_eq!(
            key_path_with_env(None, &db, Some("/env.p8")),
            PathBuf::from("/env.p8")
        );
        assert_eq!(
            key_path_with_env(None, &db, Some("   ")),
            PathBuf::from("/tmp/x/apns.p8")
        );
        assert_eq!(
            key_path_with_env(None, &db, None),
            PathBuf::from("/tmp/x/apns.p8")
        );
    }

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("est-hub-apns-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_key(path: &Path, der: &[u8], mode: u32) {
        use std::os::unix::fs::OpenOptionsExt;
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        );
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(mode);
        use std::io::Write;
        opts.open(path).unwrap().write_all(pem.as_bytes()).unwrap();
    }

    fn open_db(dir: &Path) -> rusqlite::Connection {
        crate::db::open(&dir.join("hub.sqlite")).unwrap()
    }

    #[test]
    fn load_roundtrips_a_key_and_ids() {
        let dir = tempdir("load");
        let conn = open_db(&dir);
        let der = test_key_der();
        write_key(&dir.join("apns.p8"), &der, 0o600);
        crate::db::meta_set(&conn, META_KEY_ID, "KEY1").unwrap();
        crate::db::meta_set(&conn, META_TEAM_ID, "TEAM1").unwrap();
        crate::db::meta_set(&conn, META_TOPIC, "com.x").unwrap();
        // Hermetic: the env arrives as a value, never from the process.
        let key = dir.join("apns.p8");
        let cfg = load_with(Some(key.as_path()), &dir.join("hub.sqlite"), &conn, None)
            .unwrap()
            .unwrap();
        assert_eq!(cfg.key_id, "KEY1");
        assert_eq!(cfg.team_id, "TEAM1");
        assert_eq!(cfg.topic, "com.x");
        assert_eq!(cfg.key_der, der);
        assert!(cfg.provider_jwt().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_unconfigured_reads_none() {
        // No key at the default path, no ids: cleanly unconfigured.
        let dir = tempdir("unconfigured");
        let conn = open_db(&dir);
        let out = load_with(None, &dir.join("hub.sqlite"), &conn, None).unwrap();
        assert!(out.is_none());
        // A missing env path refuses — it never reads as unconfigured.
        let err = load_with(None, &dir.join("hub.sqlite"), &conn, Some("/nope.p8")).unwrap_err();
        assert!(err.contains("cannot read"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_refuses_loudly_when_half_configured() {
        let dir = tempdir("loud");
        let conn = open_db(&dir);
        let db = dir.join("hub.sqlite");
        let via = |name: &str| load_with(Some(dir.join(name).as_path()), &db, &conn, None);
        // A readable-by-all key refuses, naming the fix.
        write_key(&dir.join("open.p8"), &test_key_der(), 0o644);
        let err = via("open.p8").unwrap_err();
        assert!(err.contains("chmod 600"), "{err}");
        // An explicit path that is missing refuses (never unconfigured).
        let err = via("nope.p8").unwrap_err();
        assert!(err.contains("cannot read"), "{err}");
        // Garbage bytes are not a key.
        std::fs::write(dir.join("junk.p8"), b"not a key\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.join("junk.p8"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let err = via("junk.p8").unwrap_err();
        assert!(err.contains("not a .p8 key"), "{err}");
        // A good key with no ids names the missing id.
        write_key(&dir.join("good.p8"), &test_key_der(), 0o600);
        let err = via("good.p8").unwrap_err();
        assert!(err.contains(META_KEY_ID), "{err}");
        assert!(err.contains("apns set"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);

        // Ids with no key file at the default path refuse too.
        let dir = tempdir("loud-ids");
        let conn = open_db(&dir);
        crate::db::meta_set(&conn, META_KEY_ID, "K").unwrap();
        let err = load_with(None, &dir.join("hub.sqlite"), &conn, None).unwrap_err();
        assert!(err.contains("apns.p8"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn topics_resolve_override_then_fallback_then_suffix() {
        assert_eq!(resolve_topic(Some("com.x.y"), "com.x"), "com.x.y");
        assert_eq!(resolve_topic(None, "com.x"), "com.x");
        assert_eq!(resolve_topic(Some("  "), "com.x"), "com.x");
        assert_eq!(live_topic("com.x"), "com.x.push-type.liveactivity");
        assert_eq!(
            live_topic(&resolve_topic(Some("com.x.y"), "com.x")),
            "com.x.y.push-type.liveactivity"
        );
    }

    /// The exact key set of an object (order never matters to a JSON
    /// decoder; presence and absence do).
    fn keys(v: &serde_json::Value) -> Vec<&str> {
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        keys
    }

    #[test]
    fn live_update_carries_exact_state_keys_and_optional_alert() {
        let state = live_content_state(2, "high", 1, 1_700_000_000);
        assert_eq!(
            keys(&state),
            ["down_count", "pending_approvals", "updated_ts", "worst"]
        );
        assert_eq!(state["down_count"], 2);
        assert_eq!(state["worst"], "high");
        assert_eq!(state["pending_approvals"], 1);
        assert_eq!(state["updated_ts"], 1_700_000_000);
        // Silent update: no alert key at all.
        let v = live_update_payload(&state, None, 1_700_000_001);
        assert_eq!(v["aps"]["event"], "update");
        assert_eq!(v["aps"]["timestamp"], 1_700_000_001);
        assert!(v["aps"].get("alert").is_none());
        assert_eq!(v["aps"]["content-state"], state);
        // Alerting update: title + body.
        let v = live_update_payload(&state, Some(("t", "b")), 1_700_000_001);
        assert_eq!(v["aps"]["alert"]["title"], "t");
        assert_eq!(v["aps"]["alert"]["body"], "b");
    }

    #[test]
    fn live_end_carries_final_state_and_dismissal() {
        let state = live_content_state(0, "low", 0, 1_700_000_000);
        let v = live_end_payload(&state, 1_700_003_600, 1_700_000_000);
        assert_eq!(v["aps"]["event"], "end");
        assert_eq!(v["aps"]["content-state"], state);
        assert_eq!(v["aps"]["dismissal-date"], 1_700_003_600);
        assert_eq!(v["aps"]["timestamp"], 1_700_000_000);
    }

    #[test]
    fn live_start_carries_attributes_and_required_alert() {
        let state = live_content_state(1, "normal", 0, 1_700_000_000);
        let v = live_start_payload("phone", "EST status", &state, "at", "ab", 1_700_000_000);
        assert_eq!(v["aps"]["event"], "start");
        assert_eq!(v["aps"]["attributes-type"], LA_ATTRIBUTES_TYPE);
        assert_eq!(keys(&v["aps"]["attributes"]), ["device_name", "title"]);
        assert_eq!(v["aps"]["attributes"]["device_name"], "phone");
        assert_eq!(v["aps"]["attributes"]["title"], "EST status");
        assert_eq!(v["aps"]["content-state"], state);
        assert_eq!(v["aps"]["alert"]["title"], "at");
        assert_eq!(v["aps"]["alert"]["body"], "ab");
    }

    #[test]
    fn fleet_payloads_pin_rows_and_empty_attributes() {
        let rows = vec![crate::model::FleetRow {
            pane: "w1:p1".to_string(),
            name: "Export".to_string(),
            status: "working".to_string(),
        }];
        let state = fleet_content_state(&rows, 1_700_000_000);
        assert_eq!(keys(&state), ["rows", "updated_ts"]);
        assert_eq!(keys(&state["rows"][0]), ["name", "pane", "status"]);
        assert_eq!(state["updated_ts"], 1_700_000_000);
        let v = fleet_start_payload(&state, "t", "b", 1_700_000_001);
        assert_eq!(v["aps"]["event"], "start");
        assert_eq!(v["aps"]["attributes-type"], FLEET_ATTRIBUTES_TYPE);
        assert_eq!(v["aps"]["attributes"], serde_json::json!({}));
        assert_eq!(v["aps"]["content-state"], state);
        assert_eq!(v["aps"]["alert"]["title"], "t");
        let v = fleet_end_payload(&state, 1_700_000_002);
        assert_eq!(v["aps"]["event"], "end");
        assert_eq!(v["aps"]["dismissal-date"], 1_700_000_002);
    }

    #[test]
    fn live_priorities_favor_the_fresh_down() {
        assert_eq!(live_update_priority(true), 10);
        assert_eq!(live_update_priority(false), 5);
    }

    #[test]
    fn live_outcomes_unregister_on_410_and_bad_token() {
        assert!(matches!(
            outcome_for_live(410, "Unregistered", None),
            SendOutcome::Unregistered
        ));
        assert!(matches!(
            outcome_for_live(400, "BadDeviceToken", None),
            SendOutcome::Unregistered
        ));
        // Everything else maps exactly like alerts.
        assert!(matches!(
            outcome_for_live(200, "", Some("abc")),
            SendOutcome::Sent { .. }
        ));
        match outcome_for_live(400, "BadTopic", None) {
            SendOutcome::Rejected { status, reason } => {
                assert_eq!(status, 400);
                assert_eq!(reason, "BadTopic");
            }
            other => panic!("BadTopic mapped to {}", other.error_line()),
        }
        match outcome_for_live(403, "InvalidProviderToken", None) {
            SendOutcome::Rejected { .. } => {}
            other => panic!("403 mapped to {}", other.error_line()),
        }
    }

    #[test]
    fn targets_resolve_single_and_broadcast() {
        let dir = tempdir("targets");
        let conn = open_db(&dir);
        crate::db::device_add(&conn, "phone", Some("tok1")).unwrap();
        crate::db::device_update_apns(&conn, "phone", Some("tok1"), Some("production"), None)
            .unwrap();
        crate::db::device_add(&conn, "watch", Some("tok2")).unwrap();
        crate::db::device_update_apns(&conn, "watch", Some("tok2"), Some("development"), None)
            .unwrap();
        crate::db::device_add(&conn, "bare", None).unwrap();
        // Broadcast reaches exactly the tokened devices.
        let targets = resolve_targets(&conn, "").unwrap();
        let names: Vec<&str> = targets.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["phone", "watch"]);
        // Named delivery reaches one, token or not.
        let targets = resolve_targets(&conn, "bare").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "bare");
        // Unknown names refuse with the name.
        let err = match resolve_targets(&conn, "nope") {
            Ok(_) => panic!("unknown device resolved"),
            Err(e) => e,
        };
        assert!(err.contains("nope"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
