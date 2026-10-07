//! Full resource flows over real HTTP, plus every CLI twin against
//! a live hub. If a flow breaks here, dashboards and agents break too.

mod common;

use common::Hub;
use serde_json::{Value, json};

async fn post(hub: &Hub, path: &str, body: Value) -> (u16, Value) {
    let res = reqwest::Client::new()
        .post(hub.url(path))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap())
}

async fn get(hub: &Hub, path: &str) -> (u16, Value) {
    let res = reqwest::get(hub.url(path)).await.unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap())
}

async fn put(hub: &Hub, path: &str, body: Value) -> (u16, Value) {
    let res = reqwest::Client::new()
        .put(hub.url(path))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap())
}

#[tokio::test]
async fn device_self_registers_then_updates_push_state() {
    let hub = Hub::spawn("flows-device-self");
    // The phone registers itself over the tailnet: PUT upserts the row.
    let (s, v) = put(
        &hub,
        "/devices/phone",
        json!({"apns_token": "tok-1", "apns_env": "production"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["device"]["name"], "phone");
    assert_eq!(v["device"]["state"], "active");
    assert_eq!(v["device"]["apns_env"], "production");
    assert_eq!(v["device"]["apns_configured"], true);
    // Idempotent: a second upsert keeps one row and refreshes the token.
    let (s, v) = put(&hub, "/devices/phone", json!({"apns_token": "tok-2"})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["device"]["apns_token"], "tok-2");
    // Env validation still bites.
    let res = reqwest::Client::new()
        .put(hub.url("/devices/phone"))
        .json(&json!({"apns_env": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 400);
    // Empty clears; absent keeps.
    let (s, v) = put(&hub, "/devices/phone", json!({"apns_token": ""})).await;
    assert_eq!(s, 200);
    assert!(v["device"]["apns_token"].is_null());
    // The registry path (POST) and the upsert (PUT) land in one list.
    let (s, _) = post(&hub, "/devices", json!({"name": "watch"})).await;
    assert_eq!(s, 201);
    let (_, v) = get(&hub, "/devices").await;
    let names: Vec<&str> = v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["phone", "watch"]);
    // The name is validated before any write.
    let (s, _) = put(&hub, "/devices/Nope!", json!({})).await;
    assert_eq!(s, 400);
}

#[tokio::test]
async fn devices_crud_roundtrip() {
    let hub = Hub::spawn("flows-devices");
    let (s, v) = post(&hub, "/devices", json!({"name": "iphone"})).await;
    assert_eq!(s, 201);
    assert_eq!(v["device"]["name"], "iphone");
    let (s, v) = post(&hub, "/devices", json!({"name": "iphone"})).await;
    assert_eq!(s, 409);
    assert_eq!(v["ok"], false);
    let (s, _) = get(&hub, "/devices").await;
    assert_eq!(s, 200);
    let (s, v) = post(&hub, "/devices", json!({"name": "Nope!"})).await;
    assert_eq!(s, 400);
    assert_eq!(v["ok"], false);
    let client = reqwest::Client::new();
    let res = client
        .delete(hub.url("/devices/iphone"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let (s, _) = get(&hub, "/devices/iphone").await;
    assert_eq!(s, 404);
}

#[tokio::test]
async fn plain_devices_keep_tokens_and_flag() {
    let hub = Hub::spawn("flows-plain-tokens");
    // The tailnet listener serves the full token plus the new bit.
    let (s, v) = post(
        &hub,
        "/devices",
        json!({"name": "iphone", "apns_token": "plain-tok"}),
    )
    .await;
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["device"]["apns_token"], "plain-tok");
    assert_eq!(v["device"]["apns_configured"], true);
    let (s, v) = get(&hub, "/devices/iphone").await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["device"]["apns_token"], "plain-tok");
    assert_eq!(v["device"]["apns_configured"], true);
    let (s, v) = get(&hub, "/devices").await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["devices"][0]["apns_token"], "plain-tok");
    assert_eq!(v["devices"][0]["apns_configured"], true);
    // No token anywhere: null on the wire, flag false.
    let (s, v) = post(&hub, "/devices", json!({"name": "bare"})).await;
    assert_eq!(s, 201, "{v}");
    assert!(v["device"]["apns_token"].is_null(), "{v}");
    assert_eq!(v["device"]["apns_configured"], false);
}

#[tokio::test]
async fn checks_crud_and_validation() {
    let hub = Hub::spawn("flows-checks");
    let (s, v) = post(
        &hub,
        "/checks",
        json!({"name": "site", "owner": "estifie", "type": "url", "target": "https://example.com"}),
    )
    .await;
    assert_eq!(s, 201);
    assert_eq!(v["check"]["state"]["status"], "unknown");
    let (s, _) = post(
        &hub,
        "/checks",
        json!({"name": "bad", "owner": "e", "type": "nope", "target": "x"}),
    )
    .await;
    assert_eq!(s, 400);
    let client = reqwest::Client::new();
    let res = client
        .put(hub.url("/checks/site"))
        .json(&json!({"owner": "e2", "type": "url", "target": "https://example.org"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["check"]["owner"], "e2");
    let res = client.delete(hub.url("/checks/site")).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let (s, _) = get(&hub, "/checks/site").await;
    assert_eq!(s, 404);
}

#[tokio::test]
async fn ack_mute_roundtrip_and_gates() {
    let hub = Hub::spawn("flows-silence");
    let (s, _) = post(
        &hub,
        "/checks",
        json!({"name": "site", "owner": "estifie", "type": "url", "target": "https://example.com"}),
    )
    .await;
    assert_eq!(s, 201);
    // Ack with an explicit span: the fresh check carries the horizon.
    let (s, v) = put(&hub, "/checks/site/ack", json!({"until_secs": 3600})).await;
    assert_eq!(s, 200, "{v}");
    assert!(v["check"]["ack_until"].as_u64().unwrap() > 0, "{v}");
    assert_eq!(v["check"]["mute_until"], 0);
    // Mute defaults to a day when the body omits the span.
    let (s, v) = put(&hub, "/checks/site/mute", json!({})).await;
    assert_eq!(s, 200, "{v}");
    assert!(v["check"]["mute_until"].as_u64().unwrap() > 0, "{v}");
    // Lifts clear; clearing twice still 200s.
    let client = reqwest::Client::new();
    for path in ["/checks/site/ack", "/checks/site/mute"] {
        for _ in 0..2 {
            let res = client.delete(hub.url(path)).send().await.unwrap();
            assert_eq!(res.status().as_u16(), 200, "{path}");
        }
    }
    let (_, v) = get(&hub, "/checks/site").await;
    assert_eq!(v["check"]["ack_until"], 0);
    assert_eq!(v["check"]["mute_until"], 0);
    // Ghost checks 404; bad spans 400.
    let (s, v) = put(&hub, "/checks/ghost/ack", json!({"until_secs": 60})).await;
    assert_eq!(s, 404, "{v}");
    let (s, v) = put(&hub, "/checks/site/ack", json!({"until_secs": 0})).await;
    assert_eq!(s, 400, "{v}");
    let (s, v) = put(&hub, "/checks/site/mute", json!({"until_secs": 31 * 86400})).await;
    assert_eq!(s, 400, "{v}");
    let res = client
        .delete(hub.url("/checks/ghost/mute"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 404);
}

#[tokio::test]
async fn alive_without_apns_is_a_loud_400() {
    // The drill route on an unconfigured hub: an enveloped refusal,
    // never a silent 200 with zero sends.
    let hub = Hub::spawn("flows-alive");
    let (s, v) = post(&hub, "/notify/alive", json!({})).await;
    assert_eq!(s, 400, "{v}");
    assert_eq!(v["ok"], false);
    assert_eq!(v["v"], 1);
}

#[tokio::test]
async fn secrets_push_token_pull_revoke_delete() {
    let hub = Hub::spawn("flows-secrets");
    let client = reqwest::Client::new();
    // Push: the blob never echoes.
    let (s, v) = put(&hub, "/secrets/api", json!({"env": "K=V\n"})).await;
    assert_eq!(s, 200, "{v}");
    assert!(
        v["secret"]["sha"].as_str().is_some_and(|h| h.len() == 64),
        "{v}"
    );
    assert!(v.get("env").is_none(), "{v}");
    assert_eq!(v["secret"]["has_token"], false);
    // Mint: the plaintext shows once.
    let res = client
        .post(hub.url("/secrets/api/token"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 201);
    let v: Value = res.json().await.unwrap();
    let token = v["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("est_s_"), "{v}");
    // Pull with the token: the one route that serves a blob.
    let res = client
        .get(hub.url("/secrets/api"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["env"], "K=V\n");
    // No token 401s, a wrong token 404s (never confirm).
    let (s, _) = get(&hub, "/secrets/api").await;
    assert_eq!(s, 401);
    let res = client
        .get(hub.url("/secrets/api"))
        .header("Authorization", "Bearer est_s_nope")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 404);
    // Revoke kills the pull; delete kills the secret.
    let res = client
        .delete(hub.url("/secrets/api/token"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let res = client
        .get(hub.url("/secrets/api"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 404);
    let res = client.delete(hub.url("/secrets/api")).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let (s, _) = get(&hub, "/secrets/api").await;
    assert_eq!(s, 401); // Auth runs before existence: no token, no answer.
    let (s, v) = put(&hub, "/secrets/BAD", json!({"env": "K=V"})).await;
    assert_eq!(s, 400, "{v}");
}

#[tokio::test]
async fn balances_roundtrip_and_gates() {
    let hub = Hub::spawn("flows-balances");
    let client = reqwest::Client::new();
    let (s, v) = put(
        &hub,
        "/balances/openai",
        json!({"amount": "$12.34", "currency": "USD", "note": "team"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["balance"]["label"], "openai");
    assert_eq!(v["balance"]["amount"], "$12.34");
    let (_, v) = get(&hub, "/balances").await;
    assert_eq!(v["balances"].as_array().unwrap().len(), 1);
    let (s, v) = put(&hub, "/balances/BAD", json!({"amount": "1"})).await;
    assert_eq!(s, 400, "{v}");
    let (s, v) = put(&hub, "/balances/openai", json!({"amount": 42})).await;
    assert_eq!(s, 400, "{v}");
    let res = client
        .delete(hub.url("/balances/openai"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let res = client
        .delete(hub.url("/balances/openai"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 404);
}

#[tokio::test]
async fn agents_roundtrip_and_gates() {
    let hub = Hub::spawn("flows-agents");
    let client = reqwest::Client::new();
    let (s, v) = put(
        &hub,
        "/agents/w7:p1P",
        json!({"status": "working", "title": "Release run-up", "cwd": "/Users/x/iOS"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["agent"]["pane"], "w7:p1P");
    assert_eq!(v["agent"]["stale"], false);
    let (s, v) = put(&hub, "/agents/w7:p1W", json!({"status": "blocked"})).await;
    assert_eq!(s, 200, "{v}");
    let (_, v) = get(&hub, "/agents").await;
    let agents = v["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 2);
    assert_eq!(agents[0]["pane"], "w7:p1P"); // Working sorts first.
    let (_, v) = get(&hub, "/agents/w7:p1W").await;
    assert_eq!(v["agent"]["status"], "blocked");
    // Space/tab/output ride along, and omitted ones keep.
    let (s, v) = put(
        &hub,
        "/agents/w7:p1P",
        json!({"status": "working", "space": "iOS", "tab": "1", "output": "compiling…"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["agent"]["space"], "iOS");
    let (s, v) = put(&hub, "/agents/w7:p1P", json!({"status": "idle"})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["agent"]["output"], "compiling…");
    assert_eq!(v["agent"]["tab"], "1");
    let (s, v) = put(
        &hub,
        "/agents/w7:p1P",
        json!({"status": "idle", "output": 42}),
    )
    .await;
    assert_eq!(s, 400, "{v}");
    let (s, v) = put(&hub, "/agents/w7:p1P", json!({"status": "napping"})).await;
    assert_eq!(s, 400, "{v}");
    let (s, v) = put(&hub, "/agents/w7:p1P", json!({"status": 42})).await;
    assert_eq!(s, 400, "{v}");
    let (s, v) = put(&hub, "/agents/w7@p1P", json!({"status": "working"})).await;
    assert_eq!(s, 400, "{v}");
    let res = client
        .delete(hub.url("/agents/w7:p1P"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let (s, _) = get(&hub, "/agents/w7:p1P").await;
    assert_eq!(s, 404);
}

#[tokio::test]
async fn results_flip_and_queue_flip_notifications() {
    let hub = Hub::spawn("flows-flip");
    post(
        &hub,
        "/checks",
        json!({"name": "api", "owner": "e", "type": "api", "target": "https://x.test/h"}),
    )
    .await;
    let (s, v) = post(
        &hub,
        "/results",
        json!({"check": "api", "ok": false, "reason": "refused"}),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(v["flipped"], false);
    let (_, v) = post(
        &hub,
        "/results",
        json!({"check": "api", "ok": false, "reason": "refused"}),
    )
    .await;
    assert_eq!(v["flipped"], false);
    let (_, v) = post(
        &hub,
        "/results",
        json!({"check": "api", "ok": true, "code": 200}),
    )
    .await;
    assert_eq!(v["flipped"], true);
    let (_, v) = get(&hub, "/checks/api").await;
    assert_eq!(v["check"]["state"]["status"], "up");
    assert_eq!(v["check"]["state"]["fails"], 0);
    let (_, v) = get(&hub, "/notifications?limit=10").await;
    let notes = v["notifications"].as_array().unwrap();
    assert_eq!(notes.len(), 1);
    assert!(notes.iter().all(|n| n["topic"] == "health.flip"));
    let (_, v) = get(&hub, "/checks/api/results?limit=2").await;
    assert_eq!(v["results"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn results_carry_optional_numeric_values() {
    let hub = Hub::spawn("flows-values");
    post(
        &hub,
        "/checks",
        json!({"name": "disk", "owner": "e", "type": "heartbeat", "target": "vps2"}),
    )
    .await;
    // A value rides the result row and the check's last state.
    let (s, _) = post(
        &hub,
        "/results",
        json!({"check": "disk", "ok": true, "reason": "disk 42% used", "value": 42.0}),
    )
    .await;
    assert_eq!(s, 200);
    let (_, v) = get(&hub, "/checks/disk/results?limit=5").await;
    assert_eq!(v["results"][0]["value"], 42.0);
    let (_, v) = get(&hub, "/checks/disk").await;
    assert_eq!(v["check"]["state"]["last_value"], 42.0);
    // Absent means no value — and it clears the last state.
    let (s, _) = post(&hub, "/results", json!({"check": "disk", "ok": true})).await;
    assert_eq!(s, 200);
    let (_, v) = get(&hub, "/checks/disk").await;
    assert!(v["check"]["state"]["last_value"].is_null(), "{v}");
    // Explicit null also means no value.
    let (s, _) = post(
        &hub,
        "/results",
        json!({"check": "disk", "ok": true, "value": null}),
    )
    .await;
    assert_eq!(s, 200);
    // Non-numeric refuses.
    let (s, v) = post(
        &hub,
        "/results",
        json!({"check": "disk", "ok": true, "value": "42"}),
    )
    .await;
    assert_eq!(s, 400, "{v}");
    // Overflow exponents parse to inf — still a 400.
    let raw = r#"{"check":"disk","ok":true,"value":1e999}"#;
    let res = reqwest::Client::new()
        .post(hub.url("/results"))
        .header("content-type", "application/json")
        .body(raw.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 400);
    // `since` floors by probe time: backfill an old row, then fence it out.
    post(
        &hub,
        "/results",
        json!({"check": "disk", "ok": true, "ts": 100}),
    )
    .await;
    let (_, v) = get(&hub, "/checks/disk/results?limit=10").await;
    assert!(
        v["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["ts"] == 100)
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (_, v) = get(&hub, &format!("/checks/disk/results?limit=10&since={now}")).await;
    assert!(
        v["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["ts"].as_u64().unwrap_or(0) >= now)
    );
}

#[tokio::test]
async fn balance_values_page_on_thresholds() {
    let hub = Hub::spawn("flows-balance");
    let (s, _) = post(
        &hub,
        "/checks",
        json!({"name": "balance-openrouter", "owner": "sys", "type": "balance",
               "target": "openrouter", "warn_below": 5.0, "crit_below": 1.0}),
    )
    .await;
    assert_eq!(s, 201);
    // Below crit pages even though the reporter said ok.
    let (s, v) = post(
        &hub,
        "/results",
        json!({"check": "balance-openrouter", "ok": true, "reason": "OpenRouter $0.50", "value": 0.5}),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(v["flipped"], false); // birth is quiet
    let (_, v) = get(&hub, "/checks/balance-openrouter").await;
    assert_eq!(v["check"]["state"]["status"], "down");
    assert_eq!(v["check"]["state"]["last_value"], 0.5);
    // Between crit and warn: up, soft line in the copy.
    post(
        &hub,
        "/results",
        json!({"check": "balance-openrouter", "ok": true, "reason": "OpenRouter $3.00", "value": 3.0}),
    )
    .await;
    let (_, v) = get(&hub, "/checks/balance-openrouter").await;
    assert_eq!(v["check"]["state"]["status"], "up");
    assert!(
        v["check"]["state"]["last_reason"]
            .as_str()
            .unwrap()
            .contains("(below warn 5)")
    );
}

#[tokio::test]
async fn projects_metadata_rollup_and_icon() {
    let hub = Hub::spawn("flows-projects");
    // Metadata upsert (create), then read back with an empty rollup.
    let (s, v) = put(
        &hub,
        "/projects/daysleft",
        json!({"group": "ios", "name": "Days Left", "bundle_id": "com.estifie.daysleft"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["project"]["slug"], "daysleft");
    assert_eq!(v["project"]["state"], "unknown");
    assert_eq!(v["project"]["health"]["total"], 0);
    // Bad slug refuses.
    let (s, _) = put(
        &hub,
        "/projects/Bad Slug!",
        json!({"group": "ios", "name": "x"}),
    )
    .await;
    assert_eq!(s, 400);
    // A check owned by the slug rolls into the project.
    post(
        &hub,
        "/checks",
        json!({"name": "ios-daysleft-privacy", "owner": "daysleft", "type": "url", "target": "https://x.test/p"}),
    )
    .await;
    post(
        &hub,
        "/results",
        json!({"check": "ios-daysleft-privacy", "ok": true}),
    )
    .await;
    let (_, v) = get(&hub, "/projects/daysleft").await;
    assert_eq!(v["project"]["state"], "up");
    assert_eq!(v["project"]["health"]["up"], 1);
    let (_, v) = get(&hub, "/projects").await;
    assert_eq!(v["projects"].as_array().unwrap().len(), 1);
    // Icon round-trip: PNG bytes in, base64 envelope out.
    let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    png.extend([0u8; 100]);
    let client = reqwest::Client::new();
    let res = client
        .put(hub.url("/projects/daysleft/icon"))
        .header("content-type", "image/png")
        .body(png.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let (_, v) = get(&hub, "/projects/daysleft").await;
    assert_eq!(v["project"]["has_icon"], true);
    assert!(!v["project"]["icon_sha256"].as_str().unwrap().is_empty());
    let (_, v) = get(&hub, "/projects/daysleft/icon").await;
    assert_eq!(v["bytes"], 108);
    // Non-PNG refuses; missing icon 404s.
    let res = client
        .put(hub.url("/projects/daysleft/icon"))
        .header("content-type", "image/png")
        .body(b"nope".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 400);
    let (s, _) = get(&hub, "/projects/ghost/icon").await;
    assert_eq!(s, 404);
}

#[tokio::test]
async fn heartbeat_staleness_reads_down() {
    let hub = Hub::spawn("flows-beat");
    post(
        &hub,
        "/checks",
        json!({"name": "nightly", "owner": "e", "type": "heartbeat", "target": "nightly-job",
               "every_secs": 10, "miss_after_secs": 30}),
    )
    .await;
    // A fresh beat: the prober's next tick records it up.
    let (s, _) = post(&hub, "/heartbeats", json!({"check": "nightly"})).await;
    assert_eq!(s, 200);
    let (_, v) = get(&hub, "/checks/nightly").await;
    assert!(v["check"]["state"]["last_beat"].as_u64().unwrap() > 0);
    // An ancient beat: the next tick records it down.
    let old = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 3600;
    post(&hub, "/heartbeats", json!({"check": "nightly", "ts": old})).await;
    let mut down = false;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let (_, v) = get(&hub, "/checks/nightly").await;
        if v["check"]["state"]["status"] == "down" {
            down = true;
            break;
        }
    }
    assert!(down, "the prober never marked the stale heartbeat down");
}

#[tokio::test]
async fn approvals_decide_once_and_expire_live() {
    let hub = Hub::spawn("flows-approvals");
    let (_, v) = post(&hub, "/approvals", json!({"title": "deploy?"})).await;
    let id = v["approval"]["id"].as_i64().unwrap();
    assert_eq!(v["approval"]["state"], "pending");
    let (s, v) = post(
        &hub,
        &format!("/approvals/{id}/decision"),
        json!({"approve": true, "by": "e"}),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(v["approval"]["state"], "approved");
    let (s, _) = post(
        &hub,
        &format!("/approvals/{id}/decision"),
        json!({"approve": false}),
    )
    .await;
    assert_eq!(s, 400);
    let (_, v) = get(&hub, "/approvals?state=approved").await;
    assert_eq!(v["approvals"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn notify_queues_for_drivers() {
    let hub = Hub::spawn("flows-notify");
    let (s, v) = post(&hub, "/notify", json!({"title": "hello", "topic": "test"})).await;
    assert_eq!(s, 201);
    assert_eq!(v["notification"]["delivered"], false);
    let (s, _) = post(&hub, "/notify", json!({"title": ""})).await;
    assert_eq!(s, 400);
}

#[tokio::test]
async fn notify_test_route_needs_apns_and_queues_nothing() {
    let hub = Hub::spawn("flows-notify-test");
    post(&hub, "/devices", json!({"name": "phone"})).await;
    // No key, no ids: 4xx with the fix, and the queue stays empty.
    let (s, v) = post(&hub, "/notify/test", json!({"to": "phone"})).await;
    assert_eq!(s, 400, "{v}");
    assert_eq!(v["ok"], false);
    assert!(v["error"].as_str().unwrap().contains("APNs"), "{v}");
    let (s, v) = post(&hub, "/notify/test", json!({})).await;
    assert_eq!(s, 400, "{v}");
    let (_, v) = get(&hub, "/notifications?limit=50").await;
    assert!(v["notifications"].as_array().unwrap().is_empty(), "{v}");
}

#[tokio::test]
async fn notify_send_queues_without_apns() {
    // Unconfigured hubs queue exactly as before: the row lands,
    // undelivered, and reads back.
    let hub = Hub::spawn("flows-notify-queue");
    let (s, v) = post(
        &hub,
        "/notify",
        json!({"title": "hello", "topic": "test", "to": "phone"}),
    )
    .await;
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["notification"]["delivered"], false);
    let id = v["notification"]["id"].as_i64().unwrap();
    let (_, v) = get(&hub, "/notifications?limit=50").await;
    let notes = v["notifications"].as_array().unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0]["id"], id);
    assert_eq!(notes[0]["delivered"], false);
}

#[tokio::test]
async fn approval_request_emits_a_queue_row() {
    let hub = Hub::spawn("flows-approval-row");
    let (s, v) = post(&hub, "/approvals", json!({"title": "deploy?"})).await;
    assert_eq!(s, 201, "{v}");
    let (_, v) = get(&hub, "/notifications?limit=50").await;
    let notes = v["notifications"].as_array().unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0]["topic"], "approval.requested");
    assert_eq!(notes[0]["title"], "deploy?");
}

#[tokio::test]
async fn notifications_filters_narrow_the_queue() {
    let hub = Hub::spawn("flows-notif-filters");
    let (_, a) = post(&hub, "/notify", json!({"title": "one", "to": "phone"})).await;
    post(&hub, "/notify", json!({"title": "two", "to": "watch"})).await;
    let (_, c) = post(&hub, "/notify", json!({"title": "three"})).await;
    let aid = a["notification"]["id"].as_i64().unwrap();
    let cid = c["notification"]["id"].as_i64().unwrap();
    let (_, v) = get(&hub, "/notifications?to=phone").await;
    let notes = v["notifications"].as_array().unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0]["title"], "one");
    let (_, v) = get(&hub, &format!("/notifications?since_id={aid}")).await;
    let notes = v["notifications"].as_array().unwrap();
    assert_eq!(notes.len(), 2);
    assert_eq!(notes[0]["id"], cid);
    let (_, v) = get(&hub, &format!("/notifications?to=phone&since_id={aid}")).await;
    assert!(v["notifications"].as_array().unwrap().is_empty(), "{v}");
    let (s, v) = get(&hub, "/notifications?since_id=nope").await;
    assert_eq!(s, 400, "{v}");
    assert_eq!(v["ok"], false);
}

#[tokio::test]
async fn apns_ids_roundtrip_present_sets_absent_keeps() {
    let hub = Hub::spawn("flows-apns-ids");
    let (s, v) = put(
        &hub,
        "/apns",
        json!({"key_id": "KEY1", "team_id": "TEAM1", "topic": "com.x"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["apns"]["key_id"], "KEY1");
    assert_eq!(v["apns"]["team_id"], "TEAM1");
    assert_eq!(v["apns"]["topic"], "com.x");
    // Absent keeps: only the topic moves.
    let (s, v) = put(&hub, "/apns", json!({"topic": "com.y"})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["apns"]["key_id"], "KEY1");
    assert_eq!(v["apns"]["topic"], "com.y");
    // Null clears back to unset.
    let (s, v) = put(&hub, "/apns", json!({"key_id": Value::Null})).await;
    assert_eq!(s, 200, "{v}");
    assert!(v["apns"]["key_id"].is_null(), "{v}");
    assert_eq!(v["apns"]["team_id"], "TEAM1");
    // Wrong types and over-long ids refuse.
    let (s, _) = put(&hub, "/apns", json!({"key_id": 7})).await;
    assert_eq!(s, 400);
    let (s, _) = put(&hub, "/apns", json!({"key_id": "k".repeat(65)})).await;
    assert_eq!(s, 400);
}

#[test]
fn devices_set_keeps_absent_push_state() {
    // The push-state wipe, pinned shut: `devices set` with no flags
    // (or one flag) keeps what it was not told.
    let hub = Hub::spawn("flows-set-keep");
    let run = |args: &[&str]| {
        let out = hub.cli(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    run(&["devices", "add", "phone"]);
    run(&[
        "devices",
        "set",
        "phone",
        "--apns",
        "tok",
        "--apns-env",
        "production",
    ]);
    run(&["devices", "set", "phone"]);
    let out = hub
        .cli(&["devices", "show", "phone", "--json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["device"]["apns_token"], "tok", "{v}");
    assert_eq!(v["device"]["apns_env"], "production", "{v}");
    run(&["devices", "set", "phone", "--apns-env", "development"]);
    let out = hub
        .cli(&["devices", "show", "phone", "--json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["device"]["apns_token"], "tok", "{v}");
    assert_eq!(v["device"]["apns_env"], "development", "{v}");
}

#[test]
fn apns_and_notify_test_twins_work_against_a_live_hub() {
    let hub = Hub::spawn("flows-apns-cli");
    let run = |args: &[&str]| {
        let out = hub.cli(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let text = run(&[
        "apns",
        "set",
        "--key-id",
        "K",
        "--team-id",
        "T",
        "--topic",
        "com.x",
    ]);
    assert!(text.contains("key_id:  K"), "{text}");
    assert!(text.contains("topic:   com.x"), "{text}");
    let text = run(&["apns", "set", "--topic", "com.y"]);
    assert!(text.contains("key_id:  K"), "{text}");
    assert!(text.contains("topic:   com.y"), "{text}");
    // Unconfigured: the twin fails with the hub's APNs line.
    run(&["devices", "add", "phone"]);
    let out = hub
        .cli(&["notify", "test", "--to", "phone", "--title", "hi"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(stderr.to_lowercase().contains("apns"), "{stderr}");
    // And the twin requires its device.
    let out = hub.cli(&["notify", "test"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    // Filtered list twins.
    run(&["notify", "send", "--title", "one", "--to", "phone"]);
    run(&["notify", "send", "--title", "two", "--to", "watch"]);
    let text = run(&["notifications", "list", "--to", "phone"]);
    assert!(text.contains("one"), "{text}");
    assert!(!text.contains("two"), "{text}");
    let text = run(&["notifications", "list", "--since", "1"]);
    assert!(text.contains("two"), "{text}");
    assert!(!text.contains("one"), "{text}");
}

#[test]
fn every_cli_twin_works_against_a_live_hub() {
    let hub = Hub::spawn("flows-cli");
    let run = |args: &[&str]| {
        let out = hub.cli(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    assert!(run(&["devices", "add", "phone"]).contains("added device phone"));
    assert!(run(&["devices", "list"]).contains("phone"));
    assert!(run(&["devices", "show", "phone"]).contains("phone"));
    assert!(
        run(&[
            "checks",
            "add",
            "site",
            "--type",
            "url",
            "--target",
            "https://example.com",
            "--owner",
            "e"
        ])
        .contains("added check site")
    );
    assert!(run(&["checks", "list"]).contains("site"));
    assert!(run(&["checks", "show", "site"]).contains("example.com"));
    assert!(
        run(&[
            "checks",
            "set",
            "site",
            "--type",
            "url",
            "--target",
            "https://example.org",
            "--owner",
            "e"
        ])
        .contains("updated check site")
    );
    assert!(
        run(&[
            "results", "report", "--check", "site", "--fail", "--reason", "x"
        ])
        .contains("recorded")
    );
    assert!(run(&["results", "list", "--check", "site"]).contains("FAIL"));
    assert!(
        run(&[
            "results", "report", "--check", "site", "--ok", "--value", "42.5"
        ])
        .contains("recorded")
    );
    let out = hub
        .cli(&["checks", "show", "site", "--json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["check"]["state"]["last_value"], 42.5, "{v}");
    // Non-finite refuses at usage level.
    let out = hub
        .cli(&[
            "results", "report", "--check", "site", "--ok", "--value", "nan",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(run(&["heartbeats", "beat", "--check", "site"]).contains("beat site"));
    let text = run(&["approvals", "request", "--title", "ship?"]);
    assert!(text.contains("approval #"), "{text}");
    let id = text
        .split('#')
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    assert!(run(&["approvals", "list"]).contains("ship?"));
    assert!(run(&["approvals", "show", &id]).contains("pending"));
    assert!(run(&["approvals", "decide", &id, "--approve", "--by", "e"]).contains("approved"));
    assert!(run(&["notify", "send", "--title", "hi"]).contains("notified #"));
    assert!(run(&["notifications", "list"]).contains("hi"));
    assert!(run(&["checks", "delete", "site", "--yes"]).contains("deleted check site"));
    assert!(run(&["devices", "revoke", "phone", "--yes"]).contains("revoked device phone"));
    let out = hub.cli(&["checks", "show", "site"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn devices_cli_twins_register_and_update_push_state() {
    let hub = Hub::spawn("flows-device-cli");
    let run = |args: &[&str]| {
        let out = hub.cli(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    // add (registry) then set (push state), then show.
    assert!(run(&["devices", "add", "tablet"]).contains("added device tablet"));
    assert!(
        run(&[
            "devices",
            "set",
            "tablet",
            "--apns",
            "tok",
            "--apns-env",
            "development"
        ])
        .contains("updated device tablet")
    );
    assert!(run(&["devices", "list"]).contains("tablet"));
    assert!(run(&["devices", "show", "tablet"]).contains("apns:"));
    assert!(run(&["devices", "revoke", "tablet", "--yes"]).contains("revoked device tablet"));
}
