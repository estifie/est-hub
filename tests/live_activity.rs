//! Part 4 over real HTTP: the Live Activity feed routes, the token
//! registry, disable-means-stop, the tailnet-only test route, and every
//! CLI twin. Pushes themselves converge to nothing here (no APNs key),
//! so these suites pin the routes, the validation, and the local state
//! machine; the wire bytes live under `live::tests` against a mock.

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

async fn delete(hub: &Hub, path: &str) -> (u16, Value) {
    let res = reqwest::Client::new()
        .delete(hub.url(path))
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap())
}

async fn device(hub: &Hub, name: &str) {
    let (s, v) = post(hub, "/devices", json!({"name": name})).await;
    assert_eq!(s, 201, "{v}");
}

async fn check(hub: &Hub, name: &str) {
    let (s, v) = post(
        hub,
        "/checks",
        json!({"name": name, "owner": "e", "type": "url", "target": "https://example.com"}),
    )
    .await;
    assert_eq!(s, 201, "{v}");
}

#[tokio::test]
async fn live_config_roundtrips_and_merges() {
    let hub = Hub::spawn("live-config");
    device(&hub, "phone").await;
    check(&hub, "site").await;
    check(&hub, "blog").await;
    // Fresh devices read off, all checks, defaults.
    let (s, v) = get(&hub, "/devices/phone/live-activity").await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["device"], "phone");
    assert_eq!(v["config"]["enabled"], false);
    assert!(v["config"]["checks"].is_null(), "{v}");
    assert_eq!(v["config"]["min_severity"], "low");
    assert_eq!(v["config"]["approvals"], true);
    assert_eq!(v["config"]["alert_on_down"], true);
    assert_eq!(v["pts_configured"], false);
    assert_eq!(v["status"], "off");
    assert!(v["tokens"].as_array().unwrap().is_empty());
    // Unknown devices stay 404 on both verbs.
    let (s, _) = get(&hub, "/devices/ghost/live-activity").await;
    assert_eq!(s, 404);
    let (s, _) = put(&hub, "/devices/ghost/live-activity", json!({})).await;
    assert_eq!(s, 404);
    // Full write: every field lands, PTS reads back as a bit only.
    let (s, v) = put(
        &hub,
        "/devices/phone/live-activity",
        json!({
            "enabled": true, "pts_token": "ab12", "checks": ["site", "blog"],
            "min_severity": "high", "approvals": false, "alert_on_down": false,
        }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["config"]["enabled"], true);
    assert_eq!(v["config"]["checks"], json!(["blog", "site"]));
    assert_eq!(v["config"]["min_severity"], "high");
    assert_eq!(v["config"]["approvals"], false);
    assert_eq!(v["config"]["alert_on_down"], false);
    assert_eq!(v["pts_configured"], true);
    assert_eq!(v["status"], "pending"); // enabled, no activity yet
    assert!(!v.to_string().contains("ab12"), "the PTS token leaked: {v}");
    // Empty PUT keeps everything (the CLI's omit-absent depends on it).
    let (s, v) = put(&hub, "/devices/phone/live-activity", json!({})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["config"]["enabled"], true);
    assert_eq!(v["config"]["checks"], json!(["blog", "site"]));
    assert_eq!(v["pts_configured"], true);
    // `checks: "all"` (and null) reset to the whole fleet.
    let (s, v) = put(
        &hub,
        "/devices/phone/live-activity",
        json!({"checks": "all"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert!(v["config"]["checks"].is_null(), "{v}");
    let (s, v) = put(
        &hub,
        "/devices/phone/live-activity",
        json!({"checks": ["site"], "pts_token": Value::Null}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["config"]["checks"], json!(["site"]));
    assert_eq!(v["pts_configured"], false);
}

#[tokio::test]
async fn live_config_validation_refuses_loud() {
    let hub = Hub::spawn("live-validate");
    device(&hub, "phone").await;
    check(&hub, "site").await;
    // Bad severity, bad bools, bad PTS, bad checks shape: all 400.
    for (body, why) in [
        (json!({"min_severity": "urgent"}), "severity"),
        (json!({"enabled": "yes"}), "enabled"),
        (json!({"approvals": 1}), "approvals"),
        (json!({"alert_on_down": "no"}), "alert"),
        (json!({"pts_token": "not-hex!"}), "pts"),
        (json!({"pts_token": "ab".repeat(300)}), "pts-long"),
        (json!({"pts_token": 7}), "pts-type"),
        (json!({"checks": "some"}), "checks-str"),
        (json!({"checks": [7]}), "checks-type"),
        (json!({"checks": ["Nope!"]}), "checks-name"),
        (json!({"checks": [""]}), "checks-empty"),
    ] {
        let (s, v) = put(&hub, "/devices/phone/live-activity", body).await;
        assert_eq!(s, 400, "{why}: {v}");
        assert_eq!(v["ok"], false);
    }
    // Well-formed but unknown checks read 404, naming the check.
    let (s, v) = put(
        &hub,
        "/devices/phone/live-activity",
        json!({"checks": ["site", "ghost"]}),
    )
    .await;
    assert_eq!(s, 404, "{v}");
    assert!(v["error"].as_str().unwrap().contains("ghost"), "{v}");
    // Nothing above moved the config: still the default.
    let (_, v) = get(&hub, "/devices/phone/live-activity").await;
    assert_eq!(v["config"]["enabled"], false);
    assert!(v["config"]["checks"].is_null(), "{v}");
    assert_eq!(v["pts_configured"], false);
}

#[tokio::test]
async fn labeled_tokens_ride_beside_the_status_pointer() {
    let hub = Hub::spawn("live-labels");
    device(&hub, "phone").await;
    // A labeled (incident) report: 201 with the label echoed, but the
    // device's activity pointer stays untouched.
    let (s, v) = post(
        &hub,
        "/devices/phone/live-activity/tokens",
        json!({"activity_id": "act-i", "token": "cc33", "label": "incident:site"}),
    )
    .await;
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["label"], "incident:site");
    let (_, v) = get(&hub, "/devices/phone/live-activity").await;
    assert!(v["activity_id"].is_null(), "{v}");
    assert_eq!(v["tokens"].as_array().unwrap().len(), 1);
    assert_eq!(v["tokens"][0]["label"], "incident:site");
    // A status report still moves the pointer, beside the incident row.
    let (s, _) = post(
        &hub,
        "/devices/phone/live-activity/tokens",
        json!({"activity_id": "act-s", "token": "dd44"}),
    )
    .await;
    assert_eq!(s, 201);
    let (_, v) = get(&hub, "/devices/phone/live-activity").await;
    assert_eq!(v["activity_id"], "act-s");
    assert_eq!(v["tokens"].as_array().unwrap().len(), 2);
    // Overlong labels refuse.
    let (s, v) = post(
        &hub,
        "/devices/phone/live-activity/tokens",
        json!({"activity_id": "act-x", "token": "ee55", "label": "l".repeat(129)}),
    )
    .await;
    assert_eq!(s, 400, "{v}");
}

#[tokio::test]
async fn live_tokens_upsert_and_delete_by_owner() {
    let hub = Hub::spawn("live-tokens");
    device(&hub, "phone").await;
    device(&hub, "watch").await;
    // Upsert: 201, and the device points at the activity.
    let (s, v) = post(
        &hub,
        "/devices/phone/live-activity/tokens",
        json!({"activity_id": "act-1", "token": "aa11"}),
    )
    .await;
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["activity_id"], "act-1");
    assert_eq!(v["device"], "phone");
    assert!(!v.to_string().contains("aa11"), "token value leaked: {v}");
    let (_, v) = get(&hub, "/devices/phone/live-activity").await;
    assert_eq!(v["activity_id"], "act-1");
    assert!(v["started_ts"].as_u64().unwrap() > 1_700_000_000);
    assert_eq!(v["tokens"].as_array().unwrap().len(), 1);
    assert_eq!(v["tokens"][0]["activity_id"], "act-1");
    assert!(!v.to_string().contains("aa11"), "token value leaked: {v}");
    // Re-report refreshes the stamp; the id list, not values, serves.
    let (s, v) = post(
        &hub,
        "/devices/phone/live-activity/tokens",
        json!({"activity_id": "act-1", "token": "bb22"}),
    )
    .await;
    assert_eq!(s, 201, "{v}");
    let (_, v) = get(&hub, "/devices/phone/live-activity").await;
    assert_eq!(v["tokens"].as_array().unwrap().len(), 1);
    // Validation: bad ids, bad tokens, unknown devices.
    for (path, body, want) in [
        (
            "/devices/phone/live-activity/tokens",
            json!({"activity_id": "", "token": "aa"}),
            400,
        ),
        (
            "/devices/phone/live-activity/tokens",
            json!({"activity_id": "act-2", "token": "nope!"}),
            400,
        ),
        (
            "/devices/phone/live-activity/tokens",
            json!({"activity_id": "act-2"}),
            400,
        ),
        (
            "/devices/ghost/live-activity/tokens",
            json!({"activity_id": "act-2", "token": "aa"}),
            404,
        ),
    ] {
        let (s, v) = post(&hub, path, body).await;
        assert_eq!(s, want, "{path}: {v}");
    }
    // Another device's id is not this device's to delete.
    let (s, _) = delete(&hub, "/devices/watch/live-activity/tokens/act-1").await;
    assert_eq!(s, 404);
    let (s, _) = delete(&hub, "/devices/phone/live-activity/tokens/nope").await;
    assert_eq!(s, 404);
    let (s, _) = delete(&hub, "/devices/ghost/live-activity/tokens/act-1").await;
    assert_eq!(s, 404);
    // Delete: the row dies and the device unpoints.
    let (s, v) = delete(&hub, "/devices/phone/live-activity/tokens/act-1").await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["deleted"], "act-1");
    let (_, v) = get(&hub, "/devices/phone/live-activity").await;
    assert!(v["activity_id"].is_null(), "{v}");
    assert!(v["tokens"].as_array().unwrap().is_empty());
    let (s, _) = delete(&hub, "/devices/phone/live-activity/tokens/act-1").await;
    assert_eq!(s, 404);
}

#[tokio::test]
async fn live_disable_ends_and_stops() {
    let hub = Hub::spawn("live-disable");
    device(&hub, "phone").await;
    check(&hub, "site").await;
    put(
        &hub,
        "/devices/phone/live-activity",
        json!({"enabled": true, "pts_token": "ab12"}),
    )
    .await;
    post(
        &hub,
        "/devices/phone/live-activity/tokens",
        json!({"activity_id": "act-1", "token": "aa11"}),
    )
    .await;
    let (_, v) = get(&hub, "/devices/phone/live-activity").await;
    assert_eq!(v["status"], "active");
    // Disable: off, unpointed, no tokens — the stop holds unconfigured.
    let (s, v) = put(
        &hub,
        "/devices/phone/live-activity",
        json!({"enabled": false}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "off");
    assert!(v["activity_id"].is_null(), "{v}");
    assert!(v["tokens"].as_array().unwrap().is_empty());
    // The PTS token survives (only the card stops, not the feed's keys).
    assert_eq!(v["pts_configured"], true);
    // Re-enable: pending, waiting on the app to report again.
    let (s, v) = put(
        &hub,
        "/devices/phone/live-activity",
        json!({"enabled": true}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "pending");
}

#[tokio::test]
async fn live_test_route_needs_apns_and_queues_nothing() {
    let hub = Hub::spawn("live-test");
    device(&hub, "phone").await;
    // No key, no ids: 4xx with the fix, and the queue stays empty.
    let (s, v) = post(
        &hub,
        "/live-activities/test",
        json!({"to": "phone", "event": "update"}),
    )
    .await;
    assert_eq!(s, 400, "{v}");
    assert_eq!(v["ok"], false);
    assert!(v["error"].as_str().unwrap().contains("APNs"), "{v}");
    // Bad events and missing/unknown devices refuse before Apple matters.
    let (s, v) = post(
        &hub,
        "/live-activities/test",
        json!({"to": "phone", "event": "nudge"}),
    )
    .await;
    assert_eq!(s, 400, "{v}");
    let (s, v) = post(&hub, "/live-activities/test", json!({"event": "update"})).await;
    assert_eq!(s, 400, "{v}");
    let (s, v) = post(
        &hub,
        "/live-activities/test",
        json!({"to": "ghost", "event": "end"}),
    )
    .await;
    assert_eq!(s, 404, "{v}");
    let (s, v) = post(&hub, "/live-activities/test", json!({})).await;
    assert_eq!(s, 400, "{v}");
    let (_, v) = get(&hub, "/notifications?limit=50").await;
    assert!(v["notifications"].as_array().unwrap().is_empty(), "{v}");
}

#[tokio::test]
async fn apns_topic_roundtrips_present_sets_absent_keeps() {
    let hub = Hub::spawn("live-topic");
    device(&hub, "phone").await;
    // Fresh devices read null, beside the configured bit.
    let (_, v) = get(&hub, "/devices/phone").await;
    assert!(v["device"]["apns_topic"].is_null(), "{v}");
    // Present sets (with the token and env alongside).
    let (s, v) = put(
        &hub,
        "/devices/phone",
        json!({"apns_token": "tok", "apns_env": "production", "apns_topic": "com.owner.sidecar"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["device"]["apns_topic"], "com.owner.sidecar");
    // Absent keeps: the token moves alone.
    let (s, v) = put(&hub, "/devices/phone", json!({"apns_token": "tok2"})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["device"]["apns_topic"], "com.owner.sidecar");
    assert_eq!(v["device"]["apns_token"], "tok2");
    // Null clears back to unset; the rest stays.
    let (s, v) = put(&hub, "/devices/phone", json!({"apns_topic": Value::Null})).await;
    assert_eq!(s, 200, "{v}");
    assert!(v["device"]["apns_topic"].is_null(), "{v}");
    assert_eq!(v["device"]["apns_token"], "tok2");
    // Wrong types and over-long topics refuse.
    let (s, _) = put(&hub, "/devices/phone", json!({"apns_topic": 7})).await;
    assert_eq!(s, 400);
    let (s, _) = put(
        &hub,
        "/devices/phone",
        json!({"apns_topic": "t".repeat(257)}),
    )
    .await;
    assert_eq!(s, 400);
}

#[test]
fn live_cli_twins_drive_the_routes() {
    let hub = Hub::spawn("live-cli");
    let run = |args: &[&str]| {
        let out = hub.cli(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let run_json = |args: &[&str]| {
        let mut full = args.to_vec();
        full.push("--json");
        let out = run(&full);
        serde_json::from_str::<Value>(&out).unwrap()
    };
    run(&["devices", "add", "phone"]);
    run(&[
        "checks",
        "add",
        "site",
        "--type",
        "url",
        "--target",
        "https://example.com",
        "--owner",
        "e",
    ]);
    // set: every flag lands; show reads it back.
    let text = run(&[
        "devices",
        "live",
        "set",
        "phone",
        "--enable",
        "--pts",
        "ab12",
        "--checks",
        "site",
        "--min-severity",
        "high",
        "--no-approvals",
        "--no-alert-on-down",
    ]);
    assert!(text.contains("pending"), "{text}");
    let v = run_json(&["devices", "live", "show", "phone"]);
    assert_eq!(v["config"]["enabled"], true);
    assert_eq!(v["config"]["checks"], json!(["site"]));
    assert_eq!(v["config"]["min_severity"], "high");
    assert_eq!(v["config"]["approvals"], false);
    assert_eq!(v["config"]["alert_on_down"], false);
    assert_eq!(v["pts_configured"], true);
    // `--checks all` resets; bare set keeps.
    run(&["devices", "live", "set", "phone", "--checks", "all"]);
    let v = run_json(&["devices", "live", "show", "phone"]);
    assert!(v["config"]["checks"].is_null(), "{v}");
    assert_eq!(v["config"]["enabled"], true);
    run(&["devices", "live", "set", "phone"]);
    let v = run_json(&["devices", "live", "show", "phone"]);
    assert_eq!(v["config"]["enabled"], true);
    // token + untoken roundtrip.
    let text = run(&[
        "devices",
        "live",
        "token",
        "phone",
        "--activity",
        "act-1",
        "--token",
        "aa11",
    ]);
    assert!(text.contains("act-1"), "{text}");
    let v = run_json(&["devices", "live", "show", "phone"]);
    assert_eq!(v["status"], "active");
    let text = run(&["devices", "live", "untoken", "phone", "act-1"]);
    assert!(text.contains("act-1"), "{text}");
    // disable ends; devices set carries the topic flag through.
    run(&["devices", "live", "set", "phone", "--disable"]);
    let v = run_json(&["devices", "live", "show", "phone"]);
    assert_eq!(v["status"], "off");
    run(&[
        "devices",
        "set",
        "phone",
        "--apns-topic",
        "com.owner.sidecar",
    ]);
    let v = run_json(&["devices", "show", "phone"]);
    assert_eq!(v["device"]["apns_topic"], "com.owner.sidecar");
    // live test without APNs fails loud on stderr (exit 1, not silent).
    let out = hub
        .cli(&["live", "test", "--to", "phone", "--event", "update"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("APNs"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
