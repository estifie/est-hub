//! Liveness and the unknown-route shape.

mod common;

use common::Hub;

#[tokio::test]
async fn ping_answers_the_versioned_envelope() {
    let hub = Hub::spawn("ping");
    let res = reqwest::get(hub.url("/ping")).await.unwrap();
    assert!(res.status().is_success());
    let value: serde_json::Value = res.json().await.unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["v"], 1);
    assert_eq!(value["name"], "est-hub");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn unknown_routes_are_404_envelopes() {
    let hub = Hub::spawn("404");
    let res = reqwest::get(hub.url("/nope")).await.unwrap();
    assert_eq!(res.status().as_u16(), 404);
    let value: serde_json::Value = res.json().await.unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["v"], 1);
}

#[test]
fn ping_command_reports_liveness() {
    let hub = Hub::spawn("cli");
    let out = hub.cli(&["ping"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.starts_with("hub ok (est-hub "), "{text}");
}
