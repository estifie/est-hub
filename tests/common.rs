//! Shared harness: spawn `serve` on an ephemeral port, read the
//! address it prints, kill it on drop. The address read is bounded
//! (15s) so a broken binary fails the test instead of hanging it.

// Harness, not product: no rustdoc, and not every helper is used by
// every suite that includes this file.
#![allow(missing_docs)]
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub struct Hub {
    child: Child,
    pub addr: String,
    pub dir: std::path::PathBuf,
}

impl Hub {
    pub fn spawn(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("est-hub-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_est-hub"));
        cmd.args(["serve", "--port", "0", "--db"])
            .arg(dir.join("hub.sqlite"));
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut out = out;
            let _ = out.read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("the hub did not print its address");
        let value: serde_json::Value = serde_json::from_str(&line).expect("not JSON");
        assert_eq!(value["ok"], true);
        let addr = value["listening"].as_str().unwrap().to_string();
        Hub { child, addr, dir }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// The CLI pointed at this hub.
    pub fn cli(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_est-hub"));
        cmd.args(args)
            .arg("--hub")
            .arg(format!("http://{}", self.addr));
        cmd
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
