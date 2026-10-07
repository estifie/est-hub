//! Small shared helpers: where the hub's key files live, plus the hex
//! and randomness primitives the rest of the crate builds on.

use std::path::{Path, PathBuf};

/// Where key material lives: next to the SQLite db (dir is `0700`).
/// Only the APNs sender key (`apns.p8`) is stored here.
pub fn key_dir(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Lowercase hex, for hashes and throttle keys.
pub fn hex(bytes: &[u8]) -> String {
    const NIB: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(NIB[(b >> 4) as usize] as char);
        out.push(NIB[(b & 0xf) as usize] as char);
    }
    out
}

/// Fill with randomness, or say why the platform refused.
pub fn random_bytes(dest: &mut [u8]) -> Result<(), String> {
    getrandom::fill(dest).map_err(|e| format!("no randomness: {e}"))
}
