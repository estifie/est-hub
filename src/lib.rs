//! est-hub: one API on the tailnet for the whole ecosystem.
//!
//! Phones, desktops, daemons, scripts, and agents all talk to the same
//! routes ([`api`]) over the same versioned JSON envelopes; state lives
//! in one SQLite file ([`db`]). The hub holds operational state only —
//! it never sees the vault master key.

pub mod api;
pub mod db;

/// The running crate version, reported by `/ping`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
