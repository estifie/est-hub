//! est-hub: one API on the tailnet for the whole ecosystem.
//!
//! Phones, desktops, daemons, scripts, and agents all talk to the same
//! routes ([`api`]) over the same versioned JSON envelopes; state lives
//! in one SQLite file ([`db`]); shapes and validation live in [`model`];
//! the hub's own prober is [`probe`]; `checks sync` reads the ecosystem
//! repos in [`sync`]. The hub holds operational state
//! only — it never sees the vault master key.

pub mod api;
pub mod apns;
pub mod db;
pub mod live;
pub mod model;
pub mod probe;
pub mod sync;
pub mod util;

/// The running crate version, reported by `/ping`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
