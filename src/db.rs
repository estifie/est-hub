//! One SQLite file: checks, results, heartbeats, devices, approvals.
//! Opened WAL for readers-don't-block-writers; the directory is `0700`,
//! the file `0600` (SQLite honors the process umask on creation, so the
//! dir carries the secrecy).

use std::path::Path;

/// Opening the store failed: why, in one human line.
#[derive(Debug)]
pub enum Error {
    /// The directory could not be made or entered.
    Io(String),
    /// SQLite itself refused.
    Sql(rusqlite::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(why) => write!(f, "cannot ready the store dir: {why}"),
            Error::Sql(e) => write!(f, "sqlite refused: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Open (creating) the store: dirs made `0700`, WAL on, the `meta`
/// table present. Every later slice adds its own tables here.
pub fn open(path: &Path) -> Result<rusqlite::Connection, Error> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| Error::Io(format!("{}: {e}", parent.display())))?;
    }
    let conn = rusqlite::Connection::open(path).map_err(Error::Sql)?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(Error::Sql)?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        .map_err(Error::Sql)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_wal_and_roundtrips_meta() {
        let dir = std::env::temp_dir().join(format!("est-hub-db-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let conn = open(&dir.join("hub.sqlite")).unwrap();
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')", [])
            .unwrap();
        let back: String = conn
            .query_row("SELECT value FROM meta WHERE key = 'k'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(back, "v");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
