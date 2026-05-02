//! Token jar — local SQLite store for saved tokens.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

/// One row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JarEntry {
    pub id: i64,
    pub label: String,
    pub token: String,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub created_at: String,
}

/// SQLite-backed token jar.
#[derive(Debug)]
pub struct Jar {
    conn: Connection,
}

impl Jar {
    /// Open the default jar at `~/.local/share/jwt-tui/jar.db` (or platform
    /// equivalent), creating the schema if needed.
    pub fn open_default() -> anyhow::Result<Self> {
        let path = Self::default_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Self::open(&path)
    }

    /// Open a jar at an arbitrary path.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                token TEXT NOT NULL,
                notes TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS tags (
                token_id INTEGER NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
                tag TEXT NOT NULL,
                PRIMARY KEY (token_id, tag)
            );
            CREATE INDEX IF NOT EXISTS idx_tags_tag ON tags(tag);
            ",
        )?;
        Ok(Self { conn })
    }

    /// Insert a token, returning its new id.
    pub fn insert(
        &mut self,
        label: &str,
        token: &str,
        tags: &[String],
        notes: Option<&str>,
    ) -> anyhow::Result<i64> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO tokens (label, token, notes) VALUES (?1, ?2, ?3)",
            params![label, token, notes],
        )?;
        let id = tx.last_insert_rowid();
        for t in tags {
            tx.execute(
                "INSERT OR IGNORE INTO tags (token_id, tag) VALUES (?1, ?2)",
                params![id, t],
            )?;
        }
        tx.commit()?;
        Ok(id)
    }

    /// Remove a row by id; returns whether something was deleted.
    pub fn remove(&self, id: i64) -> anyhow::Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM tokens WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    /// Look up a single entry.
    pub fn get(&self, id: i64) -> anyhow::Result<Option<JarEntry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, label, token, notes, created_at FROM tokens WHERE id = ?1")?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let label: String = row.get(1)?;
            let token: String = row.get(2)?;
            let notes: Option<String> = row.get(3)?;
            let created_at: String = row.get(4)?;
            let tags = self.tags_for(id)?;
            return Ok(Some(JarEntry {
                id,
                label,
                token,
                tags,
                notes,
                created_at,
            }));
        }
        Ok(None)
    }

    /// All entries, newest first.
    pub fn list(&self) -> anyhow::Result<Vec<JarEntry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, label, token, notes, created_at FROM tokens ORDER BY id DESC")?;
        let mut entries: Vec<JarEntry> = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            entries.push(JarEntry {
                id,
                label: row.get(1)?,
                token: row.get(2)?,
                notes: row.get(3)?,
                created_at: row.get(4)?,
                tags: Vec::new(),
            });
        }
        for e in &mut entries {
            e.tags = self.tags_for(e.id)?;
        }
        Ok(entries)
    }

    fn tags_for(&self, id: i64) -> anyhow::Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT tag FROM tags WHERE token_id = ?1 ORDER BY tag")?;
        let tags: Vec<String> = stmt
            .query_map(params![id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(tags)
    }

    /// Where the default jar file lives. Honors `JWT_TUI_DATA_DIR` for tests
    /// and ad-hoc redirection.
    pub fn default_path() -> anyhow::Result<PathBuf> {
        if let Some(custom) = std::env::var_os("JWT_TUI_DATA_DIR") {
            return Ok(PathBuf::from(custom).join("jar.db"));
        }
        let dirs = directories::ProjectDirs::from("dev", "jwt-tui", "jwt-tui")
            .ok_or_else(|| anyhow::anyhow!("could not resolve project data dir"))?;
        Ok(dirs.data_local_dir().join("jar.db"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut jar = Jar::open(&dir.path().join("jar.db")).unwrap();
        let id = jar
            .insert(
                "test",
                "eyJh.bGc.iJ",
                &["pentest".into(), "prod".into()],
                Some("notes"),
            )
            .unwrap();
        let got = jar.get(id).unwrap().unwrap();
        assert_eq!(got.label, "test");
        assert_eq!(got.tags, vec!["pentest", "prod"]);
        assert_eq!(got.notes.as_deref(), Some("notes"));
    }

    #[test]
    fn list_orders_by_id_desc() {
        let dir = tempfile::tempdir().unwrap();
        let mut jar = Jar::open(&dir.path().join("jar.db")).unwrap();
        jar.insert("a", "a.b.c", &[], None).unwrap();
        jar.insert("b", "a.b.c", &[], None).unwrap();
        let list = jar.list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].label, "b");
    }

    #[test]
    fn remove_returns_false_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let jar = Jar::open(&dir.path().join("jar.db")).unwrap();
        assert!(!jar.remove(99).unwrap());
    }
}
