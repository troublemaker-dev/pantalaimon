#![allow(dead_code)]

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use tokio::task::spawn_blocking;
use tracing::debug;

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MediaInfo {
    pub mxc_server: String,
    pub mxc_path: String,
    pub key: serde_json::Value,
    pub iv: String,
    pub hashes: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct UploadInfo {
    pub content_uri: String,
    pub filename: String,
    pub mimetype: String,
}

#[derive(Debug, Clone)]
pub struct FetchTask {
    pub room_id: String,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub user_id: String,
    pub access_token: String,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// SQLite-backed persistence for pantalaimon.
///
/// Table names intentionally match the peewee-generated names from the Python
/// version so that existing pan.db files can be opened without migration.
pub struct PanStore {
    conn: Arc<Mutex<Connection>>,
}

impl PanStore {
    pub async fn new(data_dir: &Path) -> Result<Self> {
        let db_path = data_dir.join("pan.db");
        debug!("Opening pan.db at {}", db_path.display());
        let db_path_str = db_path.to_string_lossy().into_owned();

        let conn = spawn_blocking(move || -> Result<Connection> {
            let conn = Connection::open(&db_path_str)
                .with_context(|| format!("Cannot open {db_path_str}"))?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
            Ok(conn)
        })
        .await
        .context("spawn_blocking panicked")??;

        let store = Self { conn: Arc::new(Mutex::new(conn)) };
        store.create_tables().await?;
        let ver = store.schema_version().await.unwrap_or(0);
        debug!("pan.db schema version {ver}");
        Ok(store)
    }

    pub async fn schema_version(&self) -> Result<i64> {
        let conn = self.conn.clone();
        spawn_blocking(move || -> Result<i64> {
            let db = conn.lock().unwrap();
            let ver = db
                .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| r.get(0))
                .context("schema_version query")?;
            Ok(ver)
        })
        .await
        .context("spawn_blocking panicked")?
    }

    async fn create_tables(&self) -> Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || -> Result<()> {
            let db = conn.lock().unwrap();
            db.execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER NOT NULL
                );
                INSERT INTO schema_version (version)
                SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);

                CREATE TABLE IF NOT EXISTS servers (
                    id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT    NOT NULL UNIQUE
                );

                CREATE TABLE IF NOT EXISTS serverusers (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id   TEXT    NOT NULL,
                    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                    UNIQUE(user_id, server_id)
                );

                CREATE TABLE IF NOT EXISTS accesstokens (
                    user_id   TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    token     TEXT NOT NULL,
                    PRIMARY KEY (user_id, device_id)
                );

                CREATE TABLE IF NOT EXISTS pansynctokens (
                    server_user_id INTEGER NOT NULL PRIMARY KEY
                        REFERENCES serverusers(id) ON DELETE CASCADE,
                    token TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS panfetchertasks (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_user_id INTEGER NOT NULL
                        REFERENCES serverusers(id) ON DELETE CASCADE,
                    room_id        TEXT NOT NULL,
                    token          TEXT NOT NULL,
                    UNIQUE(server_user_id, room_id, token)
                );

                CREATE TABLE IF NOT EXISTS panmediainfo (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id  INTEGER NOT NULL
                        REFERENCES servers(id) ON DELETE CASCADE,
                    mxc_server TEXT NOT NULL,
                    mxc_path   TEXT NOT NULL,
                    key_data   TEXT NOT NULL,
                    iv         TEXT NOT NULL,
                    hashes     TEXT NOT NULL,
                    UNIQUE(server_id, mxc_server, mxc_path)
                );

                CREATE TABLE IF NOT EXISTS panuploadinfo (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id   INTEGER NOT NULL
                        REFERENCES servers(id) ON DELETE CASCADE,
                    content_uri TEXT NOT NULL,
                    filename    TEXT NOT NULL,
                    mimetype    TEXT NOT NULL,
                    UNIQUE(server_id, content_uri)
                );",
            )?;
            Ok(())
        })
        .await
        .context("spawn_blocking panicked")?
    }

    // -----------------------------------------------------------------------
    // Servers / users
    // -----------------------------------------------------------------------

    async fn get_or_create_server(&self, server_name: &str) -> Result<i64> {
        let conn = self.conn.clone();
        let server_name = server_name.to_owned();
        spawn_blocking(move || -> Result<i64> {
            let db = conn.lock().unwrap();
            db.execute(
                "INSERT INTO servers(name) VALUES(?1) ON CONFLICT(name) DO UPDATE SET name=name",
                params![server_name],
            )?;
            let id = db.query_row(
                "SELECT id FROM servers WHERE name=?1",
                params![server_name],
                |r| r.get(0),
            )?;
            Ok(id)
        })
        .await
        .context("spawn_blocking panicked")?
    }

    async fn get_or_create_server_user(&self, server_id: i64, user_id: &str) -> Result<i64> {
        let conn = self.conn.clone();
        let user_id = user_id.to_owned();
        spawn_blocking(move || -> Result<i64> {
            let db = conn.lock().unwrap();
            db.execute(
                "INSERT INTO serverusers(user_id, server_id) VALUES(?1, ?2)
                 ON CONFLICT(user_id, server_id) DO UPDATE SET user_id=user_id",
                params![user_id, server_id],
            )?;
            let id = db.query_row(
                "SELECT id FROM serverusers WHERE user_id=?1 AND server_id=?2",
                params![user_id, server_id],
                |r| r.get(0),
            )?;
            Ok(id)
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn save_server_user(&self, server_name: &str, user_id: &str) -> Result<()> {
        let server_id = self.get_or_create_server(server_name).await?;
        self.get_or_create_server_user(server_id, user_id).await?;
        Ok(())
    }

    pub async fn load_users(&self, server_name: &str) -> Result<Vec<String>> {
        let conn = self.conn.clone();
        let server_name = server_name.to_owned();
        spawn_blocking(move || -> Result<Vec<String>> {
            let db = conn.lock().unwrap();
            let mut stmt = db.prepare(
                "SELECT su.user_id FROM serverusers su
                 JOIN servers s ON s.id = su.server_id
                 WHERE s.name = ?1",
            )?;
            let rows = stmt.query_map(params![server_name], |r| r.get::<_, String>(0))?;
            rows.map(|r| r.map_err(anyhow::Error::from)).collect()
        })
        .await
        .context("spawn_blocking panicked")?
    }

    // -----------------------------------------------------------------------
    // Access tokens
    // -----------------------------------------------------------------------

    pub async fn save_access_token(
        &self,
        user_id: &str,
        device_id: &str,
        token: &str,
    ) -> Result<()> {
        let conn = self.conn.clone();
        let (user_id, device_id, token) =
            (user_id.to_owned(), device_id.to_owned(), token.to_owned());
        spawn_blocking(move || -> Result<()> {
            let db = conn.lock().unwrap();
            db.execute(
                "INSERT INTO accesstokens(user_id, device_id, token) VALUES(?1, ?2, ?3)
                 ON CONFLICT(user_id, device_id) DO UPDATE SET token=excluded.token",
                params![user_id, device_id, token],
            )?;
            Ok(())
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn load_access_token(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<String>> {
        let conn = self.conn.clone();
        let (user_id, device_id) = (user_id.to_owned(), device_id.to_owned());
        spawn_blocking(move || -> Result<Option<String>> {
            let db = conn.lock().unwrap();
            let token = db
                .query_row(
                    "SELECT token FROM accesstokens WHERE user_id=?1 AND device_id=?2",
                    params![user_id, device_id],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(token)
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn load_all_tokens(&self) -> Result<Vec<(String, String, String)>> {
        let conn = self.conn.clone();
        spawn_blocking(move || -> Result<Vec<(String, String, String)>> {
            let db = conn.lock().unwrap();
            let mut stmt =
                db.prepare("SELECT user_id, device_id, token FROM accesstokens")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            rows.map(|r| r.map_err(anyhow::Error::from)).collect()
        })
        .await
        .context("spawn_blocking panicked")?
    }

    /// Load (user_id, device_id, db_token) for every user belonging to
    /// `server_name`.  The caller should prefer keyring over `db_token` when
    /// `UseKeyring = true`.
    pub async fn load_session_tokens(
        &self,
        server_name: &str,
    ) -> Result<Vec<(String, String, String)>> {
        let conn = self.conn.clone();
        let server_name = server_name.to_owned();
        spawn_blocking(move || -> Result<Vec<(String, String, String)>> {
            let db = conn.lock().unwrap();
            let mut stmt = db.prepare(
                "SELECT at.user_id, at.device_id, at.token
                 FROM accesstokens at
                 JOIN serverusers su ON su.user_id = at.user_id
                 JOIN servers s ON s.id = su.server_id
                 WHERE s.name = ?1",
            )?;
            let rows = stmt.query_map(params![server_name], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            rows.map(|r| r.map_err(anyhow::Error::from)).collect()
        })
        .await
        .context("spawn_blocking panicked")?
    }

    // -----------------------------------------------------------------------
    // Sync tokens
    // -----------------------------------------------------------------------

    pub async fn save_sync_token(
        &self,
        server_name: &str,
        user_id: &str,
        token: &str,
    ) -> Result<()> {
        let server_id = self.get_or_create_server(server_name).await?;
        let su_id = self.get_or_create_server_user(server_id, user_id).await?;
        let conn = self.conn.clone();
        let token = token.to_owned();
        spawn_blocking(move || -> Result<()> {
            let db = conn.lock().unwrap();
            db.execute(
                "INSERT INTO pansynctokens(server_user_id, token) VALUES(?1, ?2)
                 ON CONFLICT(server_user_id) DO UPDATE SET token=excluded.token",
                params![su_id, token],
            )?;
            Ok(())
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn load_sync_token(
        &self,
        server_name: &str,
        user_id: &str,
    ) -> Result<Option<String>> {
        let conn = self.conn.clone();
        let (server_name, user_id) = (server_name.to_owned(), user_id.to_owned());
        spawn_blocking(move || -> Result<Option<String>> {
            let db = conn.lock().unwrap();
            let token = db
                .query_row(
                    "SELECT pst.token FROM pansynctokens pst
                     JOIN serverusers su ON su.id = pst.server_user_id
                     JOIN servers s ON s.id = su.server_id
                     WHERE s.name = ?1 AND su.user_id = ?2",
                    params![server_name, user_id],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(token)
        })
        .await
        .context("spawn_blocking panicked")?
    }

    // -----------------------------------------------------------------------
    // Fetcher tasks
    // -----------------------------------------------------------------------

    pub async fn save_fetcher_task(
        &self,
        server_name: &str,
        user_id: &str,
        task: &FetchTask,
    ) -> Result<()> {
        let server_id = self.get_or_create_server(server_name).await?;
        let su_id = self.get_or_create_server_user(server_id, user_id).await?;
        let conn = self.conn.clone();
        let (room_id, token) = (task.room_id.clone(), task.token.clone());
        spawn_blocking(move || -> Result<()> {
            let db = conn.lock().unwrap();
            db.execute(
                "INSERT OR REPLACE INTO panfetchertasks(server_user_id, room_id, token)
                 VALUES(?1, ?2, ?3)",
                params![su_id, room_id, token],
            )?;
            Ok(())
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn load_fetcher_tasks(
        &self,
        server_name: &str,
        user_id: &str,
    ) -> Result<Vec<FetchTask>> {
        let conn = self.conn.clone();
        let (server_name, user_id) = (server_name.to_owned(), user_id.to_owned());
        spawn_blocking(move || -> Result<Vec<FetchTask>> {
            let db = conn.lock().unwrap();
            let mut stmt = db.prepare(
                "SELECT pft.room_id, pft.token FROM panfetchertasks pft
                 JOIN serverusers su ON su.id = pft.server_user_id
                 JOIN servers s ON s.id = su.server_id
                 WHERE s.name = ?1 AND su.user_id = ?2",
            )?;
            let rows = stmt.query_map(params![server_name, user_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?;
            rows.map(|r| {
                r.map(|(room_id, token)| FetchTask { room_id, token })
                    .map_err(anyhow::Error::from)
            })
            .collect()
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn delete_fetcher_task(
        &self,
        server_name: &str,
        user_id: &str,
        task: &FetchTask,
    ) -> Result<()> {
        let conn = self.conn.clone();
        let (server_name, user_id, room_id, token) = (
            server_name.to_owned(),
            user_id.to_owned(),
            task.room_id.clone(),
            task.token.clone(),
        );
        spawn_blocking(move || -> Result<()> {
            let db = conn.lock().unwrap();
            db.execute(
                "DELETE FROM panfetchertasks
                 WHERE server_user_id = (
                     SELECT su.id FROM serverusers su
                     JOIN servers s ON s.id = su.server_id
                     WHERE s.name = ?1 AND su.user_id = ?2
                 ) AND room_id = ?3 AND token = ?4",
                params![server_name, user_id, room_id, token],
            )?;
            Ok(())
        })
        .await
        .context("spawn_blocking panicked")?
    }

    // -----------------------------------------------------------------------
    // Media info (encrypted upload keys)
    // -----------------------------------------------------------------------

    pub async fn save_media(&self, server_name: &str, media: &MediaInfo) -> Result<()> {
        let server_id = self.get_or_create_server(server_name).await?;
        let conn = self.conn.clone();
        let (mxc_server, mxc_path, key_str, iv, hashes_str) = (
            media.mxc_server.clone(),
            media.mxc_path.clone(),
            media.key.to_string(),
            media.iv.clone(),
            media.hashes.to_string(),
        );
        spawn_blocking(move || -> Result<()> {
            let db = conn.lock().unwrap();
            db.execute(
                "INSERT OR IGNORE INTO panmediainfo
                 (server_id, mxc_server, mxc_path, key_data, iv, hashes)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                params![server_id, mxc_server, mxc_path, key_str, iv, hashes_str],
            )?;
            Ok(())
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn load_media(
        &self,
        server_name: &str,
        mxc_server: &str,
        mxc_path: &str,
    ) -> Result<Option<MediaInfo>> {
        let conn = self.conn.clone();
        let (server_name, mxc_server, mxc_path) =
            (server_name.to_owned(), mxc_server.to_owned(), mxc_path.to_owned());
        let raw: Option<(String, String, String, String, String)> = spawn_blocking(
            move || -> Result<Option<(String, String, String, String, String)>> {
                let db = conn.lock().unwrap();
                let row = db
                    .query_row(
                        "SELECT pmi.mxc_server, pmi.mxc_path, pmi.key_data, pmi.iv, pmi.hashes
                         FROM panmediainfo pmi
                         JOIN servers s ON s.id = pmi.server_id
                         WHERE s.name = ?1 AND pmi.mxc_server = ?2 AND pmi.mxc_path = ?3",
                        params![server_name, mxc_server, mxc_path],
                        |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, String>(1)?,
                                r.get::<_, String>(2)?,
                                r.get::<_, String>(3)?,
                                r.get::<_, String>(4)?,
                            ))
                        },
                    )
                    .optional()?;
                Ok(row)
            },
        )
        .await
        .context("spawn_blocking panicked")??;

        match raw {
            None => Ok(None),
            Some((ms, mp, key_str, iv, hashes_str)) => Ok(Some(MediaInfo {
                mxc_server: ms,
                mxc_path: mp,
                key: serde_json::from_str(&key_str)?,
                iv,
                hashes: serde_json::from_str(&hashes_str)?,
            })),
        }
    }

    // -----------------------------------------------------------------------
    // Upload info (original filename / mimetype for encrypted files)
    // -----------------------------------------------------------------------

    pub async fn save_upload(
        &self,
        server_name: &str,
        content_uri: &str,
        filename: &str,
        mimetype: &str,
    ) -> Result<()> {
        let server_id = self.get_or_create_server(server_name).await?;
        let conn = self.conn.clone();
        let (content_uri, filename, mimetype) =
            (content_uri.to_owned(), filename.to_owned(), mimetype.to_owned());
        spawn_blocking(move || -> Result<()> {
            let db = conn.lock().unwrap();
            db.execute(
                "INSERT OR IGNORE INTO panuploadinfo(server_id, content_uri, filename, mimetype)
                 VALUES(?1, ?2, ?3, ?4)",
                params![server_id, content_uri, filename, mimetype],
            )?;
            Ok(())
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn load_upload(
        &self,
        server_name: &str,
        content_uri: &str,
    ) -> Result<Option<UploadInfo>> {
        let conn = self.conn.clone();
        let (server_name, content_uri) = (server_name.to_owned(), content_uri.to_owned());
        spawn_blocking(move || -> Result<Option<UploadInfo>> {
            let db = conn.lock().unwrap();
            let row = db
                .query_row(
                    "SELECT pui.content_uri, pui.filename, pui.mimetype
                     FROM panuploadinfo pui
                     JOIN servers s ON s.id = pui.server_id
                     WHERE s.name = ?1 AND pui.content_uri = ?2",
                    params![server_name, content_uri],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?;
            Ok(row.map(|(c, f, m)| UploadInfo { content_uri: c, filename: f, mimetype: m }))
        })
        .await
        .context("spawn_blocking panicked")?
    }
}
