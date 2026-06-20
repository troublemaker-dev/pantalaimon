#![allow(dead_code)]

use std::path::Path;

use anyhow::Result;
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
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
    pool: SqlitePool,
}

impl PanStore {
    pub async fn new(data_dir: &Path) -> Result<Self> {
        let db_path = data_dir.join("pan.db");
        debug!("Opening pan.db at {}", db_path.display());

        let opts = SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(true)
            .foreign_keys(true);

        let pool = SqlitePool::connect_with(opts).await?;

        let store = Self { pool };
        store.create_tables().await?;
        let ver = store.schema_version().await.unwrap_or(0);
        debug!("pan.db schema version {ver}");
        Ok(store)
    }

    pub async fn schema_version(&self) -> Result<i64> {
        sqlx::query_scalar("SELECT version FROM schema_version LIMIT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    async fn create_tables(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            );
            -- Insert version 1 only on first creation; no-op on subsequent starts.
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
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Servers / users
    // -----------------------------------------------------------------------

    async fn get_or_create_server(&self, server_name: &str) -> Result<i64> {
        sqlx::query_scalar(
            "INSERT INTO servers(name) VALUES(?) ON CONFLICT(name) DO UPDATE SET name=name RETURNING id",
        )
        .bind(server_name)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    async fn get_or_create_server_user(
        &self,
        server_id: i64,
        user_id: &str,
    ) -> Result<i64> {
        sqlx::query_scalar(
            "INSERT INTO serverusers(user_id, server_id) VALUES(?,?)
             ON CONFLICT(user_id, server_id) DO UPDATE SET user_id=user_id
             RETURNING id",
        )
        .bind(user_id)
        .bind(server_id)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn save_server_user(&self, server_name: &str, user_id: &str) -> Result<()> {
        let server_id = self.get_or_create_server(server_name).await?;
        self.get_or_create_server_user(server_id, user_id).await?;
        Ok(())
    }

    pub async fn load_users(&self, server_name: &str) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT su.user_id FROM serverusers su
             JOIN servers s ON s.id = su.server_id
             WHERE s.name = ?",
        )
        .bind(server_name)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(u,)| u).collect())
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
        sqlx::query(
            "INSERT INTO accesstokens(user_id, device_id, token) VALUES(?,?,?)
             ON CONFLICT(user_id, device_id) DO UPDATE SET token=excluded.token",
        )
        .bind(user_id)
        .bind(device_id)
        .bind(token)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn load_access_token(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT token FROM accesstokens WHERE user_id=? AND device_id=?",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(t,)| t))
    }

    pub async fn load_all_tokens(&self) -> Result<Vec<(String, String, String)>> {
        let rows: Vec<(String, String, String)> =
            sqlx::query_as("SELECT user_id, device_id, token FROM accesstokens")
                .fetch_all(&self.pool)
                .await?;
        Ok(rows)
    }

    /// Load (user_id, device_id, db_token) for every user belonging to
    /// `server_name`.  The caller should prefer keyring over `db_token` when
    /// `UseKeyring = true`.
    pub async fn load_session_tokens(
        &self,
        server_name: &str,
    ) -> Result<Vec<(String, String, String)>> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT at.user_id, at.device_id, at.token
             FROM accesstokens at
             JOIN serverusers su ON su.user_id = at.user_id
             JOIN servers s ON s.id = su.server_id
             WHERE s.name = ?",
        )
        .bind(server_name)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
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

        sqlx::query(
            "INSERT INTO pansynctokens(server_user_id, token) VALUES(?,?)
             ON CONFLICT(server_user_id) DO UPDATE SET token=excluded.token",
        )
        .bind(su_id)
        .bind(token)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn load_sync_token(
        &self,
        server_name: &str,
        user_id: &str,
    ) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT pst.token FROM pansynctokens pst
             JOIN serverusers su ON su.id = pst.server_user_id
             JOIN servers s ON s.id = su.server_id
             WHERE s.name = ? AND su.user_id = ?",
        )
        .bind(server_name)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(t,)| t))
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

        sqlx::query(
            "INSERT OR REPLACE INTO panfetchertasks(server_user_id, room_id, token)
             VALUES(?,?,?)",
        )
        .bind(su_id)
        .bind(&task.room_id)
        .bind(&task.token)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn load_fetcher_tasks(
        &self,
        server_name: &str,
        user_id: &str,
    ) -> Result<Vec<FetchTask>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT pft.room_id, pft.token FROM panfetchertasks pft
             JOIN serverusers su ON su.id = pft.server_user_id
             JOIN servers s ON s.id = su.server_id
             WHERE s.name = ? AND su.user_id = ?",
        )
        .bind(server_name)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(r, t)| FetchTask { room_id: r, token: t }).collect())
    }

    pub async fn delete_fetcher_task(
        &self,
        server_name: &str,
        user_id: &str,
        task: &FetchTask,
    ) -> Result<()> {
        sqlx::query(
            "DELETE FROM panfetchertasks
             WHERE server_user_id = (
                 SELECT su.id FROM serverusers su
                 JOIN servers s ON s.id = su.server_id
                 WHERE s.name = ? AND su.user_id = ?
             ) AND room_id = ? AND token = ?",
        )
        .bind(server_name)
        .bind(user_id)
        .bind(&task.room_id)
        .bind(&task.token)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Media info (encrypted upload keys)
    // -----------------------------------------------------------------------

    pub async fn save_media(
        &self,
        server_name: &str,
        media: &MediaInfo,
    ) -> Result<()> {
        let server_id = self.get_or_create_server(server_name).await?;

        sqlx::query(
            "INSERT OR IGNORE INTO panmediainfo
             (server_id, mxc_server, mxc_path, key_data, iv, hashes)
             VALUES(?,?,?,?,?,?)",
        )
        .bind(server_id)
        .bind(&media.mxc_server)
        .bind(&media.mxc_path)
        .bind(media.key.to_string())
        .bind(&media.iv)
        .bind(media.hashes.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn load_media(
        &self,
        server_name: &str,
        mxc_server: &str,
        mxc_path: &str,
    ) -> Result<Option<MediaInfo>> {
        let row: Option<(String, String, String, String, String)> = sqlx::query_as(
            "SELECT pmi.mxc_server, pmi.mxc_path, pmi.key_data, pmi.iv, pmi.hashes
             FROM panmediainfo pmi
             JOIN servers s ON s.id = pmi.server_id
             WHERE s.name = ? AND pmi.mxc_server = ? AND pmi.mxc_path = ?",
        )
        .bind(server_name)
        .bind(mxc_server)
        .bind(mxc_path)
        .fetch_optional(&self.pool)
        .await?;

        match row {
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

        sqlx::query(
            "INSERT OR IGNORE INTO panuploadinfo(server_id, content_uri, filename, mimetype)
             VALUES(?,?,?,?)",
        )
        .bind(server_id)
        .bind(content_uri)
        .bind(filename)
        .bind(mimetype)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn load_upload(
        &self,
        server_name: &str,
        content_uri: &str,
    ) -> Result<Option<UploadInfo>> {
        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT pui.content_uri, pui.filename, pui.mimetype
             FROM panuploadinfo pui
             JOIN servers s ON s.id = pui.server_id
             WHERE s.name = ? AND pui.content_uri = ?",
        )
        .bind(server_name)
        .bind(content_uri)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(c, f, m)| UploadInfo { content_uri: c, filename: f, mimetype: m }))
    }
}
