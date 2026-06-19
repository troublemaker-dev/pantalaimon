#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use anyhow::{bail, Context};
use configparser::ini::Ini;
use tracing::Level;
use url::Url;

#[derive(Debug, thiserror::Error)]
#[error("config error: {0}")]
pub struct PanConfigError(pub String);

/// Per-server proxy configuration — mirrors Python's ServerConfig.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub name: String,
    pub homeserver: Url,
    pub listen_address: IpAddr,
    pub listen_port: u16,
    pub proxy: Option<Url>,
    pub ssl: bool,
    pub ignore_verification: bool,
    pub use_keyring: bool,
    pub search_requests: bool,
    pub index_encrypted_only: bool,
    pub indexing_batch_size: u32,
    /// Delay between history-fetch batches (seconds).
    pub history_fetch_delay: f64,
    pub drop_old_keys: bool,
}

#[derive(Debug, Clone)]
pub struct PanConfig {
    pub log_level: Level,
    pub debug_encryption: bool,
    pub notifications: bool,
    pub servers: indexmap::IndexMap<String, ServerConfig>,
}

// `url` is not in the workspace yet — add it, or parse URLs manually.
// For now we re-export via a thin newtype so callers stay stable.
pub fn read_config(path: &Path) -> anyhow::Result<PanConfig> {
    let mut ini = Ini::new_cs();
    ini.load(path)
        .map_err(|e| anyhow::anyhow!("Failed to read config {}: {}", path.display(), e))?;

    // Helper: get a key, trying the named section first then "Default".
    let get = |section: &str, key: &str| -> Option<String> {
        ini.get(section, key).or_else(|| ini.get("Default", key))
    };

    let get_bool = |section: &str, key: &str| -> anyhow::Result<Option<bool>> {
        match get(section, key) {
            None => Ok(None),
            Some(v) => match v.to_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => Ok(Some(true)),
                "false" | "no" | "off" | "0" => Ok(Some(false)),
                other => bail!("Invalid boolean '{}' for key '{}'", other, key),
            },
        }
    };

    let get_u16 = |section: &str, key: &str| -> anyhow::Result<Option<u16>> {
        match get(section, key) {
            None => Ok(None),
            Some(v) => Ok(Some(v.trim().parse::<u16>().with_context(|| {
                format!("Invalid integer '{}' for key '{}'", v, key)
            })?)),
        }
    };

    let get_u32 = |section: &str, key: &str| -> anyhow::Result<Option<u32>> {
        match get(section, key) {
            None => Ok(None),
            Some(v) => Ok(Some(v.trim().parse::<u32>().with_context(|| {
                format!("Invalid integer '{}' for key '{}'", v, key)
            })?)),
        }
    };

    // Global defaults from [Default] section.
    let log_level = match get("Default", "LogLevel")
        .unwrap_or_else(|| "warning".into())
        .to_lowercase()
        .as_str()
    {
        "error" => Level::ERROR,
        "warning" => Level::WARN,
        "info" => Level::INFO,
        "debug" => Level::DEBUG,
        _ => Level::WARN,
    };

    let debug_encryption = get_bool("Default", "DebugEncryption")?.unwrap_or(false);
    let notifications = get_bool("Default", "Notifications")?.unwrap_or(true);

    let mut servers = indexmap::IndexMap::new();

    for section in ini.sections() {
        if section == "Default" {
            continue;
        }

        let homeserver_str = get(&section, "Homeserver")
            .ok_or_else(|| anyhow::anyhow!("[{}] Homeserver is required", section))?;
        let homeserver = Url::parse(&homeserver_str)
            .with_context(|| format!("[{}] Invalid Homeserver URL", section))?;

        let listen_address: IpAddr = match get(&section, "ListenAddress")
            .unwrap_or_else(|| "localhost".into())
            .as_str()
        {
            "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
            addr => addr.parse().with_context(|| {
                format!("[{}] Invalid ListenAddress", section)
            })?,
        };

        let listen_port = get_u16(&section, "ListenPort")?.unwrap_or(8009);

        let proxy = get(&section, "Proxy")
            .map(|v| Url::parse(&v))
            .transpose()
            .with_context(|| format!("[{}] Invalid Proxy URL", section))?;

        let ssl = get_bool(&section, "SSL")?.unwrap_or(true);
        let ignore_verification = get_bool(&section, "IgnoreVerification")?.unwrap_or(false);
        let use_keyring = get_bool(&section, "UseKeyring")?.unwrap_or(true);
        let search_requests = get_bool(&section, "SearchRequests")?.unwrap_or(false);
        let index_encrypted_only = get_bool(&section, "IndexEncryptedOnly")?.unwrap_or(true);
        let drop_old_keys = get_bool(&section, "DropOldKeys")?.unwrap_or(false);

        let indexing_batch_size = get_u32(&section, "IndexingBatchSize")?.unwrap_or(100);
        if !(1 < indexing_batch_size && indexing_batch_size <= 1000) {
            bail!(
                "[{}] IndexingBatchSize must be between 1 and 1000",
                section
            );
        }

        let history_fetch_delay_ms = get_u32(&section, "HistoryFetchDelay")?.unwrap_or(3000);
        if !(100 < history_fetch_delay_ms && history_fetch_delay_ms <= 10000) {
            bail!(
                "[{}] HistoryFetchDelay must be between 100 and 10000 ms",
                section
            );
        }

        servers.insert(
            section.clone(),
            ServerConfig {
                name: section,
                homeserver,
                listen_address,
                listen_port,
                proxy,
                ssl,
                ignore_verification,
                use_keyring,
                search_requests,
                index_encrypted_only,
                indexing_batch_size,
                history_fetch_delay: history_fetch_delay_ms as f64 / 1000.0,
                drop_old_keys,
            },
        );
    }

    Ok(PanConfig {
        log_level,
        debug_encryption,
        notifications,
        servers,
    })
}
