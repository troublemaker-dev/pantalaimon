use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod client;
mod config;
mod dbus;
mod error;
mod messages;
mod proxy;
mod store;

use client::PanClient;
use config::read_config;
use proxy::{
    daemon::ProxyDaemon,
    routes::{load_from_keyring, save_to_keyring},
};
use store::PanStore;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "pantalaimon",
    version = "0.11.0",
    about = "E2E encryption-aware Matrix reverse proxy daemon"
)]
struct Cli {
    /// Path to the config file (default: $XDG_CONFIG_HOME/pantalaimon/pantalaimon.conf)
    #[arg(short = 'c', long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Override the log level from the config file
    #[arg(long, value_enum)]
    log_level: Option<LogLevelArg>,

    /// Override the data directory (default: $XDG_DATA_HOME/pantalaimon)
    #[arg(long, value_name = "DIR")]
    data_path: Option<PathBuf>,

    /// Enable verbose Olm/Megolm debug logging
    #[arg(long)]
    debug_encryption: bool,
}

#[derive(ValueEnum, Clone, Debug)]
enum LogLevelArg {
    Error,
    Warning,
    Info,
    Debug,
}

impl From<LogLevelArg> for tracing::Level {
    fn from(a: LogLevelArg) -> Self {
        match a {
            LogLevelArg::Error => tracing::Level::ERROR,
            LogLevelArg::Warning => tracing::Level::WARN,
            LogLevelArg::Info => tracing::Level::INFO,
            LogLevelArg::Debug => tracing::Level::DEBUG,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Config file
    let config_path = cli
        .config
        .or_else(default_config_path)
        .context("Cannot determine config directory; use --config")?;

    let pan_conf = read_config(&config_path)
        .with_context(|| format!("Failed to read config {}", config_path.display()))?;

    // Log level: CLI flag > config file
    let level = cli
        .log_level
        .map(tracing::Level::from)
        .unwrap_or(pan_conf.log_level);

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive(level.into()),
        )
        .init();

    if pan_conf.servers.is_empty() {
        anyhow::bail!(
            "No homeserver sections found in {}",
            config_path.display()
        );
    }

    // Data directory
    let data_dir = cli
        .data_path
        .or_else(default_data_path)
        .context("Cannot determine data directory; use --data-path")?;

    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("Cannot create data dir {}", data_dir.display()))?;

    // Shared SQLite store
    let store = Arc::new(PanStore::new(&data_dir).await?);

    // Build one ProxyDaemon per configured server so startup restore has
    // access to the daemon's register_client method.
    let mut daemons: HashMap<String, Arc<ProxyDaemon>> = HashMap::new();

    for (server_name, server_conf) in &pan_conf.servers {
        let daemon =
            ProxyDaemon::new(server_conf.clone(), store.clone()).await?;
        daemons.insert(server_name.clone(), daemon);
    }

    // Restore PanClients for every user that was logged in during a previous
    // run.  Token precedence: keyring > database.
    for (server_name, server_conf) in &pan_conf.servers {
        let sessions = store.load_session_tokens(server_name).await?;

        for (user_id, device_id, db_token) in sessions {
            // Keyring takes precedence (the user may have logged in again
            // since we last ran and the new token is in the keyring).
            let token = if server_conf.use_keyring {
                load_from_keyring(&user_id, &device_id)
                    .unwrap_or(db_token.clone())
            } else {
                db_token.clone()
            };

            // If keyring held a different token, update the DB.
            if server_conf.use_keyring && token != db_token {
                if let Err(e) = store
                    .save_access_token(&user_id, &device_id, &token)
                    .await
                {
                    warn!(%user_id, "Failed to refresh DB token from keyring: {e}");
                }
            }

            // Ensure the keyring always has an entry (idempotent).
            if server_conf.use_keyring {
                save_to_keyring(&user_id, &device_id, &token);
            }

            info!(%user_id, %device_id, server = %server_name, "Restored session");

            let daemon = daemons.get(server_name).unwrap();
            let client = match PanClient::new(
                user_id,
                device_id,
                token,
                server_conf.clone(),
                store.clone(),
                daemon.http_client.clone(),
                None, // ui_tx — wired in Phase 6
                None, // pan_rx — wired in Phase 6
            )
            .await
            {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    warn!(%server_name, "Failed to create PanClient on restore: {e}");
                    continue;
                }
            };

            client.clone().start_sync().await;
            daemon.register_client(client);
        }
    }

    // D-Bus server (Phase 6: replaces the no-op stub)
    tokio::spawn(dbus::server::DbusServer::new().run());

    // Start one axum server per configured homeserver.
    let mut handles = Vec::new();

    for (server_name, server_conf) in pan_conf.servers {
        let daemon = daemons.remove(&server_name).unwrap();
        info!(
            server = %server_conf.name,
            listen = %format!("{}:{}", server_conf.listen_address, server_conf.listen_port),
            homeserver = %server_conf.homeserver,
            "Starting proxy"
        );
        let handle = tokio::spawn(proxy::run(daemon, server_conf));
        handles.push(handle);
    }

    println!("pantalaimon running — press Ctrl+C to stop");

    // Wait for a shutdown signal.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }

    info!("Shutting down");
    for h in handles {
        h.abort();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("pantalaimon").join("pantalaimon.conf"))
}

fn default_data_path() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("pantalaimon"))
}
