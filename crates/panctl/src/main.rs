use std::collections::HashMap;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use zbus::Connection;

// ---------------------------------------------------------------------------
// D-Bus proxy traits
// ---------------------------------------------------------------------------

#[zbus::proxy(
    interface = "org.pantalaimon1.control",
    default_service = "org.pantalaimon1",
    default_path = "/org/pantalaimon1"
)]
trait Control {
    async fn list_servers(&self) -> zbus::Result<Vec<HashMap<String, String>>>;
    async fn list_users(&self) -> zbus::Result<Vec<String>>;
    async fn send_anyways(
        &self,
        pan_user: &str,
        message_id: &str,
        room_id: &str,
    ) -> zbus::Result<()>;
    async fn cancel_sending(
        &self,
        pan_user: &str,
        message_id: &str,
        room_id: &str,
    ) -> zbus::Result<()>;
    async fn start_sas(
        &self,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
    ) -> zbus::Result<String>;
    async fn accept_sas(
        &self,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
    ) -> zbus::Result<String>;
    async fn confirm_sas(
        &self,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
    ) -> zbus::Result<String>;
    async fn cancel_sas(
        &self,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
    ) -> zbus::Result<String>;
    async fn import_keys(
        &self,
        pan_user: &str,
        file_path: &str,
        passphrase: &str,
    ) -> zbus::Result<String>;
    async fn export_keys(
        &self,
        pan_user: &str,
        file_path: &str,
        passphrase: &str,
    ) -> zbus::Result<String>;
    async fn continue_key_share(
        &self,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
    ) -> zbus::Result<String>;
    async fn cancel_key_share(
        &self,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
    ) -> zbus::Result<String>;
}

#[zbus::proxy(
    interface = "org.pantalaimon1.devices",
    default_service = "org.pantalaimon1",
    default_path = "/org/pantalaimon1"
)]
trait Devices {
    async fn list_devices(
        &self,
        pan_user: &str,
        user_id: &str,
    ) -> zbus::Result<Vec<HashMap<String, String>>>;
    async fn verify_device(
        &self,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
    ) -> zbus::Result<String>;
    async fn unverify_device(
        &self,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
    ) -> zbus::Result<String>;
    async fn blacklist_device(
        &self,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
    ) -> zbus::Result<String>;
    async fn unblacklist_device(
        &self,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
    ) -> zbus::Result<String>;
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "panctl",
    version = "0.11.0",
    about = "Control pantalaimon via D-Bus"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List all configured homeserver proxies
    ListServers,

    /// List all tracked users (logged-in sessions)
    ListUsers,

    /// List known devices for a Matrix user
    ListDevices {
        /// The pantalaimon user (@alice:matrix.org)
        pan_user: String,
        /// The Matrix user whose devices to list
        user_id: String,
    },

    /// Mark a device as verified
    VerifyDevice {
        pan_user: String,
        user_id: String,
        device_id: String,
    },

    /// Mark a device as unverified
    UnverifyDevice {
        pan_user: String,
        user_id: String,
        device_id: String,
    },

    /// Blacklist a device (never trust, never encrypt to)
    BlacklistDevice {
        pan_user: String,
        user_id: String,
        device_id: String,
    },

    /// Remove a device from the blacklist
    UnblacklistDevice {
        pan_user: String,
        user_id: String,
        device_id: String,
    },

    /// Initiate SAS emoji verification with a device
    StartVerification {
        pan_user: String,
        user_id: String,
        device_id: String,
    },

    /// Accept an incoming SAS verification request
    AcceptVerification {
        pan_user: String,
        user_id: String,
        device_id: String,
    },

    /// Confirm that the SAS emoji match
    ConfirmVerification {
        pan_user: String,
        user_id: String,
        device_id: String,
    },

    /// Cancel a SAS verification in progress
    CancelVerification {
        pan_user: String,
        user_id: String,
        device_id: String,
    },

    /// Import E2E key backup from a file
    ImportKeys {
        pan_user: String,
        file_path: String,
        passphrase: String,
    },

    /// Export E2E keys to a file
    ExportKeys {
        pan_user: String,
        file_path: String,
        passphrase: String,
    },

    /// Send a blocked message despite unverified devices
    SendAnyways {
        pan_user: String,
        room_id: String,
    },

    /// Cancel a blocked message
    CancelSending {
        pan_user: String,
        room_id: String,
    },

    /// Forward a pending key-share request
    ContinueKeyshare {
        pan_user: String,
        user_id: String,
        device_id: String,
    },

    /// Reject a pending key-share request
    CancelKeyshare {
        pan_user: String,
        user_id: String,
        device_id: String,
    },
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let conn = Connection::session()
        .await
        .context("Cannot connect to D-Bus session bus")?;
    run(cli.command, &conn).await
}

async fn run(cmd: Cmd, conn: &Connection) -> Result<()> {
    let ctrl = ControlProxy::new(conn).await?;
    let devs = DevicesProxy::new(conn).await?;

    match cmd {
        Cmd::ListServers => {
            let servers = ctrl.list_servers().await?;
            if servers.is_empty() {
                println!("No servers configured.");
            }
            for s in &servers {
                println!(
                    "{}: {} → {}:{}",
                    s.get("name").map(String::as_str).unwrap_or("?"),
                    s.get("homeserver").map(String::as_str).unwrap_or("?"),
                    s.get("listen_address").map(String::as_str).unwrap_or("?"),
                    s.get("listen_port").map(String::as_str).unwrap_or("?"),
                );
            }
        }

        Cmd::ListUsers => {
            let users = ctrl.list_users().await?;
            if users.is_empty() {
                println!("No tracked users.");
            }
            for u in &users {
                println!("{u}");
            }
        }

        Cmd::ListDevices { pan_user, user_id } => {
            let devices = devs.list_devices(&pan_user, &user_id).await?;
            if devices.is_empty() {
                println!("No devices found (user may not be tracked yet).");
                return Ok(());
            }
            for d in &devices {
                println!(
                    "{:<20} {:<15} {}",
                    d.get("device_id").map(String::as_str).unwrap_or("?"),
                    d.get("trust_state").map(String::as_str).unwrap_or("?"),
                    d.get("device_display_name").map(String::as_str).unwrap_or(""),
                );
            }
        }

        Cmd::VerifyDevice { pan_user, user_id, device_id } => {
            let mid = devs.verify_device(&pan_user, &user_id, &device_id).await?;
            wait_response(conn, &mid).await?;
        }

        Cmd::UnverifyDevice { pan_user, user_id, device_id } => {
            let mid = devs.unverify_device(&pan_user, &user_id, &device_id).await?;
            wait_response(conn, &mid).await?;
        }

        Cmd::BlacklistDevice { pan_user, user_id, device_id } => {
            let mid = devs.blacklist_device(&pan_user, &user_id, &device_id).await?;
            wait_response(conn, &mid).await?;
        }

        Cmd::UnblacklistDevice { pan_user, user_id, device_id } => {
            let mid = devs.unblacklist_device(&pan_user, &user_id, &device_id).await?;
            wait_response(conn, &mid).await?;
        }

        Cmd::StartVerification { pan_user, user_id, device_id } => {
            let mid = ctrl.start_sas(&pan_user, &user_id, &device_id).await?;
            println!("SAS verification initiated (message_id={mid})");
            println!("Waiting for the remote device to accept...");
            wait_sas_show(conn, &pan_user, &user_id, &device_id).await?;
        }

        Cmd::AcceptVerification { pan_user, user_id, device_id } => {
            let mid = ctrl.accept_sas(&pan_user, &user_id, &device_id).await?;
            println!("SAS accept sent (message_id={mid})");
            wait_sas_show(conn, &pan_user, &user_id, &device_id).await?;
        }

        Cmd::ConfirmVerification { pan_user, user_id, device_id } => {
            let mid = ctrl.confirm_sas(&pan_user, &user_id, &device_id).await?;
            wait_response(conn, &mid).await?;
        }

        Cmd::CancelVerification { pan_user, user_id, device_id } => {
            let mid = ctrl.cancel_sas(&pan_user, &user_id, &device_id).await?;
            wait_response(conn, &mid).await?;
        }

        Cmd::ImportKeys { pan_user, file_path, passphrase } => {
            let mid = ctrl.import_keys(&pan_user, &file_path, &passphrase).await?;
            wait_response(conn, &mid).await?;
        }

        Cmd::ExportKeys { pan_user, file_path, passphrase } => {
            let mid = ctrl.export_keys(&pan_user, &file_path, &passphrase).await?;
            wait_response(conn, &mid).await?;
        }

        Cmd::SendAnyways { pan_user, room_id } => {
            // SendAnyways uses a caller-provided message_id from the UnverifiedDevices signal.
            // Since panctl doesn't persist signal state across invocations, we use a static id.
            ctrl.send_anyways(&pan_user, "0", &room_id).await?;
            println!("Send-anyways command dispatched.");
        }

        Cmd::CancelSending { pan_user, room_id } => {
            ctrl.cancel_sending(&pan_user, "0", &room_id).await?;
            println!("Cancel-sending command dispatched.");
        }

        Cmd::ContinueKeyshare { pan_user, user_id, device_id } => {
            let mid = ctrl.continue_key_share(&pan_user, &user_id, &device_id).await?;
            wait_response(conn, &mid).await?;
        }

        Cmd::CancelKeyshare { pan_user, user_id, device_id } => {
            let mid = ctrl.cancel_key_share(&pan_user, &user_id, &device_id).await?;
            wait_response(conn, &mid).await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Signal helpers
// ---------------------------------------------------------------------------

const SIGNAL_TIMEOUT_SECS: u64 = 30;

/// Wait for a `Response` signal matching `message_id` and print the result.
async fn wait_response(conn: &Connection, message_id: &str) -> Result<()> {
    let mut stream = zbus::MessageStream::from(conn);
    let deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_secs(SIGNAL_TIMEOUT_SECS);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("Timed out waiting for Response signal");
        }

        let item = tokio::time::timeout(remaining, stream.next()).await;
        let Some(Ok(msg)) = item.ok().flatten() else {
            continue;
        };

        let hdr = msg.header();
        if hdr.message_type() != zbus::message::Type::Signal {
            continue;
        }
        if hdr.member().map(|m| m.as_str()) != Some("Response") {
            continue;
        }

        let Ok((mid, _pan_user, code, message)) =
            msg.body().deserialize::<(String, String, String, String)>()
        else {
            continue;
        };

        if mid != message_id {
            continue;
        }

        if code == "ok" {
            println!("OK: {message}");
        } else {
            eprintln!("Error ({code}): {message}");
            std::process::exit(1);
        }
        return Ok(());
    }
}

/// Wait for a `SasShow` signal and print the emoji list so the user can compare.
async fn wait_sas_show(
    conn: &Connection,
    pan_user: &str,
    user_id: &str,
    device_id: &str,
) -> Result<()> {
    let mut stream = zbus::MessageStream::from(conn);
    let deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_secs(SIGNAL_TIMEOUT_SECS);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("Timed out waiting for SasShow signal");
        }

        let item = tokio::time::timeout(remaining, stream.next()).await;
        let Some(Ok(msg)) = item.ok().flatten() else {
            continue;
        };

        let hdr = msg.header();
        if hdr.message_type() != zbus::message::Type::Signal {
            continue;
        }
        if hdr.member().map(|m| m.as_str()) != Some("SasShow") {
            continue;
        }

        let Ok((sig_pan_user, sig_user_id, sig_device_id, _txn_id, emoji)) = msg
            .body()
            .deserialize::<(String, String, String, String, Vec<(String, String)>)>()
        else {
            continue;
        };

        if sig_pan_user != pan_user || sig_user_id != user_id || sig_device_id != device_id {
            continue;
        }

        println!("\nVerify that both devices show the same emoji:");
        println!("{:-<50}", "");
        for (symbol, name) in &emoji {
            println!("  {symbol}  {name}");
        }
        println!("{:-<50}", "");
        println!("Run `panctl confirm-verification` if they match, or `panctl cancel-verification` to abort.");
        return Ok(());
    }
}
