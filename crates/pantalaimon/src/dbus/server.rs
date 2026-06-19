/// D-Bus interface server — Phase 6 placeholder.
///
/// This will expose `org.pantalaimon1` on the session bus using `zbus`.
/// For now it is a no-op so the rest of the codebase compiles without
/// requiring a D-Bus daemon at build or run time.
///
/// Phase 6 will implement:
///   - `StartSas` / `AcceptSas` / `ConfirmSas` / `CancelSas`
///   - `VerifyDevice` / `UnverifyDevice` / `BlacklistDevice` / `UnblacklistDevice`
///   - `ImportKeys` / `ExportKeys`
///   - `ListDevices` / `ListServers` / `ListUsers`
///   - Signal emission for `UnverifiedDevices`, `SasInvite`, `SasShow`, `SasDone`
pub struct DbusServer;

impl DbusServer {
    pub fn new() -> Self {
        Self
    }

    /// Start the D-Bus interface as a background tokio task.
    pub async fn run(self) {
        #[cfg(feature = "ui")]
        {
            // TODO Phase 6: connect_session_bus, ObjectServer::at, run loop
            tracing::info!("D-Bus UI enabled — not yet implemented (Phase 6)");
        }
        #[cfg(not(feature = "ui"))]
        {
            tracing::debug!("D-Bus UI feature not enabled, skipping");
        }
    }
}
