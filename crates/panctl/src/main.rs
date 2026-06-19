/// panctl — control tool for pantalaimon.
///
/// Phase 6 placeholder.  The final implementation will:
///   - Connect to pantalaimon's D-Bus interface (`org.pantalaimon1`)
///   - Offer an interactive readline loop (rustyline) mirroring the Python
///     prompt_toolkit REPL
///   - Expose clap subcommands for non-interactive use:
///     list-servers, list-users, list-devices, verify-device, start-sas, etc.

fn main() {
    eprintln!("panctl: D-Bus UI not yet implemented (Phase 6)");
    std::process::exit(1);
}
