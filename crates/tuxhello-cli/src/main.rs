//! `tuxhello` — command-line client. Phase 0 has `status` and `test`; the
//! enrolment and policy commands arrive with the real backends (Phase 1).

use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use tuxhello_client::{AuthContext, Client, SessionState};

#[derive(Parser)]
#[command(name = "tuxhello", version, about = "Tux Hello command-line tool")]
struct Cli {
    /// Talk to a daemon started with `tuxhellod --session-bus` (development).
    #[arg(long, global = true)]
    session_bus: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show daemon version and available methods.
    Status,
    /// Run a real authentication as the current user, without PAM.
    Test {
        /// PAM service name to report to the daemon (affects policy).
        #[arg(long, default_value = "tuxhello-test")]
        service: String,
        /// Give up after this many seconds.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
}

fn current_user() -> Result<String, String> {
    let uid = nix::unistd::getuid();
    nix::unistd::User::from_uid(uid)
        .map_err(|e| e.to_string())?
        .map(|u| u.name)
        .ok_or_else(|| format!("no passwd entry for uid {uid}"))
}

fn status(client: &Client) -> Result<ExitCode, String> {
    let version = client.version().map_err(|e| e.to_string())?;
    println!("tuxhellod {version}");
    let backends = client.list_backends().map_err(|e| e.to_string())?;
    if backends.is_empty() {
        println!("No authentication methods available (password only).");
    }
    for b in backends {
        println!(
            "  {:<12} {:<12} assurance {}",
            b.name,
            if b.available {
                "available"
            } else {
                "unavailable"
            },
            b.assurance
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn test(client: &Client, service: &str, timeout: u64) -> Result<ExitCode, String> {
    let user = current_user()?;
    let ctx = AuthContext {
        user: &user,
        service,
        tty: None,
        rhost: None,
    };
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let r = client
        .authenticate(&ctx, deadline, |ev| {
            println!("[{}] {}", ev.method, ev.message)
        })
        .map_err(|e| e.to_string())?;
    match r.state {
        SessionState::Success => {
            println!(
                "Success: authenticated by {} (assurance {})",
                r.method, r.assurance
            );
            Ok(ExitCode::SUCCESS)
        }
        other => {
            println!("Not authenticated: {}", other.as_str());
            Ok(ExitCode::from(1))
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let connect = if cli.session_bus {
        Client::connect_session
    } else {
        Client::connect
    };
    let result = connect()
        .map_err(|e| e.to_string())
        .and_then(|client| match cli.command {
            Command::Status => status(&client),
            Command::Test { service, timeout } => test(&client, &service, timeout),
        });
    result.unwrap_or_else(|e| {
        eprintln!("tuxhello: {e}");
        ExitCode::from(2)
    })
}
