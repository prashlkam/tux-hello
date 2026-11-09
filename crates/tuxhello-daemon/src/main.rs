//! tuxhellod — the Tux Hello system daemon.

mod auth;
mod backend;
mod config;
mod session;
#[cfg(feature = "stub-backend")]
mod stub;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tuxhello_proto::{BUS_NAME, OBJECT_PATH};

use crate::backend::Backend;
use crate::config::Config;

#[derive(Parser)]
#[command(name = "tuxhellod", version, about = "Tux Hello authentication daemon")]
struct Args {
    /// Configuration file.
    #[arg(long, default_value = config::DEFAULT_PATH)]
    config: PathBuf,
    /// Use the session bus instead of the system bus (development only; the
    /// PAM module only ever talks to the system bus).
    #[arg(long)]
    session_bus: bool,
}

#[cfg(feature = "stub-backend")]
fn add_stub(cfg: &Config, backends: &mut Vec<Arc<dyn Backend>>) {
    if cfg.stub.enabled {
        log::warn!(
            "STUB BACKEND ENABLED (outcome = {:?}). This is for testing only; \
             never run it on a real system.",
            cfg.stub.outcome
        );
        backends.push(Arc::new(stub::Stub::new(&cfg.stub)));
    }
}

#[cfg(not(feature = "stub-backend"))]
fn add_stub(cfg: &Config, _backends: &mut Vec<Arc<dyn Backend>>) {
    if cfg.stub.enabled {
        log::warn!("[stub] is enabled in the config but this build has no stub backend; ignoring");
    }
}

fn build_backends(cfg: &Config) -> Vec<Arc<dyn Backend>> {
    let mut backends: Vec<Arc<dyn Backend>> = Vec::new();
    add_stub(cfg, &mut backends);

    if backends.is_empty() {
        log::warn!(
            "no authentication backends available; every request will fall back to the password"
        );
    }
    backends
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::load(&args.config)?;
    let backends = build_backends(&cfg);
    let service = auth::AuthService::new(cfg.daemon, backends);

    let builder = if args.session_bus {
        zbus::connection::Builder::session()?
    } else {
        zbus::connection::Builder::system()?
    };
    let _conn = builder
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, service)?
        .build()
        .await?;
    log::info!(
        "tuxhellod {} listening as {BUS_NAME} on the {} bus",
        env!("CARGO_PKG_VERSION"),
        if args.session_bus {
            "session"
        } else {
            "system"
        }
    );

    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => log::info!("SIGTERM received, exiting"),
        _ = tokio::signal::ctrl_c() => log::info!("SIGINT received, exiting"),
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            ExitCode::FAILURE
        }
    }
}
