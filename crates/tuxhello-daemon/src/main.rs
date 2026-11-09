//! tuxhellod — the Tux Hello system daemon.

mod auth;
mod backend;
mod config;
mod daemon;
mod manager;
mod pin;
mod session;
#[cfg(feature = "stub-backend")]
mod stub;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tuxhello_proto::{BUS_NAME, MANAGER_PATH, OBJECT_PATH};
use tuxhello_store::{FileKey, Store};

use crate::backend::Backend;
use crate::config::Config;
use crate::daemon::Daemon;
use crate::pin::PinBackend;

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

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::load(&args.config)?;
    let store = Arc::new(Store::open(&cfg.store.path, &FileKey)?);
    log::info!(
        "template store {} (key: {})",
        store.root().display(),
        store.key_description()
    );

    let pin = Arc::new(PinBackend::new(store.clone(), cfg.pin.clone()));
    let mut backends: Vec<Arc<dyn Backend>> = vec![pin.clone()];
    add_stub(&cfg, &mut backends);

    let daemon = Arc::new(Daemon::new(
        cfg.daemon,
        cfg.policy.dirs,
        backends,
        pin,
        store,
    )?);

    let builder = if args.session_bus {
        zbus::connection::Builder::session()?
    } else {
        zbus::connection::Builder::system()?
    };
    let _conn = builder
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, auth::AuthService::new(daemon.clone()))?
        .serve_at(MANAGER_PATH, manager::ManagerService::new(daemon.clone()))?
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
    let mut hup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = term.recv() => { log::info!("SIGTERM received, exiting"); break; }
            _ = tokio::signal::ctrl_c() => { log::info!("SIGINT received, exiting"); break; }
            _ = hup.recv() => match daemon.reload_policy() {
                Ok(()) => log::info!("SIGHUP: policy reloaded"),
                Err(e) => log::error!("SIGHUP: policy reload failed, keeping the old one: {e}"),
            },
        }
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
