//! `tuxhello` — command-line client.

mod doctor;

use std::io::{self, BufRead, IsTerminal, Write};
use std::os::fd::AsFd;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use nix::sys::termios;
use tuxhello_client::{AuthContext, Client, SessionState, Zeroizing};

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
    /// Show daemon version, store and available methods.
    Status,
    /// Check the installation and say how to fix what is wrong.
    Doctor,
    /// Run a real authentication as the current user, without PAM.
    Test {
        /// PAM service name to report to the daemon (selects the policy).
        #[arg(long, default_value = "tuxhello-test")]
        service: String,
        /// Give up after this many seconds (time spent typing is not counted).
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// Enrol an authentication method (currently requires sudo).
    Enroll {
        #[command(subcommand)]
        method: EnrollMethod,
    },
    /// List enrolments.
    List {
        /// User to list (default: you, or the invoking user under sudo).
        #[arg(long)]
        user: Option<String>,
    },
    /// Delete an enrolment, or everything with --all.
    Delete {
        /// Method (pin, key, fingerprint, ...).
        #[arg(required_unless_present = "all")]
        method: Option<String>,
        /// Enrolment id (see `tuxhello list`); default "default".
        id: Option<String>,
        /// Delete all enrolments of the user.
        #[arg(long, conflicts_with = "method")]
        all: bool,
        #[arg(long)]
        user: Option<String>,
    },
    /// Bring in enrolments from another tool (requires sudo).
    Import {
        #[command(subcommand)]
        source: ImportSource,
    },
    /// Clear a user's lockouts: too many failed attempts, biometrics switched
    /// off, PIN backoff (requires sudo).
    Unlock {
        #[arg(long)]
        user: Option<String>,
    },
    /// Show the policy that applies to a PAM service.
    Policy {
        /// PAM service, e.g. sudo, gdm-password, swaylock.
        #[arg(default_value = "sudo")]
        service: String,
        #[arg(long)]
        user: Option<String>,
    },
}

#[derive(Subcommand)]
enum ImportSource {
    /// Security keys registered with pam_u2f (pamu2fcfg).
    PamU2f {
        /// Key file (default: ~USER/.config/Yubico/u2f_keys, then /etc/u2f_mappings).
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// The `origin` pam_u2f was configured with (default: pam://<hostname>).
        #[arg(long)]
        origin: Option<String>,
        #[arg(long)]
        user: Option<String>,
    },
}

#[derive(Subcommand)]
enum EnrollMethod {
    /// Set or change the PIN.
    Pin {
        #[arg(long)]
        user: Option<String>,
    },
    /// Enrol a finger with fprintd (your own without sudo; others with sudo).
    Fingerprint {
        /// Which finger, e.g. right-index-finger (default: fprintd chooses).
        #[arg(long)]
        finger: Option<String>,
        #[arg(long)]
        user: Option<String>,
    },
    /// Register a FIDO2/U2F security key (enrol a backup key too).
    Key {
        /// Name for this key, e.g. "yubikey" or "backup" (default: key-N).
        #[arg(long)]
        label: Option<String>,
        /// Don't ask for the key's own PIN (the key has none).
        #[arg(long)]
        no_pin: bool,
        #[arg(long)]
        user: Option<String>,
    },
}

type Res = Result<ExitCode, String>;

/// Resolves the user a command acts on: `--user`, else the user who ran
/// sudo, else the current user.
fn target_user(user: Option<String>) -> Result<(String, u32), String> {
    let lookup_name = |n: &str| -> Result<(String, u32), String> {
        nix::unistd::User::from_name(n)
            .map_err(|e| e.to_string())?
            .map(|u| (u.name, u.uid.as_raw()))
            .ok_or_else(|| format!("no such user {n:?}"))
    };
    if let Some(u) = user {
        return lookup_name(&u);
    }
    let uid = nix::unistd::getuid();
    if uid.is_root() {
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            return lookup_name(&sudo_user);
        }
    }
    nix::unistd::User::from_uid(uid)
        .map_err(|e| e.to_string())?
        .map(|u| (u.name, u.uid.as_raw()))
        .ok_or_else(|| format!("no passwd entry for uid {uid}"))
}

/// Reads a secret from the terminal with echo off (or a plain line from a
/// non-terminal stdin, for scripts).
fn read_secret(prompt: &str) -> io::Result<Zeroizing<String>> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let stdin = io::stdin();
    let fd = stdin.as_fd();
    let saved = if stdin.is_terminal() {
        let old = termios::tcgetattr(fd).map_err(io::Error::from)?;
        let mut t = old.clone();
        t.local_flags.remove(termios::LocalFlags::ECHO);
        termios::tcsetattr(fd, termios::SetArg::TCSANOW, &t).map_err(io::Error::from)?;
        Some(old)
    } else {
        None
    };
    let mut line = Zeroizing::new(String::new());
    let r = stdin.lock().read_line(&mut line);
    if let Some(old) = saved {
        let _ = termios::tcsetattr(fd, termios::SetArg::TCSANOW, &old);
        eprintln!();
    }
    r?;
    let trimmed = line.trim_end_matches(['\n', '\r']).to_string();
    Ok(Zeroizing::new(trimmed))
}

fn status(client: &Client) -> Res {
    let info = client.info().map_err(|e| e.to_string())?;
    let get = |k: &str| info.get(k).map(String::as_str).unwrap_or("?");
    println!("tuxhellod {}", get("version"));
    println!("  store       {} (key: {})", get("store"), get("store-key"));
    println!("  policy dirs {}", get("policy-dirs").replace(':', ", "));
    let backends = client.list_backends().map_err(|e| e.to_string())?;
    println!("methods:");
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

fn test(client: &Client, service: &str, timeout: u64) -> Res {
    let (user, _) = target_user(None)?;
    let ctx = AuthContext {
        user: &user,
        service,
        tty: None,
        rhost: None,
    };
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let r = client
        .authenticate(&ctx, deadline, |ev| {
            if ev.is_prompt() {
                return read_secret(&format!("[{}] {}", ev.method, ev.message)).ok();
            }
            println!("[{}] {}", ev.method, ev.message);
            None
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

fn enroll_pin(client: &Client, user: Option<String>) -> Res {
    let (name, uid) = target_user(user)?;
    if !nix::unistd::getuid().is_root() {
        return Err("enrolling requires root for now: run `sudo tuxhello enroll pin`".into());
    }
    println!("Setting the PIN for {name}.");
    let pin = read_secret("New PIN: ").map_err(|e| e.to_string())?;
    let again = read_secret("Repeat PIN: ").map_err(|e| e.to_string())?;
    if *pin != *again {
        return Err("the PINs do not match".into());
    }
    client.enroll_pin(uid, &pin).map_err(|e| e.to_string())?;
    println!("PIN set for {name}.");
    Ok(ExitCode::SUCCESS)
}

fn enroll_key(client: &Client, label: Option<String>, no_pin: bool, user: Option<String>) -> Res {
    let (name, uid) = target_user(user)?;
    if !nix::unistd::getuid().is_root() {
        return Err("enrolling requires root for now: run `sudo tuxhello enroll key`".into());
    }
    let key_pin = if no_pin {
        Zeroizing::new(String::new())
    } else {
        read_secret("Security key PIN (leave empty if your key has none): ")
            .map_err(|e| e.to_string())?
    };
    println!("Touch your security key now…");
    let id = client
        .enroll_key(uid, label.as_deref().unwrap_or(""), &key_pin)
        .map_err(|e| e.to_string())?;
    println!("Security key enrolled for {name} as {id:?}.");
    println!("Tip: enrol a second (backup) key with `sudo tuxhello enroll key --label backup`.");
    Ok(ExitCode::SUCCESS)
}

const FINGERS: &[&str] = &[
    "left-thumb",
    "left-index-finger",
    "left-middle-finger",
    "left-ring-finger",
    "left-little-finger",
    "right-thumb",
    "right-index-finger",
    "right-middle-finger",
    "right-ring-finger",
    "right-little-finger",
];

/// Fingerprints live in fprintd; its own enrolment tool shows the scan
/// progress, so we hand over to it.
fn enroll_fingerprint(finger: Option<String>, user: Option<String>) -> Res {
    let (name, uid) = target_user(user)?;
    let me = nix::unistd::getuid();
    if !me.is_root() && me.as_raw() != uid {
        return Err("enrolling someone else's fingerprint requires sudo".into());
    }
    if let Some(f) = &finger {
        if !FINGERS.contains(&f.as_str()) {
            return Err(format!(
                "unknown finger {f:?}; one of: {}",
                FINGERS.join(", ")
            ));
        }
    }
    let mut cmd = std::process::Command::new("fprintd-enroll");
    if let Some(f) = &finger {
        cmd.args(["-f", f]);
    }
    if me.is_root() {
        cmd.arg(&name);
    }
    println!("Enrolling a fingerprint for {name} (follow the prompts)…");
    let st = cmd.status().map_err(|e| {
        format!("cannot run fprintd-enroll ({e}); install fprintd to use fingerprints")
    })?;
    if st.success() {
        println!("Done. Check with `tuxhello list`.");
        Ok(ExitCode::SUCCESS)
    } else {
        Err(format!("fprintd-enroll failed ({st})"))
    }
}

fn list(client: &Client, user: Option<String>) -> Res {
    let (name, uid) = target_user(user)?;
    let v = client.list_enrollments(uid).map_err(|e| e.to_string())?;
    if v.is_empty() {
        println!("{name} has no enrolments.");
    } else {
        println!("Enrolments of {name}:");
        for (method, id) in v {
            println!("  {method:<12} {id}");
        }
    }
    // Older daemons don't have GetLockout; the list is still worth showing.
    if let Ok(l) = client.lockout(uid) {
        let get = |k: &str| l.get(k).copied().unwrap_or(0);
        if get("biometrics-locked") != 0 {
            println!(
                "Biometrics are switched off after {} failed attempts; a PIN or security-key \
                 login, or `sudo tuxhello unlock`, switches them back on.",
                get("biometric-failures")
            );
        }
        if get("pin-locked-s") != 0 {
            println!("The PIN is locked for another {} s.", get("pin-locked-s"));
        }
        if get("throttled-s") != 0 {
            println!(
                "Too many failed attempts: Tux Hello is paused for another {} s (the password still works).",
                get("throttled-s")
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn import_pam_u2f(
    client: &Client,
    file: Option<std::path::PathBuf>,
    origin: Option<String>,
    user: Option<String>,
) -> Res {
    let (name, uid) = target_user(user)?;
    if !nix::unistd::getuid().is_root() {
        return Err("importing requires root for now: run `sudo tuxhello import pam-u2f`".into());
    }
    let candidates: Vec<std::path::PathBuf> = match file {
        Some(f) => vec![f],
        None => {
            let home = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
                .ok()
                .flatten()
                .map(|u| u.dir);
            home.into_iter()
                .map(|h| h.join(".config/Yubico/u2f_keys"))
                .chain(["/etc/u2f_mappings".into()])
                .collect()
        }
    };
    let Some((path, text)) = candidates
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok().map(|t| (p, t)))
    else {
        return Err(format!(
            "no pam_u2f key file found (looked at {}); name it with --file",
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    };
    let origin = match origin {
        Some(o) => o,
        None => format!(
            "pam://{}",
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map_err(|e| format!("cannot read the hostname ({e}); pass --origin"))?
                .trim()
        ),
    };
    let (ids, notes) = client
        .import_pam_u2f(uid, &text, &origin)
        .map_err(|e| e.to_string())?;
    println!(
        "Imported {} security key(s) for {name} from {} (origin {origin}).",
        ids.len(),
        path.display()
    );
    for id in &ids {
        println!("  key          {id}");
    }
    for n in &notes {
        println!("  note: {n}");
    }
    if ids.is_empty() {
        return Ok(ExitCode::from(1));
    }
    println!(
        "Check with `tuxhello test`. If the key is not recognised, pam_u2f was probably set up \
         with a different origin= (see its line in /etc/pam.d); delete the import and repeat \
         it with --origin."
    );
    Ok(ExitCode::SUCCESS)
}

fn unlock(client: &Client, user: Option<String>) -> Res {
    let (name, uid) = target_user(user)?;
    if !nix::unistd::getuid().is_root() {
        return Err("clearing lockouts requires root: run `sudo tuxhello unlock`".into());
    }
    client.reset_lockout(uid).map_err(|e| e.to_string())?;
    println!("Lockouts cleared for {name}.");
    Ok(ExitCode::SUCCESS)
}

fn delete(
    client: &Client,
    method: Option<String>,
    id: Option<String>,
    all: bool,
    user: Option<String>,
) -> Res {
    let (name, uid) = target_user(user)?;
    if all {
        client.delete_all(uid).map_err(|e| e.to_string())?;
        println!("Deleted all enrolments of {name}.");
        return Ok(ExitCode::SUCCESS);
    }
    let method = method.expect("clap requires method unless --all");
    let id = id.unwrap_or_else(|| "default".into());
    if client
        .delete_enrollment(uid, &method, &id)
        .map_err(|e| e.to_string())?
    {
        println!("Deleted {method}/{id} of {name}.");
        Ok(ExitCode::SUCCESS)
    } else {
        println!("{name} has no {method}/{id} enrolment.");
        Ok(ExitCode::from(1))
    }
}

fn policy(client: &Client, service: &str, user: Option<String>) -> Res {
    let (name, uid) = target_user(user)?;
    let m = client
        .explain_policy(uid, service)
        .map_err(|e| e.to_string())?;
    let get = |k: &str| m.get(k).map(String::as_str).unwrap_or("?");
    println!("Policy for {name} on PAM service {service:?}:");
    println!("  class          {}", get("class"));
    println!("  requires       {}", get("require"));
    println!("  min assurance  {}", get("min-assurance"));
    println!("  timeout        {} s", get("timeout-s"));
    let usable = get("usable");
    println!(
        "  usable now     {}",
        if usable.is_empty() {
            "nothing enrolled (password only)"
        } else {
            usable
        }
    );
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let connect = if cli.session_bus {
        Client::connect_session
    } else {
        Client::connect
    };
    if matches!(cli.command, Command::Doctor) {
        // Doctor must work when nothing else does, so it handles a missing
        // bus or daemon itself.
        let client = connect().ok();
        return match target_user(None) {
            Ok((name, uid)) => doctor::run(client.as_ref(), cli.session_bus, &name, uid),
            Err(e) => {
                eprintln!("tuxhello: {e}");
                ExitCode::from(2)
            }
        };
    }
    let result = connect()
        .map_err(|e| e.to_string())
        .and_then(|client| match cli.command {
            Command::Doctor => unreachable!("handled above"),
            Command::Status => status(&client),
            Command::Test { service, timeout } => test(&client, &service, timeout),
            Command::Enroll {
                method: EnrollMethod::Pin { user },
            } => enroll_pin(&client, user),
            Command::Enroll {
                method: EnrollMethod::Fingerprint { finger, user },
            } => enroll_fingerprint(finger, user),
            Command::Enroll {
                method:
                    EnrollMethod::Key {
                        label,
                        no_pin,
                        user,
                    },
            } => enroll_key(&client, label, no_pin, user),
            Command::List { user } => list(&client, user),
            Command::Delete {
                method,
                id,
                all,
                user,
            } => delete(&client, method, id, all, user),
            Command::Import {
                source: ImportSource::PamU2f { file, origin, user },
            } => import_pam_u2f(&client, file, origin, user),
            Command::Unlock { user } => unlock(&client, user),
            Command::Policy { service, user } => policy(&client, &service, user),
        });
    result.unwrap_or_else(|e| {
        eprintln!("tuxhello: {e}");
        ExitCode::from(2)
    })
}
