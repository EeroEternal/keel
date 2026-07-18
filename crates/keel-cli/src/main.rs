//! Keel CLI — thin front-end over `keel-core`.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use keel_core::{
    profile_read_only, profile_strict, profile_workspace, EnforceBackend, LocalProcessBackend,
    MemorySink, NullBackend, Policy, ProcessGuardBackend, Space, SpawnRequest,
};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "keel",
    version,
    about = "Keel — execution layer under agents (Policy · Enforce · Record)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print version and backend inventory.
    Info,
    /// Build and print a preset policy as JSON.
    Policy {
        #[arg(long, value_enum, default_value_t = Profile::Workspace)]
        profile: Profile,
        /// Workspace root (default: cwd).
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Also write TOML to this path.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Soft-check whether a path is allowed under a profile.
    Check {
        #[arg(long, value_enum, default_value_t = Profile::Workspace)]
        profile: Profile,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Path to check.
        path: PathBuf,
        /// Check write access instead of read.
        #[arg(long)]
        write: bool,
        #[arg(long, value_enum, default_value_t = BackendChoice::ProcessGuard)]
        backend: BackendChoice,
    },
    /// Run a command inside a temporary space.
    Run {
        #[arg(long, value_enum, default_value_t = Profile::Workspace)]
        profile: Profile,
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = BackendChoice::ProcessGuard)]
        backend: BackendChoice,
        /// Print JSONL-style events to stderr after the run.
        #[arg(long)]
        trace: bool,
        /// Program and args after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Profile {
    Workspace,
    ReadOnly,
    Strict,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BackendChoice {
    Null,
    ProcessGuard,
    /// Landlock (Linux) / Seatbelt (macOS). Process-wide FS; irreversible.
    LocalProcess,
}

fn build_policy(profile: Profile, workspace: PathBuf) -> Result<Policy> {
    let p = match profile {
        Profile::Workspace => profile_workspace(&workspace)?,
        Profile::ReadOnly => profile_read_only(&workspace)?,
        Profile::Strict => profile_strict(&workspace)?,
    };
    Ok(p)
}

fn make_backend(choice: BackendChoice) -> Arc<dyn keel_core::EnforceBackend> {
    match choice {
        BackendChoice::Null => Arc::new(NullBackend::new()),
        BackendChoice::ProcessGuard => Arc::new(ProcessGuardBackend::new()),
        BackendChoice::LocalProcess => Arc::new(LocalProcessBackend::new()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("keel=info".parse()?))
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Info => {
            println!("keel {}", env!("CARGO_PKG_VERSION"));
            println!("backends:");
            for b in [
                NullBackend::new().info(),
                ProcessGuardBackend::new().info(),
                LocalProcessBackend::new().info(),
            ] {
                println!(
                    "  - {:<16} kernel_fs={} child_network={}",
                    b.name, b.kernel_fs, b.child_network
                );
            }
            println!("pillars: Policy · Enforce · Record · Lifecycle");
            println!(
                "note: local-process applies irreversible process-wide FS sandbox (Landlock/Seatbelt)"
            );
        }
        Commands::Policy {
            profile,
            workspace,
            out,
        } => {
            let ws = workspace.unwrap_or(std::env::current_dir()?);
            let policy = build_policy(profile, ws)?;
            let json = policy.to_json()?;
            println!("{json}");
            if let Some(path) = out {
                std::fs::write(&path, policy.to_toml()?).with_context(|| {
                    format!("write policy toml to {}", path.display())
                })?;
            }
        }
        Commands::Check {
            profile,
            workspace,
            path,
            write,
            backend,
        } => {
            let ws = workspace.unwrap_or(std::env::current_dir()?);
            let policy = build_policy(profile, ws)?;
            let sink = Arc::new(MemorySink::new());
            let space = Space::create(policy, make_backend(backend), sink).await?;
            let allowed = space.check_fs(&path, write).await?;
            println!(
                "{} {} → {}",
                if write { "write" } else { "read" },
                path.display(),
                if allowed { "ALLOW" } else { "DENY" }
            );
            space.destroy().await?;
            if !allowed {
                std::process::exit(2);
            }
        }
        Commands::Run {
            profile,
            workspace,
            backend,
            trace,
            cmd,
        } => {
            if cmd.is_empty() {
                bail!("missing command; usage: keel run -- <program> [args...]");
            }
            let ws = workspace.unwrap_or(std::env::current_dir()?);
            let policy = build_policy(profile, ws)?;
            let sink = Arc::new(MemorySink::new());
            let space = Space::create(policy, make_backend(backend), sink.clone()).await?;

            let program = cmd[0].clone();
            let args: Vec<String> = cmd[1..].to_vec();
            let req = SpawnRequest::new(program).args(args);
            let spawned = space.spawn(req).await?;
            let output = spawned.child.wait_with_output().await?;

            use std::io::Write;
            let _ = std::io::stdout().write_all(&output.stdout);
            let _ = std::io::stderr().write_all(&output.stderr);

            if trace {
                for ev in sink.events().await {
                    eprintln!("{}", serde_json::to_string(&ev)?);
                }
            }

            space.destroy().await?;
            if !output.status.success() {
                std::process::exit(output.status.code().unwrap_or(1));
            }
        }
    }
    Ok(())
}
