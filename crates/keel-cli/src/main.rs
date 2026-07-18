//! Keel CLI — thin front-end over `keel-core`.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use keel_core::{
    profile_read_only, profile_strict, profile_workspace, EnforceBackend, LocalProcessBackend,
    NullBackend, Policy, ProcessGuardBackend, Space, SpaceOptions, SpawnRequest,
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
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Soft-check whether a path is allowed under a profile.
    Check {
        #[arg(long, value_enum, default_value_t = Profile::Workspace)]
        profile: Profile,
        #[arg(long)]
        workspace: Option<PathBuf>,
        path: PathBuf,
        #[arg(long)]
        write: bool,
        #[arg(long, value_enum, default_value_t = BackendChoice::ProcessGuard)]
        backend: BackendChoice,
    },
    /// Run a command inside a temporary space (events under ~/.keel/spaces/).
    Run {
        #[arg(long, value_enum, default_value_t = Profile::Workspace)]
        profile: Profile,
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = BackendChoice::ProcessGuard)]
        backend: BackendChoice,
        /// Also keep events in memory and print them to stderr.
        #[arg(long)]
        trace: bool,
        /// Do not write ~/.keel/spaces/<id>/events.jsonl.
        #[arg(long)]
        no_persist: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    /// Apply kernel sandbox then exec a program (internal / advanced).
    ///
    /// Used so library hosts never apply Landlock/Seatbelt to themselves.
    SandboxExec {
        /// Path to policy JSON.
        #[arg(long)]
        policy_file: PathBuf,
        /// Block network in the sandboxed process.
        #[arg(long)]
        block_network: bool,
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
    /// Landlock/Seatbelt; children sandboxed by default (host stays clean).
    LocalProcess,
}

fn build_policy(profile: Profile, workspace: PathBuf) -> Result<Policy> {
    Ok(match profile {
        Profile::Workspace => profile_workspace(&workspace)?,
        Profile::ReadOnly => profile_read_only(&workspace)?,
        Profile::Strict => profile_strict(&workspace)?,
    })
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
                "local-process: isolate_apply=true (host clean; children get Landlock/Seatbelt)"
            );
            println!("events: ~/.keel/spaces/<id>/events.jsonl");
        }
        Commands::Policy {
            profile,
            workspace,
            out,
        } => {
            let ws = workspace.unwrap_or(std::env::current_dir()?);
            let policy = build_policy(profile, ws)?;
            println!("{}", policy.to_json()?);
            if let Some(path) = out {
                std::fs::write(&path, policy.to_toml()?)
                    .with_context(|| format!("write {}", path.display()))?;
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
            let space = Space::create_with(
                policy,
                make_backend(backend),
                SpaceOptions {
                    persist_events: false,
                    memory_events: true,
                    persist_policy: false,
                },
            )
            .await?;
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
            no_persist,
            cmd,
        } => {
            if cmd.is_empty() {
                bail!("missing command; usage: keel run -- <program> [args...]");
            }
            let ws = workspace.unwrap_or(std::env::current_dir()?);
            let policy = build_policy(profile, ws)?;
            let space = Space::create_with(
                policy,
                make_backend(backend),
                SpaceOptions {
                    persist_events: !no_persist,
                    memory_events: trace,
                    persist_policy: !no_persist,
                },
            )
            .await?;

            if let Some(p) = space.events_path() {
                eprintln!("keel: events → {}", p.display());
            }

            let req = SpawnRequest::new(cmd[0].clone()).args(cmd[1..].to_vec());
            let spawned = space.spawn(req).await?;
            let output = spawned.child.wait_with_output().await?;

            use std::io::Write;
            let _ = std::io::stdout().write_all(&output.stdout);
            let _ = std::io::stderr().write_all(&output.stderr);

            space.destroy().await?;
            if !output.status.success() {
                std::process::exit(output.status.code().unwrap_or(1));
            }
        }
        Commands::SandboxExec {
            policy_file,
            block_network,
            cmd,
        } => {
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                let _policy =
                    keel_core::apply_policy_file_and_ready(&policy_file, block_network)?;
                let err = std::process::Command::new(&cmd[0])
                    .args(&cmd[1..])
                    .exec();
                bail!("exec failed: {err}");
            }
            #[cfg(not(unix))]
            {
                let _ = (policy_file, block_network, cmd);
                bail!("sandbox-exec requires unix");
            }
        }
    }
    Ok(())
}
