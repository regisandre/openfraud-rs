use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use openfraud::config::{Config, DEFAULT_CONFIG};
use openfraud::engine::Engine;
use openfraud::files::write_atomic;
use openfraud::keys::State;
use std::io::IsTerminal;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "openfraud",
    version,
    about = "Self-hosted fraud and abuse engine: events in, decisions out"
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, global = true, env = "OPENFRAUD_CONFIG", default_value = "openfraud.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the API and the admin interface. Writes a default configuration
    /// first if there is none.
    Serve,
    /// Check the configuration, with the core and the packs merged in.
    Validate,
    /// List the rule packs shipped in the binary.
    Packs,
    /// Run a scenario file (JSON lines of events and expectations) on a
    /// fresh in-memory engine and report every mismatch.
    Simulate { file: PathBuf },
    /// Replay the stored events through a candidate configuration and print
    /// what would change, rule by rule.
    Replay {
        /// The candidate configuration; the current one when absent.
        #[arg(long)]
        candidate: Option<PathBuf>,
        #[arg(long, default_value_t = 30)]
        days: u64,
    },
    /// Print a new admin token. The old one stops working.
    AdminToken,
    /// Create, list and revoke API keys without the admin interface.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Create a key and print it on stdout. It is shown this once only.
    Add { name: String },
    /// List the keys: id, name, first characters and creation date.
    List,
    /// Revoke the key with this id (see `openfraud key list`).
    Revoke { id: String },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "openfraud=info,warn".into()))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    let cli = Cli::parse();
    if matches!(cli.command, Command::Serve) && !cli.config.exists() {
        write_atomic(&cli.config, DEFAULT_CONFIG.as_bytes(), false)?;
        tracing::info!("wrote the default configuration to {}", cli.config.display());
    }
    let mut config = Config::load(&cli.config)?;
    // Containers listen on every interface without editing the file.
    if let Ok(bind) = std::env::var("OPENFRAUD_BIND") {
        config.server.bind = bind;
    }
    if let Ok(bind) = std::env::var("OPENFRAUD_ADMIN_BIND") {
        config.admin.bind = bind;
    }
    let state_path = config.resolve(&config.server.state_file);

    match cli.command {
        Command::Validate => {
            let assembled = config
                .assemble()
                .map_err(|p| anyhow::anyhow!("the configuration is not valid:\n- {}", p.join("\n- ")))?;
            if let Err(problems) = config.compile() {
                bail!("the configuration is not valid:\n- {}", problems.join("\n- "));
            }
            for warning in config.warnings() {
                eprintln!("warning: {warning}");
            }
            let rules: usize = assembled.workflows.values().map(|w| w.rules.len()).sum();
            println!(
                "{} is valid: {} packs, {} workflows, {} rules, {} counters, {} lists",
                cli.config.display(),
                assembled.packs.len(),
                assembled.workflows.len(),
                rules,
                assembled.counters.len(),
                assembled.lists.len()
            );
        }
        Command::Packs => {
            for (name, text) in openfraud::packs::BUILTIN {
                let pack: toml::Value = toml::from_str(text)?;
                println!("{name:26} {}", pack["pack"]["description"].as_str().unwrap_or_default());
            }
        }
        Command::Simulate { file } => {
            let text = std::fs::read_to_string(&file)?;
            let report = openfraud::scenario::run_scenario(config, &text)?;
            for step in &report.steps {
                let o = &step.outcome;
                println!(
                    "line {:3}  {:28} {:10} would {:10} score {:4}  {}",
                    step.line,
                    o.kind,
                    o.decision.as_str(),
                    o.shadow_decision.as_str(),
                    o.score,
                    if step.problems.is_empty() { "ok" } else { "MISMATCH" }
                );
            }
            let mismatches = report.mismatches();
            if !mismatches.is_empty() {
                for m in &mismatches {
                    eprintln!("{m}");
                }
                bail!("{} mismatches", mismatches.len());
            }
        }
        Command::Replay { candidate, days } => {
            let state = State::load(&state_path)?;
            let key = state
                .pseudonym_key()
                .ok_or_else(|| anyhow::anyhow!("no state file at {}: nothing to replay", state_path.display()))?;
            let database = config.resolve(&config.server.database);
            let source = Engine::open(config.clone(), key, Some(&database))?;
            let candidate = match candidate {
                Some(path) => Config::load(&path)?,
                None => config,
            };
            let since = openfraud::event::now().saturating_sub(days * 86_400);
            let report = openfraud::replay::replay(&source, candidate, since)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::AdminToken => {
            let mut state = State::load(&state_path)?;
            let token = state.rotate_admin_token();
            state.save(&state_path)?;
            println!("{token}");
        }
        Command::Key { action } => {
            let mut state = State::load(&state_path)?;
            match action {
                KeyAction::Add { name } => {
                    let key = state.add_key(&name)?;
                    state.save(&state_path)?;
                    eprintln!("created `{name}`: keep the key now, it is not shown again");
                    println!("{key}");
                }
                KeyAction::List => {
                    for k in &state.api_keys {
                        println!(
                            "{}  {}...  {}  {}",
                            k.id,
                            k.prefix,
                            openfraud::event::format_time(k.created),
                            k.name
                        );
                    }
                }
                KeyAction::Revoke { id } => {
                    if !state.revoke(&id) {
                        bail!("no key with id `{id}` (see `openfraud key list`)");
                    }
                    state.save(&state_path)?;
                    eprintln!("revoked {id}");
                }
            }
        }
        Command::Serve => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(openfraud::run::serve(cli.config, config))?,
    }
    Ok(())
}
