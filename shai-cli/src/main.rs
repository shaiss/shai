#![allow(clippy::module_inception)]
// async_trait-generated futures trip double_must_use on methods returning Result
#![allow(clippy::double_must_use)]
use clap::{Parser, Subcommand};
use crossterm::{
    cursor,
    event::{self, Event, EventStream, KeyCode, KeyEvent, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
    ExecutableCommand,
};
use headless::app::AppHeadless;
use session_options::{SessionOptions, SessionStartError};

use console::strip_ansi_codes;
use futures::StreamExt;
use openai_dive::v1::resources::chat::{ChatMessage, ChatMessageContent};
use ringbuffer::RingBuffer;
use shai_core::agent::builder::AgentBuilder;
use shai_core::agent::LoggingConfig;
use shai_core::config::agent::AgentConfig;
use shai_core::config::anonymous_fallback::{
    confirm_anonymous_fallback, env_anonymous_fallback, evaluate_anonymous_fallback_gate,
    resolve_anonymous_fallback, AnonymousFallbackMode, FallbackGate, FallbackInteraction,
    FallbackSituation, CANCEL_MESSAGE,
};
use shai_core::config::config::ShaiConfig;
use shai_core::config::roles::{PrimaryConfigError, RoleError};
use shai_core::runners::clifixer::fix::clifix;
use shai_llm::LlmClient;
use std::env;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, sleep};
use tui::auth::AppAuth;
use tui::theme::logo_cyan;
use tui::App;

#[cfg(unix)]
mod fc;
mod headless;
mod import;
mod session_options;
#[cfg(unix)]
mod shell;

#[cfg(unix)]
use fc::history::CommandHistoryExt;
mod tui;

#[cfg(unix)]
use fc::client::ShaiSessionClient;
#[cfg(unix)]
use shell::pty::ShaiPtyManager;
#[cfg(unix)]
use shell::rc::{get_shell, ShellType};

use crate::headless::tools::list_all_tools;

/// Sentinel value for `--restore` used without a session ID (opens the picker).
const RESTORE_PICKER_SENTINEL: &str = "@picker";

#[derive(Parser)]
#[command(name = "shai")]
#[command(about = "SHAI - Smart terminal wrapper with advanced features")]
#[command(subcommand_required = false)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    /// Dump entire trace upon completion (headless mode only)
    #[arg(long, global = true)]
    trace: bool,
    /// the url to pull the default shai config
    #[arg(long)]
    default_shai_config_url: Option<String>,
    /// List all available tools
    #[arg(long)]
    list_tools: bool,
    /// Only allow these tools (comma-separated). With --agent, restricts the agent's tools; its MCP tools are listed as <server>:<tool>
    #[arg(long)]
    tools: Option<String>,
    /// Remove specific tools (comma-separated), also from the --agent's tools (MCP tools as <server>:<tool>)
    #[arg(long)]
    remove: Option<String>,
    /// Headless mode only: allow tools that write files, run bash or use the
    /// network. Without it, headless runs only read-only tools and deny the rest
    #[arg(long)]
    yes: bool,
    /// Set the LLM sampling temperature (default: 0.0)
    #[arg(long)]
    temperature: Option<f32>,
    /// Show version information
    #[arg(short, long)]
    version: bool,
    /// Restore a previous session by session ID.
    /// Without an ID, opens the session picker (TUI only).
    #[arg(short, long, num_args = 0..=1, default_missing_value = "@picker")]
    restore: Option<String>,
    /// Restore the most recent session automatically
    #[arg(long)]
    latest: bool,
    /// Headless mode with prompt
    #[arg(short, long)]
    prompt: Option<String>,
    /// Use specific agent
    #[arg(short, long)]
    agent: Option<String>,
    /// Interactive mode: pipe input then show TUI with context
    #[arg(short, long)]
    interactive: bool,
    /// Hand the session off to another model after the first edit:
    /// a role name or <provider>/<model> (overrides prewalk.into)
    #[arg(long, value_name = "ROLE_OR_MODEL")]
    prewalk_into: Option<String>,
    /// Have a second model (the "advisor" role) review the agent's steps, read-only
    #[arg(long)]
    advisor: bool,
}

#[derive(Subcommand)]
enum Commands {
    #[cfg(unix)]
    /// Start a PTY session with the specified shell
    On {
        /// Shell to run (defaults to $SHELL or /bin/sh)
        #[arg(short, long)]
        shell: Option<ShellType>,
        /// Suppress shell session restoration messages
        #[arg(long, default_value_t = true)]
        quiet: bool,
    },
    #[cfg(unix)]
    /// Exit the current PTY session
    Off,
    #[cfg(unix)]
    /// Is the session on or not
    Status,
    /// Configure SHAI with your AI provider
    Auth,
    /// Agent management commands
    Agent {
        /// Agent name or "list" to list agents
        name: Option<String>,
    },
    /// Session management commands
    Session {
        /// Session ID or "latest" to restore the most recent session
        id: Option<String>,
    },
    /// List agents, sessions, or skills
    List {
        #[command(subcommand)]
        what: Option<ListTarget>,
    },
    #[cfg(unix)]
    /// Send pre-command hook (before command execution)
    #[command(hide = true)]
    Precmd {
        /// The command that is about to be executed
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    #[cfg(unix)]
    /// Send post-command hook (analyze last command)
    #[command(hide = true)]
    Postcmd {
        /// Exit code of the last command
        exit_code: i32,
        /// The command that was executed (optional)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Start HTTP server with SSE streaming
    Serve {
        /// Host to bind to (0.0.0.0 for all interfaces, 127.0.0.1 for localhost only)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port to bind to
        #[arg(short, long, default_value = "3000")]
        port: u16,
        /// Agent name to serve (optional)
        agent: Option<String>,
        /// Use ephemeral mode (spawn new agent per request)
        #[arg(long)]
        ephemeral: bool,
        /// Maximum number of concurrent sessions (None = unlimited)
        #[arg(long)]
        max_sessions: Option<usize>,
        /// Allow tools that write files, run bash or use the network in every
        /// session. Without it, sessions run only read-only tools and deny the rest
        #[arg(long)]
        yes: bool,
    },
    /// Import configuration from .claude or .cursor into AGENTS.md
    Import {
        /// Overwrite existing AGENTS.md instead of appending
        #[arg(long)]
        overwrite: bool,
    },
}

#[derive(Subcommand)]
enum ListTarget {
    /// List available agents
    Agent,
    /// List saved sessions
    Session,
    /// List available skills
    Skills,
}

/// Whether this invocation starts an agent session, in the TUI or headless.
fn starts_session(cli: &Cli) -> bool {
    match &cli.command {
        None => !cli.list_tools && !cli.version,
        Some(Commands::Agent { name }) => name.as_deref() != Some("list"),
        Some(Commands::Session { .. }) => true,
        Some(_) => false,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if !matches!(cli.command, Some(Commands::Serve { .. }))
        && (env::var_os("SHAI_LOG_LEVEL").is_some() || env::var_os("SHAI_LOG_FILE").is_some())
    {
        let _ = LoggingConfig::from_env().init();
    }

    let session_starts = starts_session(&cli);
    let default_url = cli.default_shai_config_url.clone();

    // Asking for session options where they cannot apply is an error.
    // Resolution itself waits until after the fallback gate (and any
    // allowed starter config), so `--prewalk-into` and `--advisor` can see
    // a just-provisioned config on a fresh profile.
    if !session_starts {
        for (given, flag) in [
            (cli.prewalk_into.is_some(), "--prewalk-into"),
            (cli.advisor, "--advisor"),
        ] {
            if given {
                eprintln!(
                    "error: {} only applies to commands that start an agent session",
                    flag
                );
                std::process::exit(2);
            }
        }
    }

    match cli.command {
        #[cfg(unix)]
        Some(Commands::On { shell, quiet }) => {
            default_config(default_url).await;
            run_pty(shell, quiet)?;
        }
        #[cfg(unix)]
        Some(Commands::Off) => {
            default_config(default_url).await;
            kill_pty()?;
        }
        #[cfg(unix)]
        Some(Commands::Status) => {
            default_config(default_url).await;
            pty_status()?;
        }
        Some(Commands::Auth) => {
            default_config(default_url).await;
            handle_config().await?;
        }
        Some(Commands::Agent { name }) => match name.as_deref() {
            Some("list") => {
                default_config(default_url).await;
                list_agents();
            }
            Some(name) => {
                let session_options = prepare_and_resolve_or_exit(
                    interactive_session_interaction(),
                    Some(name),
                    default_url,
                    cli.prewalk_into.as_deref(),
                    cli.advisor,
                )
                .await;
                handle_main(Some(name.to_string()), None, None, session_options).await?;
            }
            None => {
                let session_options = prepare_and_resolve_or_exit(
                    interactive_session_interaction(),
                    None,
                    default_url,
                    cli.prewalk_into.as_deref(),
                    cli.advisor,
                )
                .await;
                handle_main(
                    None,
                    None,
                    Some(tui::app::InitialModal::AgentPicker),
                    session_options,
                )
                .await?;
            }
        },
        Some(Commands::Session { id }) => match id.as_deref() {
            Some("latest") => {
                let restore_id = match shai_core::session::SessionPersist::list_sessions() {
                    Ok(sessions) if !sessions.is_empty() => Some(sessions[0].session_id.clone()),
                    _ => {
                        eprintln!("No previous session found.");
                        return Ok(());
                    }
                };
                let session_options = prepare_and_resolve_or_exit(
                    interactive_session_interaction(),
                    None,
                    default_url,
                    cli.prewalk_into.as_deref(),
                    cli.advisor,
                )
                .await;
                handle_main(None, restore_id, None, session_options).await?;
            }
            Some(id) => {
                let session_options = prepare_and_resolve_or_exit(
                    interactive_session_interaction(),
                    None,
                    default_url,
                    cli.prewalk_into.as_deref(),
                    cli.advisor,
                )
                .await;
                handle_main(None, Some(id.to_string()), None, session_options).await?;
            }
            None => {
                let session_options = prepare_and_resolve_or_exit(
                    interactive_session_interaction(),
                    None,
                    default_url,
                    cli.prewalk_into.as_deref(),
                    cli.advisor,
                )
                .await;
                handle_main(
                    None,
                    None,
                    Some(tui::app::InitialModal::SessionPicker),
                    session_options,
                )
                .await?;
            }
        },
        Some(Commands::List { what }) => {
            default_config(default_url).await;
            match what {
                Some(ListTarget::Agent) => list_agents(),
                Some(ListTarget::Session) => list_sessions(),
                Some(ListTarget::Skills) => list_skills(),
                None => {
                    list_agents();
                    println!();
                    list_sessions();
                    println!();
                    list_skills();
                }
            }
        }
        #[cfg(unix)]
        Some(Commands::Precmd { command }) => {
            default_config(default_url).await;
            let command_str = command.join(" ");
            handle_precmd(command_str)?;
        }
        #[cfg(unix)]
        Some(Commands::Postcmd { exit_code, command }) => {
            let command_str = command.join(" ");
            handle_postcmd(exit_code, command_str, default_url).await?;
        }
        Some(Commands::Serve {
            host,
            port,
            agent,
            ephemeral,
            max_sessions,
            yes,
        }) => {
            // The HTTP server does not yet use `--agent`, so the gate must
            // not treat a named agent as the provider the server will run.
            let startup_primary =
                prepare_session_or_exit(FallbackInteraction::NonInteractive, None, default_url)
                    .await;
            handle_serve(
                host,
                port,
                agent,
                ephemeral,
                max_sessions,
                yes,
                startup_primary,
            )
            .await?;
        }
        Some(Commands::Import { overwrite }) => {
            default_config(default_url).await;
            handle_import(overwrite)?;
        }
        None => {
            // Check for stdin input
            let stdin_input = if !io::stdin().is_terminal() {
                let mut buffer = String::new();
                io::stdin().read_to_string(&mut buffer)?;
                Some(buffer.trim().to_string()).filter(|s| !s.is_empty())
            } else {
                None
            };

            // Handle --list-tools flag
            if cli.list_tools {
                default_config(default_url).await;
                list_all_tools();
                return Ok(());
            }

            // Handle --version flag
            if cli.version {
                default_config(default_url).await;
                show_version()?;
                return Ok(());
            }

            // Handle --prompt flag (headless mode)
            if let Some(prompt) = cli.prompt {
                if cli.restore.as_deref() == Some(RESTORE_PICKER_SENTINEL) {
                    eprintln!(
                        "--restore without a session ID requires the TUI. \
                         Use --restore <id>, --latest, or `shai session`."
                    );
                    return Ok(());
                }
                let mut messages = vec![prompt];
                if let Some(ref stdin_content) = stdin_input {
                    messages.push(stdin_content.clone());
                }
                let session_options = prepare_and_resolve_or_exit(
                    FallbackInteraction::NonInteractive,
                    cli.agent.as_deref(),
                    default_url,
                    cli.prewalk_into.as_deref(),
                    cli.advisor,
                )
                .await;
                if let Err(err) = handle_fix(HeadlessRun {
                    prompt: messages,
                    tools: cli.tools,
                    remove: cli.remove,
                    trace: cli.trace,
                    agent_name: cli.agent,
                    temperature: cli.temperature,
                    yes: cli.yes,
                    session_options,
                })
                .await
                {
                    exit_session_error(err);
                }
                return Ok(());
            }

            // Handle piped stdin without --prompt
            if let Some(stdin_content) = stdin_input {
                if cli.restore.as_deref() == Some(RESTORE_PICKER_SENTINEL) {
                    eprintln!(
                        "--restore without a session ID requires the TUI. \
                         Use --restore <id>, --latest, or `shai session`."
                    );
                    return Ok(());
                }
                if cli.interactive {
                    // Interactive mode: show TUI with piped content as initial prompt.
                    // Stdin is not a TTY here, so the gate warns instead of prompting.
                    let session_options = prepare_and_resolve_or_exit(
                        FallbackInteraction::NonInteractive,
                        cli.agent.as_deref(),
                        default_url,
                        cli.prewalk_into.as_deref(),
                        cli.advisor,
                    )
                    .await;
                    handle_main_with_prompt(cli.agent.clone(), stdin_content, session_options)
                        .await?;
                    return Ok(());
                } else {
                    // Headless mode from pipe
                    let session_options = prepare_and_resolve_or_exit(
                        FallbackInteraction::NonInteractive,
                        cli.agent.as_deref(),
                        default_url,
                        cli.prewalk_into.as_deref(),
                        cli.advisor,
                    )
                    .await;
                    if let Err(err) = handle_fix(HeadlessRun {
                        prompt: vec![stdin_content],
                        tools: cli.tools,
                        remove: cli.remove,
                        trace: cli.trace,
                        agent_name: cli.agent,
                        temperature: cli.temperature,
                        yes: cli.yes,
                        session_options,
                    })
                    .await
                    {
                        exit_session_error(err);
                    }
                    return Ok(());
                }
            }

            // No input, show TUI
            if cli.restore.as_deref() == Some(RESTORE_PICKER_SENTINEL) {
                // Bare `--restore`: open the session picker
                let session_options = prepare_and_resolve_or_exit(
                    interactive_session_interaction(),
                    cli.agent.as_deref(),
                    default_url,
                    cli.prewalk_into.as_deref(),
                    cli.advisor,
                )
                .await;
                handle_main(
                    cli.agent.clone(),
                    None,
                    Some(tui::app::InitialModal::SessionPicker),
                    session_options,
                )
                .await?;
                return Ok(());
            }
            let restore_id = if cli.latest {
                match shai_core::session::SessionPersist::list_sessions() {
                    Ok(sessions) if !sessions.is_empty() => Some(sessions[0].session_id.clone()),
                    _ => {
                        eprintln!("No previous session found.");
                        return Ok(());
                    }
                }
            } else {
                cli.restore.clone()
            };
            let session_options = prepare_and_resolve_or_exit(
                interactive_session_interaction(),
                cli.agent.as_deref(),
                default_url,
                cli.prewalk_into.as_deref(),
                cli.advisor,
            )
            .await;
            handle_main(cli.agent.clone(), restore_id, None, session_options).await?;
        }
    }

    Ok(())
}

async fn default_config(default_config_url: Option<String>) {
    if let Some(env_setting) = env_anonymous_fallback() {
        if resolve_anonymous_fallback(None, Some(&env_setting)).mode == AnonymousFallbackMode::Deny
        {
            return;
        }
    }

    // One look at the config decides. Looking twice could see it broken and
    // then fine, while another process writes it, and fetch a starter config
    // over it.
    match ShaiConfig::load_for_roles() {
        Ok(_) => return,
        // A config file that is there and does not load, the legacy one
        // included, is the user's to fix: it is neither replaced nor shadowed
        // by a starter config. The warning says where it is broken and not
        // what it holds: the parser's own message can quote a value, and the
        // file holds credentials.
        Err(shai_core::config::roles::RoleError::ConfigInvalid { path, reason }) => {
            eprintln!("Warning: failed to load config at {}: {}", path, reason);
            return;
        }
        Err(_) => {}
    }

    let _ = fetch_and_save_default_config(default_config_url).await;
}

async fn fetch_and_save_default_config(default_config_url: Option<String>) -> ShaiConfig {
    let default_url = match default_config_url {
        Some(url) => url,
        None => {
            "https://raw.githubusercontent.com/ovh/shai/refs/heads/main/.shai.config".to_string()
        }
    };

    let config = if let Ok(parsed_url) = default_url.parse() {
        ShaiConfig::pull_from_url(parsed_url)
            .await
            .unwrap_or_else(|_| ShaiConfig::default())
    } else {
        ShaiConfig::default()
    };

    let _ = config.save();
    config
}

async fn provision_default_config(
    default_config_url: Option<String>,
    loaded: Option<ShaiConfig>,
    allow_fallback_provision: bool,
) -> Result<ShaiConfig, PrimaryConfigError> {
    if let Some(config) = loaded {
        return Ok(config);
    }
    if !allow_fallback_provision {
        return Err(PrimaryConfigError::Missing);
    }
    let config = fetch_and_save_default_config(default_config_url).await;
    apply_provisioned_snapshot_policy(config)
}

/// Re-evaluate a just-provisioned starter config. The pre-download gate has
/// already run against the empty profile (prompt by default). If the saved
/// snapshot itself denies anonymous OVH, the first run must refuse the same
/// way a later run would.
fn apply_provisioned_snapshot_policy(config: ShaiConfig) -> Result<ShaiConfig, PrimaryConfigError> {
    let env_setting = env_anonymous_fallback();
    let resolution =
        resolve_anonymous_fallback(config.anonymous_fallback.as_deref(), env_setting.as_deref());
    let situation = fallback_situation(Some(&config), None);
    match evaluate_anonymous_fallback_gate(
        resolution,
        situation,
        FallbackInteraction::NonInteractive,
    ) {
        FallbackGate::Refuse { message, .. } => Err(PrimaryConfigError::Other(message)),
        _ => Ok(config),
    }
}

/// Map a provision result so a deny is a refused `SessionStartError` and
/// reaches `exit_session_error` through every `prepare_session_or_exit` caller.
fn provisioned_session(
    result: Result<ShaiConfig, PrimaryConfigError>,
) -> Result<Result<ShaiConfig, PrimaryConfigError>, SessionStartError> {
    match result {
        Ok(config) => Ok(Ok(config)),
        Err(error) => Err(error.into()),
    }
}

fn interactive_session_interaction() -> FallbackInteraction {
    if io::stdin().is_terminal() {
        FallbackInteraction::InteractiveTty
    } else {
        FallbackInteraction::NonInteractive
    }
}

fn fallback_situation(loaded: Option<&ShaiConfig>, agent_name: Option<&str>) -> FallbackSituation {
    if let Some(name) = agent_name {
        if let Some(anonymous) = AgentConfig::explicit_provider_is_anonymous_ovh(name) {
            return if anonymous {
                FallbackSituation::AnonymousOvh
            } else {
                FallbackSituation::Configured
            };
        }
    }
    match loaded {
        Some(config) if config.selected_is_anonymous_ovh() => FallbackSituation::AnonymousOvh,
        Some(_) => FallbackSituation::Configured,
        None => FallbackSituation::MissingConfig,
    }
}

fn exit_session_error(err: SessionStartError) -> ! {
    eprintln!("error: {err}");
    std::process::exit(err.exit_code());
}

/// Apply the anonymous-fallback setting before a session starts. On deny, an
/// unreadable config, or an invalid value this returns a typed error with exit
/// code 2 and does not provision a default config or start a network request.
/// Returns the single loaded (or provisioned) primary config snapshot so
/// callers do not re-read `auth.config.json` after the gate passes.
async fn prepare_session(
    interaction: FallbackInteraction,
    agent_name: Option<&str>,
    default_config_url: Option<String>,
) -> Result<Result<ShaiConfig, PrimaryConfigError>, SessionStartError> {
    let loaded = match ShaiConfig::load_for_roles() {
        Ok(config) => Some(config),
        Err(RoleError::ConfigMissing) => None,
        Err(RoleError::ConfigInvalid { path, reason }) => {
            return Err(PrimaryConfigError::Invalid { path, reason }.into());
        }
        Err(other) => {
            return Err(PrimaryConfigError::Other(other.to_string()).into());
        }
    };
    let config_setting = loaded
        .as_ref()
        .and_then(|config| config.anonymous_fallback.as_deref());
    let env_setting = env_anonymous_fallback();
    let resolution = resolve_anonymous_fallback(config_setting, env_setting.as_deref());
    resolution.log();

    let allow_fallback_provision = resolution.mode == AnonymousFallbackMode::Prompt;
    let situation = fallback_situation(loaded.as_ref(), agent_name);

    match evaluate_anonymous_fallback_gate(resolution, situation, interaction) {
        FallbackGate::Proceed {
            first_run_warning, ..
        } => {
            if let Some(warning) = first_run_warning {
                eprintln!("{warning}");
            }
            provisioned_session(
                provision_default_config(default_config_url, loaded, allow_fallback_provision)
                    .await,
            )
        }
        FallbackGate::NeedConfirm { prompt, .. } => {
            let mut stdin = io::stdin().lock();
            let mut stderr = io::stderr();
            let accepted = confirm_anonymous_fallback(&mut stdin, &mut stderr, prompt)
                .map_err(|e| SessionStartError::other(e.to_string()))?;
            if accepted {
                provisioned_session(
                    provision_default_config(default_config_url, loaded, allow_fallback_provision)
                        .await,
                )
            } else {
                Err(SessionStartError::other(CANCEL_MESSAGE))
            }
        }
        FallbackGate::Refuse { message, .. } => Err(SessionStartError::refused(message)),
    }
}

async fn prepare_session_or_exit(
    interaction: FallbackInteraction,
    agent_name: Option<&str>,
    default_config_url: Option<String>,
) -> Result<ShaiConfig, PrimaryConfigError> {
    match prepare_session(interaction, agent_name, default_config_url).await {
        Ok(primary) => primary,
        Err(error) => exit_session_error(error),
    }
}

/// Apply the fallback gate, provision a starter config if allowed, then
/// resolve session options against the resulting config without re-reading disk.
async fn prepare_and_resolve_or_exit(
    interaction: FallbackInteraction,
    agent_name: Option<&str>,
    default_config_url: Option<String>,
    prewalk_into: Option<&str>,
    advisor: bool,
) -> SessionOptions {
    let startup_primary =
        prepare_session_or_exit(interaction, agent_name, default_config_url).await;
    let missing = RoleError::ConfigMissing;
    let loaded = match &startup_primary {
        Ok(config) => Ok(config),
        Err(_) => Err(&missing),
    };
    SessionOptions::resolve_from_loaded_or_exit(
        prewalk_into,
        advisor,
        loaded,
        startup_primary.clone(),
    )
}

async fn handle_main(
    agent_name: Option<String>,
    restore_session_id: Option<String>,
    initial_modal: Option<tui::app::InitialModal>,
    session_options: SessionOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut app = App::new();
    app.session_options = session_options;
    if let Some(modal) = initial_modal {
        app.initial_modal = modal;
    }
    if let Err(e) = app.run(agent_name, restore_session_id).await {
        exit_session_error(e);
    }
    Ok(())
}

async fn handle_main_with_prompt(
    agent_name: Option<String>,
    prompt: String,
    session_options: SessionOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut app = App::new();
    app.session_options = session_options;
    app.initial_prompt = Some(prompt);
    if let Err(e) = app.run(agent_name, None).await {
        exit_session_error(e);
    }
    Ok(())
}

async fn handle_config() -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = AppAuth::new();
    auth.run().await;

    // Standalone entry point: the auth view enabled raw mode and hid the
    // cursor, restore both before handing the terminal back to the shell.
    // (When the auth view runs embedded via /auth, the main TUI owns those.)
    let _ = io::stdout().execute(cursor::Show);
    let _ = disable_raw_mode();
    Ok(())
}

/// Everything a headless run (`-p` or piped stdin) needs from the command line.
struct HeadlessRun {
    prompt: Vec<String>,
    tools: Option<String>,
    remove: Option<String>,
    trace: bool,
    agent_name: Option<String>,
    temperature: Option<f32>,
    /// `--yes`: allow tools that write, run bash or use the network.
    yes: bool,
    session_options: SessionOptions,
}

async fn handle_fix(run: HeadlessRun) -> Result<(), SessionStartError> {
    let HeadlessRun {
        prompt,
        tools,
        remove,
        trace,
        agent_name,
        temperature,
        yes,
        session_options,
    } = run;
    let initial_trace: Vec<ChatMessage> = prompt
        .into_iter()
        .map(|p| ChatMessage::User {
            content: ChatMessageContent::Text(p),
            name: None,
        })
        .collect();

    let mut app = AppHeadless::new();
    if let Some(temp) = temperature {
        app.set_temperature(temp);
    }
    app.set_session_options(session_options);
    app.run(initial_trace, tools, remove, trace, agent_name, yes)
        .await
}

fn show_version() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{} version {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
    Ok(())
}

#[cfg(unix)]
fn run_pty(shell: Option<ShellType>, quiet: bool) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("SHAI_SESSION_ID").is_ok() {
        eprintln!("Already inside a SHAI session");
        return Ok(());
    }

    let mut pty = ShaiPtyManager::new()?;
    let shell = get_shell(shell)?;
    pty.start_session(shell, quiet)?;
    Ok(())
}

#[cfg(unix)]
fn kill_pty() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("SHAI_SESSION_ID").is_err() {
        eprintln!("Not currently inside a SHAI session");
        return Ok(());
    }

    let ppid = unsafe { libc::getppid() };
    unsafe {
        libc::kill(ppid, libc::SIGHUP);
    }
    std::process::exit(0);
}

#[cfg(unix)]
fn pty_status() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("SHAI_SESSION_ID").is_ok() {
        eprintln!("shAI is enabled");
    } else {
        eprintln!("shAI is disabled");
    }
    Ok(())
}

#[cfg(unix)]
pub fn handle_precmd(command: String) -> Result<(), Box<dyn std::error::Error>> {
    env::var("SHAI_SESSION_ID").ok().and_then(|session_id| {
        let client = ShaiSessionClient::new(&session_id);
        client
            .session_exists()
            .then(|| client.pre_command(&command))
    });
    Ok(())
}

#[cfg(unix)]
pub async fn handle_postcmd(
    exit_code: i32,
    command: String,
    default_config_url: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    env::var("SHAI_SESSION_ID").ok().and_then(|session_id| {
        let client = ShaiSessionClient::new(&session_id);
        client
            .session_exists()
            .then(|| client.post_command(exit_code, &command))
    });

    match exit_code {
        0 => {
            return Ok(());
        }
        code if code >= 128 => {
            return Ok(());
        }
        _ => {
            // A failed command must not start a fix on the built-in default
            // model when the auth config is there and cannot be read. Load
            // once as soon as this hook might suggest a fix, so the user is
            // told even if the session history is empty.
            let primary = if env::var("SHAI_SESSION_ID").is_ok() {
                let startup_primary = prepare_session_or_exit(
                    FallbackInteraction::NonInteractive,
                    None,
                    default_config_url,
                )
                .await;
                match startup_primary {
                    Ok(config) => Some(config),
                    Err(error) => {
                        exit_session_error(error.into());
                    }
                }
            } else {
                None
            };

            let last_terminal_output = env::var("SHAI_SESSION_ID").ok().and_then(|session_id| {
                let client = ShaiSessionClient::new(&session_id);
                client.session_exists().then(|| {
                    client
                        .get_last_commands(50)
                        .unwrap_or_else(|_| vec![].into())
                })
            });

            if let Some(cmd) = last_terminal_output {
                let trace = vec![ChatMessage::User {
                    content: ChatMessageContent::Text(cmd.export_as_text()),
                    name: None,
                }];

                let config = primary.expect("SHAI_SESSION_ID was set above");
                let (llm, model) = config.get_llm_from_config().await?;

                enable_raw_mode().unwrap();
                let mut events = EventStream::new();
                let mut ticker = interval(Duration::from_millis(100));
                let spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
                let mut spinner_index = 0;

                let mut clifix_task =
                    tokio::spawn(async move { clifix(Arc::new(llm), model, trace).await });

                let result = loop {
                    tokio::select! {
                        result = &mut clifix_task => {
                            break result.unwrap();
                        }

                        maybe_event = events.next() => {
                            if let Some(Ok(Event::Key(KeyEvent { code: KeyCode::Esc, .. }))) = maybe_event {
                                clifix_task.abort();
                                disable_raw_mode().unwrap();
                                eprintln!("\r\x1b[2K\x1b[2mCancelled.\x1b[0m");
                                return Ok(());
                            }
                        }

                        _ = ticker.tick() => {
                            eprint!("\r\x1b[2mAnalyzing command... {} (Press ESC to cancel)\x1b[0m", spinner_chars[spinner_index]);
                            io::stdout().flush().unwrap();
                            spinner_index = (spinner_index + 1) % spinner_chars.len();
                        }
                    }
                };

                disable_raw_mode().unwrap();
                eprint!("\r\x1b[2K");

                if let Ok(res) = result {
                    if let Some(rational) = &res.short_rational {
                        eprintln!("\n\x1b[2m{}\x1b[0m\n", rational);
                    }
                    eprintln!("\x1b[38;5;206m❯\x1b[0m \x1b[1m{}\x1b[0m", res.fixed_cli);
                    eprintln!("\n\x1b[2m ↵ Run • Esc / Ctrl+C Cancel\x1b[0m");

                    io::stdout().execute(cursor::MoveUp(3)).unwrap();
                    io::stdout()
                        .execute(cursor::MoveToColumn((res.fixed_cli.len() + 3) as u16))
                        .unwrap();
                    io::stdout().flush().unwrap();
                    enable_raw_mode().unwrap();

                    loop {
                        if let Ok(Event::Key(KeyEvent {
                            code, modifiers, ..
                        })) = event::read()
                        {
                            match (code, modifiers) {
                                (KeyCode::Enter, _) => {
                                    disable_raw_mode().unwrap();
                                    io::stdout().execute(cursor::MoveDown(3)).unwrap();
                                    io::stdout().execute(cursor::MoveToColumn(0)).unwrap();
                                    println!();

                                    let mut cmd = Command::new("sh");
                                    cmd.arg("-c").arg(&res.fixed_cli);
                                    cmd.envs(env::vars());

                                    match cmd.status() {
                                        Ok(status) => {
                                            if status.success() {
                                                shell::rc::write_to_shell_history(&res.fixed_cli);
                                            }
                                        }
                                        Err(e) => eprintln!("Failed to execute command: {}\n", e),
                                    }
                                    break;
                                }
                                (KeyCode::Esc, _) => {
                                    disable_raw_mode().unwrap();
                                    println!();
                                    break;
                                }
                                (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                                    disable_raw_mode().unwrap();
                                    println!();
                                    eprintln!("Exiting...");
                                    std::process::exit(0);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn handle_import(overwrite: bool) -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::current_dir()?;
    match import::import_to_agents_md(&base, overwrite) {
        Ok((path, count)) => {
            println!(
                "\x1b[32m✓\x1b[0m Imported {} config(s) into {}",
                count,
                path.display()
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m {}", e);
            std::process::exit(1);
        }
    }
}

async fn handle_serve(
    host: String,
    port: u16,
    agent: Option<String>,
    ephemeral: bool,
    max_sessions: Option<usize>,
    yes: bool,
    startup_primary: Result<ShaiConfig, PrimaryConfigError>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Pass the single startup snapshot to every HTTP session so a later edit
    // cannot change credentials or silently fall back.
    let primary = match startup_primary {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {}", error);
            std::process::exit(2);
        }
    };

    if let Some(ref agent_name) = agent {
        if let Err(error) = AgentConfig::load_with_primary(agent_name, Some(&primary)) {
            eprintln!("error: {}", error);
            std::process::exit(2);
        }
    }

    // Initialize tracing for HTTP server logs
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .with_env_filter("shai_http=debug")
        .init();

    println!("{}", logo_cyan());

    let addr = format!("{}:{}", host, port);
    let config = shai_http::ServerConfig::new(addr)
        .with_ephemeral(ephemeral)
        .with_max_sessions(max_sessions)
        .with_allow_all_tools(yes)
        .with_primary_config(primary)
        .with_default_agent(agent);

    shai_http::start_server(config).await?;

    Ok(())
}

fn list_agents() {
    let agents = match AgentConfig::list_agents() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Failed to list agents: {}", e);
            return;
        }
    };

    if agents.is_empty() {
        println!("No custom agents found.");
        println!("Create agent configs in ~/.config/shai/agents/");
        return;
    }

    println!("Available agents:");
    let max_name_len = agents.iter().map(|name| name.len()).max().unwrap_or(0);

    for agent in agents {
        match AgentConfig::load(&agent) {
            Ok(config) => {
                println!(
                    "  \x1b[1m{:<width$}\x1b[0m \x1b[2m{}\x1b[0m",
                    agent,
                    config.description,
                    width = max_name_len
                );
            }
            Err(e) => {
                eprintln!(
                    "  \x1b[1m{:<width$}\x1b[0m \x1b[2m(config error: {})\x1b[0m",
                    agent,
                    e,
                    width = max_name_len
                );
            }
        }
    }
}

fn list_sessions() {
    match shai_core::session::SessionPersist::list_sessions() {
        Ok(sessions) => {
            if sessions.is_empty() {
                println!("No saved sessions found.");
                return;
            }

            println!("Saved sessions:");
            for session in &sessions {
                let id_short = &session.session_id[..8.min(session.session_id.len())];
                let name = session.name.as_deref().unwrap_or("unnamed");
                println!("  \x1b[1m{:<20}\x1b[0m \x1b[2m({})\x1b[0m", name, id_short);
            }
        }
        Err(e) => {
            eprintln!("Failed to list sessions: {}", e);
        }
    }
}

fn list_skills() {
    let skills = shai_core::tools::skills::discovery::discover_skills();
    if skills.is_empty() {
        println!("No skills found.");
        return;
    }

    println!("Available skills:");
    for skill in &skills {
        if skill.description.is_empty() {
            println!(
                "  \x1b[36m\u{2022}\x1b[0m {} \x1b[90m({})\x1b[0m",
                skill.name,
                skill.source()
            );
        } else {
            println!(
                "  \x1b[36m\u{2022}\x1b[0m \x1b[1m{}\x1b[0m \u{2014} {} \x1b[90m({})\x1b[0m",
                skill.name,
                skill.description,
                skill.source()
            );
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn session_options_only_apply_where_a_session_starts() {
        for args in [
            &["shai"][..],
            &["shai", "-p", "do it"],
            &["shai", "--latest"],
            &["shai", "agent"],
            &["shai", "agent", "reviewer"],
            &["shai", "session"],
            &["shai", "session", "latest"],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(starts_session(&cli), "{args:?}");
        }
        for args in [
            &["shai", "--list-tools"][..],
            &["shai", "--version"],
            &["shai", "agent", "list"],
            &["shai", "auth"],
            &["shai", "import"],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(!starts_session(&cli), "{args:?}");
        }
    }

    #[test]
    fn prewalk_is_off_unless_asked_for() {
        let cli = Cli::try_parse_from(["shai"]).unwrap();
        assert!(cli.prewalk_into.is_none());
        let cli = Cli::try_parse_from(["shai", "-p", "do it"]).unwrap();
        assert!(cli.prewalk_into.is_none());
    }

    #[test]
    fn advisor_is_a_plain_switch_and_off_by_default() {
        assert!(!Cli::try_parse_from(["shai"]).unwrap().advisor);
        assert!(
            !Cli::try_parse_from(["shai", "-p", "do it"])
                .unwrap()
                .advisor
        );

        let cli = Cli::try_parse_from(["shai", "--advisor", "-p", "do it"]).unwrap();
        assert!(cli.advisor);
        assert_eq!(cli.prompt.as_deref(), Some("do it"));

        // It takes no value, so it cannot swallow what follows it.
        let cli = Cli::try_parse_from(["shai", "--advisor", "agent", "reviewer"]).unwrap();
        assert!(cli.advisor);
        assert!(matches!(cli.command, Some(Commands::Agent { .. })));
        assert!(Cli::try_parse_from(["shai", "--advisor=yes"]).is_err());
    }

    #[test]
    fn prewalk_into_takes_a_role_or_a_model_reference() {
        let cli = Cli::try_parse_from(["shai", "--prewalk-into", "cheap"]).unwrap();
        assert_eq!(cli.prewalk_into.as_deref(), Some("cheap"));

        let cli =
            Cli::try_parse_from(["shai", "-p", "do it", "--prewalk-into=ollama/qwen3:8b"]).unwrap();
        assert_eq!(cli.prewalk_into.as_deref(), Some("ollama/qwen3:8b"));
        assert_eq!(cli.prompt.as_deref(), Some("do it"));

        // The flag needs a value.
        assert!(Cli::try_parse_from(["shai", "--prewalk-into"]).is_err());
    }

    #[tokio::test]
    async fn deleting_auth_config_after_prepare_session_does_not_switch_to_anonymous_ovh() {
        let _guard = tui::app::tests::CONFIG_HOME_LOCK.lock().await;
        let prev_fb = std::env::var_os("SHAI_ANONYMOUS_FALLBACK");
        std::env::remove_var("SHAI_ANONYMOUS_FALLBACK");

        let dir = tempfile::TempDir::new().unwrap();
        let shai_dir = dir.path().join("shai");
        std::fs::create_dir_all(&shai_dir).unwrap();
        let auth_path = shai_dir.join("auth.config.json");
        std::fs::write(
            &auth_path,
            r#"{"providers":[{"provider":"openai","env_vars":{"OPENAI_API_KEY":"k"},"model":"gpt-4o","tool_method":"FunctionCall"}],"selected_provider":0}"#,
        )
        .unwrap();
        let _home = tui::app::tests::ConfigHomeGuard::set(dir.path());

        let options = prepare_and_resolve_or_exit(
            FallbackInteraction::NonInteractive,
            None,
            None,
            None,
            false,
        )
        .await;

        // Auth config vanishes before headless/TUI starts its agent.
        std::fs::remove_file(&auth_path).unwrap();

        let headless_cfg = options
            .startup_primary_config()
            .expect("headless startup_primary_config should use the snapshot");
        assert_eq!(
            headless_cfg.get_selected_provider().unwrap().provider,
            "openai",
            "headless must keep the config that passed prepare_session instead of falling back to anonymous OVH"
        );

        let tui_prepared =
            tui::app::App::load_initial_prepared(None, options.startup_primary_ref())
                .expect("TUI initial load should use the snapshot");
        match tui_prepared {
            tui::app::PreparedAgent::Primary(cfg) => assert_eq!(
                cfg.get_selected_provider().unwrap().provider,
                "openai",
                "TUI must keep the config that passed prepare_session instead of falling back to anonymous OVH"
            ),
            tui::app::PreparedAgent::Named { .. } => panic!("expected primary"),
        }

        match prev_fb {
            Some(v) => std::env::set_var("SHAI_ANONYMOUS_FALLBACK", v),
            None => std::env::remove_var("SHAI_ANONYMOUS_FALLBACK"),
        }
    }

    #[tokio::test]
    async fn a_provisioned_starter_with_deny_and_anonymous_ovh_is_refused() {
        let _guard = tui::app::tests::CONFIG_HOME_LOCK.lock().await;
        let prev_fb = std::env::var_os("SHAI_ANONYMOUS_FALLBACK");
        let prev_ovh = std::env::var_os("OVH_API_KEY");
        std::env::remove_var("SHAI_ANONYMOUS_FALLBACK");
        std::env::remove_var("OVH_API_KEY");

        let deny_anon: ShaiConfig = serde_json::from_str(
            r#"{"providers":[{"provider":"ovhcloud","env_vars":{"OVH_BASE_URL":"https://example.invalid/v1"},"model":"Qwen3-32B","tool_method":"FunctionCall"}],"selected_provider":0,"anonymous_fallback":"deny"}"#,
        )
        .unwrap();
        let err = apply_provisioned_snapshot_policy(deny_anon).unwrap_err();
        assert!(err.is_refused_start(), "{err}");
        assert!(
            err.to_string().contains("Anonymous fallback is disabled"),
            "{err}"
        );

        let deny_keyed: ShaiConfig = serde_json::from_str(
            r#"{"providers":[{"provider":"openai","env_vars":{"OPENAI_API_KEY":"k"},"model":"gpt-4o","tool_method":"FunctionCall"}],"selected_provider":0,"anonymous_fallback":"deny"}"#,
        )
        .unwrap();
        apply_provisioned_snapshot_policy(deny_keyed)
            .expect("deny must still allow a keyed provider");

        let prompt_anon: ShaiConfig = serde_json::from_str(
            r#"{"providers":[{"provider":"ovhcloud","env_vars":{"OVH_BASE_URL":"https://example.invalid/v1"},"model":"Qwen3-32B","tool_method":"FunctionCall"}],"selected_provider":0,"anonymous_fallback":"prompt"}"#,
        )
        .unwrap();
        apply_provisioned_snapshot_policy(prompt_anon)
            .expect("prompt mode starts must stay allowed");

        match prev_fb {
            Some(v) => std::env::set_var("SHAI_ANONYMOUS_FALLBACK", v),
            None => std::env::remove_var("SHAI_ANONYMOUS_FALLBACK"),
        }
        match prev_ovh {
            Some(v) => std::env::set_var("OVH_API_KEY", v),
            None => std::env::remove_var("OVH_API_KEY"),
        }
    }

    /// A provisioned starter that itself denies anonymous OVH must come back
    /// as a refused `SessionStartError`, so `prepare_session_or_exit` can
    /// call `exit_session_error` and `--prewalk-into` is not treated as a
    /// missing config.
    #[tokio::test]
    async fn prepare_session_refuses_immediately_when_a_provisioned_starter_denies() {
        let _guard = tui::app::tests::CONFIG_HOME_LOCK.lock().await;
        let prev_fb = std::env::var_os("SHAI_ANONYMOUS_FALLBACK");
        let prev_ovh = std::env::var_os("OVH_API_KEY");
        std::env::remove_var("SHAI_ANONYMOUS_FALLBACK");
        std::env::remove_var("OVH_API_KEY");

        let dir = tempfile::TempDir::new().unwrap();
        let _home = tui::app::tests::ConfigHomeGuard::set(dir.path());

        let body = r#"{"providers":[{"provider":"ovhcloud","env_vars":{"OVH_BASE_URL":"https://example.invalid/v1"},"model":"Qwen3-32B","tool_method":"FunctionCall"}],"selected_provider":0,"anonymous_fallback":"deny"}"#;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/starter.config");
        let served = body.to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("starter request");
            let mut buf = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{served}",
                served.len()
            );
            let _ = std::io::Write::write_all(&mut stream, resp.as_bytes());
        });

        let result = prepare_session(FallbackInteraction::NonInteractive, None, Some(url)).await;
        let _ = server.join();

        let err = match result {
            Err(err) => err,
            Ok(Ok(_)) => panic!("expected a refused start after provisioning a deny starter"),
            Ok(Err(err)) => panic!(
                "expected a refused SessionStartError so exit_session_error runs, got a wrapped primary config error: {err}"
            ),
        };
        assert!(err.is_refused(), "{err}");
        assert_eq!(err.exit_code(), 2, "{err}");
        assert!(
            err.to_string().contains("Anonymous fallback is disabled"),
            "{err}"
        );

        match prev_fb {
            Some(v) => std::env::set_var("SHAI_ANONYMOUS_FALLBACK", v),
            None => std::env::remove_var("SHAI_ANONYMOUS_FALLBACK"),
        }
        match prev_ovh {
            Some(v) => std::env::set_var("OVH_API_KEY", v),
            None => std::env::remove_var("OVH_API_KEY"),
        }
    }
}

#[cfg(test)]
mod yes_flag_tests {
    use super::*;

    #[test]
    fn headless_yes_defaults_off() {
        let cli = Cli::try_parse_from(["shai", "-p", "hi"]).unwrap();
        assert!(!cli.yes);
        let cli = Cli::try_parse_from(["shai", "-p", "hi", "--yes"]).unwrap();
        assert!(cli.yes);
    }

    #[test]
    fn serve_yes_defaults_off() {
        let cli = Cli::try_parse_from(["shai", "serve"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Serve { yes: false, .. })
        ));
        let cli = Cli::try_parse_from(["shai", "serve", "--yes"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Serve { yes: true, .. })
        ));
    }
}
