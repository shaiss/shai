#![allow(clippy::collapsible_if)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::collapsible_match)]
use std::io::{self, Write};

use crossterm::execute;
use crossterm::terminal::{self, disable_raw_mode};
use futures::StreamExt;
use ratatui::prelude::CrosstermBackend;
use ratatui::Terminal;
use ratatui::{TerminalOptions, Viewport};
use shai_core::agent::{AgentController, AgentEvent, PublicAgentState};
use shai_core::runners::coder::coder::coder;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};
use tracing::{debug, warn};

use super::agent_meta::AgentMeta;
use super::agent_state::AgentState;
use crate::session_options::SessionOptions;

use super::handler::AgentHandler;
use super::input::InputArea;
use super::renderer::RenderManager;
use super::session_picker::SessionPicker;
use super::shortcuts::Shortcuts;
use super::statusbar::StatusBar;
use super::theme::Theme;
use super::ui_state::UiState;

pub struct AppRunningAgent {
    pub(crate) handle: JoinHandle<()>,
    pub(crate) events: broadcast::Receiver<AgentEvent>,
    pub(crate) controller: AgentController,
    pub(crate) tools: Vec<(String, String)>,
    identity: std::sync::Arc<()>,
}

pub enum InitialModal {
    None,
    AgentPicker,
    SessionPicker,
}

pub struct App<'a> {
    pub(crate) terminal: Option<Terminal<CrosstermBackend<io::Stdout>>>,
    pub(crate) agent: Option<AppRunningAgent>,
    pub(crate) agent_state: AgentState,
    pub(crate) agent_meta: AgentMeta,
    pub(crate) ui_state: UiState<'a>,
    pub(crate) renderer: RenderManager,
    pub(crate) input: InputArea<'a>,
    pub(crate) shortcuts: Shortcuts,
    pub(crate) status_bar: StatusBar,
    pub(crate) initial_modal: InitialModal,
    pub(crate) initial_prompt: Option<String>,
    pub(crate) session_options: SessionOptions,
    /// Lines about the session's options that are waiting to be shown.
    pub(crate) session_notices: Vec<String>,
    /// Agents this session has started so far.
    pub(crate) agents_started: u32,
    pub(crate) event_reader: Option<crossterm::event::EventStream>,
    event_hold_depth: u32,
}

/// A replacement loaded once, so construction does not read the agent
/// or auth file again after the live agent has been torn down.
pub(crate) enum PreparedAgent {
    Named {
        name: String,
        config: shai_core::config::agent::AgentConfig,
    },
    Primary(shai_core::config::config::ShaiConfig),
}

struct BuiltAgent {
    agent: shai_core::agent::AgentCore,
    name: Option<String>,
    model: String,
    provider: String,
    mcp_status: Option<Vec<shai_core::tools::McpServerStatus>>,
    apply_env: Option<shai_core::config::config::ShaiConfig>,
}

pub(crate) struct EventPump {
    stop_tx: tokio::sync::oneshot::Sender<()>,
    handle: JoinHandle<(broadcast::Receiver<AgentEvent>, Vec<AgentEvent>)>,
    identity: std::sync::Arc<()>,
}

struct EventPumpTask {
    stop_tx: tokio::sync::oneshot::Sender<()>,
    handle: JoinHandle<(broadcast::Receiver<AgentEvent>, Vec<AgentEvent>)>,
    ready_rx: tokio::sync::oneshot::Receiver<()>,
}

fn start_event_pump(mut rx: broadcast::Receiver<AgentEvent>) -> EventPumpTask {
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let _ = ready_tx.send(());
        let mut held = Vec::new();
        loop {
            tokio::select! {
                ev = rx.recv() => match ev {
                    Ok(ev) => held.push(ev),
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = &mut stop_rx => break,
            }
        }
        loop {
            match rx.try_recv() {
                Ok(ev) => held.push(ev),
                Err(broadcast::error::TryRecvError::Lagged(_)) => {}
                Err(_) => break,
            }
        }
        (rx, held)
    });
    EventPumpTask {
        stop_tx,
        handle,
        ready_rx,
    }
}

impl App<'_> {
    pub async fn start_agent(
        &mut self,
        agent_name: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // As at start-up: a config file that is there and cannot be read
        // is not replaced by the built-in default, which would send the
        // conversation to a provider the user did not choose.
        // The file is loaded once, and the agent built from that load, so
        // it cannot break between a check and a later read.
        let prepared = Self::load_prepared(agent_name)?;
        self.start_prepared(prepared).await
    }

    pub(crate) fn load_prepared(
        agent_name: Option<&str>,
    ) -> Result<PreparedAgent, Box<dyn std::error::Error>> {
        match agent_name {
            Some(name) => {
                let config = shai_core::config::agent::AgentConfig::load(name)?;
                Ok(PreparedAgent::Named {
                    name: name.to_string(),
                    config,
                })
            }
            None => Ok(PreparedAgent::Primary(SessionOptions::primary_config()?)),
        }
    }

    /// Load the replacement, or tell the user why the live agent is kept.
    pub(crate) fn prepared_replacement(
        &mut self,
        agent_name: Option<&str>,
    ) -> Option<PreparedAgent> {
        match Self::load_prepared(agent_name) {
            Ok(prepared) => Some(prepared),
            Err(error) => {
                self.session_notices
                    .push(format!("the agent was not replaced: {error}"));
                None
            }
        }
    }

    pub(crate) async fn start_prepared(
        &mut self,
        prepared: PreparedAgent,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let built = self.build_agent(prepared).await?;
        Ok(self.install_built(built).await)
    }

    async fn build_agent(
        &mut self,
        prepared: PreparedAgent,
    ) -> Result<BuiltAgent, Box<dyn std::error::Error>> {
        use shai_core::agent::builder::AgentBuilder;

        match prepared {
            PreparedAgent::Named { name, config } => {
                let model = config.llm_provider.model.clone();
                let provider = config.llm_provider.provider.clone();
                let agent_builder = AgentBuilder::from_config(config).await?;
                let mcp_status = agent_builder.mcp_status.clone();
                Ok(BuiltAgent {
                    agent: agent_builder.build(),
                    name: Some(name),
                    model,
                    provider,
                    mcp_status: Some(mcp_status),
                    apply_env: None,
                })
            }
            PreparedAgent::Primary(config) => {
                // Do not call get_llm_from_config: that exports provider
                // variables into the process before we know this build will
                // be installed. Child tools of a still-running live agent
                // would then see the replacement's credentials.
                let (llm, model) = config.llm_from_config().await?;
                let provider = llm.provider().name().to_string();
                Ok(BuiltAgent {
                    agent: coder(Arc::new(llm), model.clone()),
                    name: None,
                    model,
                    provider,
                    mcp_status: None,
                    apply_env: Some(config),
                })
            }
        }
    }

    async fn install_built(&mut self, mut built: BuiltAgent) -> String {
        use shai_core::agent::Agent;

        if let Some(config) = built.apply_env.as_ref() {
            config.set_env_vars();
        }

        // The agent this one replaces may have handed off without its
        // announcement having been read. Say so before moving on.
        self.show_unseen_switch();
        // What the session was asked for follows the config, which is read
        // again for every agent: a handoff still to come is aimed at what its
        // target resolves to now, or given up if it no longer resolves.
        if self.agents_started > 0 {
            let notices = self.session_options.refresh();
            self.session_notices.extend(notices);
        }

        self.agent_meta.set_model(built.model.clone());
        self.agent_meta.set_provider(built.provider.clone());
        self.agent_meta.set_name(built.name.clone());
        if let Some(mcp_status) = built.mcp_status {
            self.agent_state.mcp_manager_mut().set_servers(mcp_status);
        }

        // A handoff that has not happened yet stays armed on an agent that
        // replaces the previous one, if that agent can hand off at all. Once
        // it has happened, no agent is armed again. The advisor follows the
        // session from one agent to the next, and so does its review counter.
        let notices = self.session_options.arm(&mut built.agent);
        self.session_notices.extend(notices);

        let banner = if let Some(ref name) = built.name {
            format!(
                "\x1b[2m░ agent {} - {} on {}\x1b[0m",
                name, built.model, built.provider
            )
        } else {
            format!("\x1b[2m░ {} on {}\x1b[0m", built.model, built.provider)
        };

        let controller = built.agent.controller();
        let events = built.agent.watch();
        let handle = tokio::spawn(async move {
            match built.agent.run().await {
                Ok(result) => debug!(target: "agent::loop", "Agent completed: {:?}", result),
                Err(error) => warn!(target: "agent::loop", "Agent failed: {}", error),
            }
        });

        self.agent = Some(AppRunningAgent {
            handle,
            controller: controller.clone(),
            events,
            tools: Vec::new(),
            identity: std::sync::Arc::new(()),
        });

        let saved_prompts = shai_core::tools::prompts::load_active_prompts_from_disk();
        if !saved_prompts.is_empty() {
            let _ = controller.set_active_prompts(saved_prompts).await;
        }

        self.status_bar.set_model(self.agent_meta.model());
        self.status_bar.set_provider(self.agent_meta.provider());
        self.refresh_status_bar();
        self.agents_started += 1;

        banner
    }

    /// Show the lines about the session's options that are waiting.
    pub(crate) fn show_session_notices(&mut self) {
        if self.session_notices.is_empty() {
            return;
        }
        let stick = self.renderer.history().at_bottom();
        for notice in std::mem::take(&mut self.session_notices) {
            self.renderer.history_mut().add_system_text(&notice);
        }
        if stick {
            self.renderer.history_mut().scroll_to_bottom();
        }
    }

    /// Show a notice event, and follow a model switch in the display.
    fn show_notice(&mut self, event: &AgentEvent) {
        if let AgentEvent::ModelSwitched { provider, model } = event {
            // Show where the conversation goes from now on.
            self.agent_meta.set_model(model.clone());
            self.agent_meta.set_provider(provider.clone());
            self.status_bar.set_model(model);
            self.status_bar.set_provider(provider);
        }
        if let Some(notice) = shai_core::agent::notice_text(event) {
            let stick = self.renderer.history().at_bottom();
            self.renderer.history_mut().add_system_text(&notice);
            if stick {
                self.renderer.history_mut().scroll_to_bottom();
            }
            self.notify(&notice, Duration::from_secs(8));
        }
    }

    /// Announce a handoff that happened without its event reaching this
    /// loop: events are dropped when the loop falls far behind, and with an
    /// agent that is replaced before they are read.
    pub(crate) fn show_unseen_switch(&mut self) {
        if let Some(event) = self.session_options.take_unseen_switch() {
            self.show_notice(&event);
        }
    }

    async fn receive_agent_event(&mut self) -> Option<AgentEvent> {
        if let Some(ref mut agent) = self.agent {
            agent.events.recv().await.ok()
        } else {
            None
        }
    }

    pub(crate) fn render_restored_trace(
        &mut self,
        trace: &[openai_dive::v1::resources::chat::ChatMessage],
    ) {
        use openai_dive::v1::resources::chat::{ChatMessage, ChatMessageContent};

        for message in trace {
            let formatted = match message {
                ChatMessage::User { content, .. } => match content {
                    ChatMessageContent::Text(text) => {
                        self.renderer
                            .formatter()
                            .format_event(&AgentEvent::UserInput {
                                input: text.clone(),
                            })
                    }
                    _ => None,
                },
                ChatMessage::Assistant { content, .. } => {
                    if let Some(ChatMessageContent::Text(text)) = content {
                        if text.trim().is_empty() {
                            None
                        } else {
                            Some(format!("\n\u{25cf} {}", text))
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(text) = formatted {
                self.renderer.history_mut().add_text(&text);
            }
        }
    }

    pub(crate) async fn restore_session(&mut self, session_id: &str) -> io::Result<()> {
        use openai_dive::v1::resources::chat::{ChatMessage, ChatMessageContent};

        let session =
            shai_core::session::SessionPersist::load_session(session_id).map_err(|e| {
                io::Error::other(format!("Failed to load session {}: {}", session_id, e))
            })?;

        self.agent_state
            .session_manager_mut()
            .set_session_id(&session.session_id);

        // Signals were reset in `try_run` before this agent was started.
        if let Some(ref agent) = self.agent {
            let _ = agent.controller.load_trace(session.trace.clone()).await;
        }

        let user_inputs: Vec<String> = session
            .trace
            .iter()
            .filter_map(|msg| match msg {
                ChatMessage::User {
                    content: ChatMessageContent::Text(text),
                    ..
                } => Some(text.clone()),
                _ => None,
            })
            .collect();
        self.input.set_history(user_inputs);

        self.render_restored_trace(&session.trace);
        self.renderer.history_mut().scroll_to_bottom();
        self.refresh_status_bar();
        Ok(())
    }

    /// Whether the running agent may be replaced by one on the agent
    /// `agent_name` (`None`: the primary model of the auth config). Not when
    /// the replacement could not be loaded: the current agent would be torn
    /// down and the session left without one. A named agent is loaded first
    /// so a broken auth config, or a file that is not a valid agent object,
    /// is reported and the live agent is kept. The user is told why.
    #[cfg(test)]
    pub(crate) fn may_replace_agent(&mut self, agent_name: Option<&str>) -> bool {
        self.prepared_replacement(agent_name).is_some()
    }

    /// [`App::may_replace_agent`] for an agent on the auth config, given what
    /// is wrong with that config file, if anything.
    #[cfg(test)]
    fn may_replace_agent_given(&mut self, config_problem: Option<String>) -> bool {
        match config_problem {
            Some(problem) => {
                self.session_notices
                    .push(format!("the agent was not replaced: {problem}"));
                false
            }
            None => true,
        }
    }

    pub async fn swap_agent(
        &mut self,
        agent_name: Option<&str>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        self.replace_running_agent(agent_name, true).await
    }

    /// Load the replacement once, then install it. The agent or auth file
    /// is not read again after this returns the snapshot.
    pub async fn replace_running_agent(
        &mut self,
        agent_name: Option<&str>,
        keep_current_trace: bool,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let Some(prepared) = self.prepared_replacement(agent_name) else {
            return Ok(false);
        };
        self.install_replacement(prepared, keep_current_trace).await
    }

    /// Build the replacement from a snapshot already loaded, then tear the
    /// live agent down only after that build succeeds. Construction does
    /// not read the agent or auth file again, so a change on disk between
    /// preflight and install cannot leave the session without an agent.
    /// If the build fails, the live agent and its trace are kept.
    ///
    /// Install after a successful build does not fail: it only updates the
    /// UI, arms prewalk, and spawns the already-built agent. There is
    /// therefore no post-teardown path that would need to reinstate the
    /// previous agent.
    pub(crate) async fn install_replacement(
        &mut self,
        prepared: PreparedAgent,
        keep_current_trace: bool,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        self.finish_replacement(prepared, keep_current_trace, false)
            .await
    }

    /// Install a replacement for a restored conversation.
    ///
    /// The prewalk trigger starts over only after the replacement has been
    /// built, and before it is armed, so the new agent holds empty signals.
    /// If the build fails, the live agent is kept and its signals and the
    /// spent one-shot latch are left as they are.
    pub(crate) async fn install_restored_agent(
        &mut self,
        prepared: PreparedAgent,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        self.finish_replacement(prepared, false, true).await
    }

    async fn finish_replacement(
        &mut self,
        prepared: PreparedAgent,
        keep_current_trace: bool,
        reset_prewalk: bool,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let hold = self.start_holding_events().await;
        let built = match self.build_agent(prepared).await {
            Ok(built) => {
                let held = self.stop_holding_events(hold).await;
                self.show_held_advisor_notices(&held);
                built
            }
            Err(error) => {
                let held = self.stop_holding_events(hold).await;
                self.replay_held_events(held).await?;
                self.session_notices
                    .push(format!("the agent was not replaced: {error}"));
                return Ok(false);
            }
        };

        // Reset only once the replacement is known to start, and before
        // install arms the new agent. A reset after arm would leave the
        // running agent holding the previous conversation's signals.
        if reset_prewalk {
            self.session_options.reset_prewalk_signals();
        }

        let trace = if keep_current_trace {
            if let Some(ref agent) = self.agent {
                agent.controller.get_trace().await.ok()
            } else {
                None
            }
        } else {
            None
        };

        if let Some(agent) = self.agent.take() {
            let _ = agent.controller.terminate().await;
            let _ = agent.handle.await;
        }

        self.install_built(built).await;

        if let Some(trace) = trace {
            if let Some(ref agent) = self.agent {
                let _ = agent.controller.load_trace(trace).await;
            }
        }

        Ok(true)
    }

    async fn handle_agent_event(&mut self, event: AgentEvent) -> io::Result<()> {
        self.agent_state.handle_event(&event).await;
        self.renderer.handle_event(&event).await;

        if let AgentEvent::StatusChanged { new_status, .. } = &event {
            self.input
                .set_agent_running(!matches!(new_status, PublicAgentState::Paused));
            self.status_bar
                .set_agent_mode(&self.input.agent_mode().status_bar_str());
            if matches!(new_status, PublicAgentState::Paused) {
                if let Some(ref agent_ref) = self.agent {
                    if let Ok(trace) = agent_ref.controller.get_trace().await {
                        let sid = self.agent_state.session_manager().session_id().to_string();
                        tokio::spawn(async move {
                            if let Err(e) =
                                shai_core::session::SessionPersist::save_session(&sid, trace)
                            {
                                tracing::warn!("Failed to save session {}: {}", sid, e);
                            }
                        });
                    }
                }
            }
        }

        // One-shot: the handoff is over for this session. If it has been
        // announced already (see `show_unseen_switch`), this is a repeat.
        let repeat = match &event {
            AgentEvent::ModelSwitched { provider, model } => {
                !self.session_options.on_model_switched(provider, model)
            }
            _ => false,
        };
        if !repeat {
            self.show_notice(&event);
        }

        if let AgentEvent::TokenUsage { .. } = &event {
            self.status_bar.set_tokens(
                self.agent_state.token_counter().input_tokens(),
                self.agent_state.token_counter().output_tokens(),
            );
        }

        self.refresh_status_bar();
        Ok(())
    }

    fn refresh_status_bar(&mut self) {
        if let Ok(cwd) = std::env::current_dir() {
            self.status_bar.set_location(cwd.to_string_lossy().as_ref());
        }
        if self.status_bar.git_needs_refresh() {
            if let Ok(output) = std::process::Command::new("git")
                .args(["rev-parse", "--abbrev-ref", "HEAD"])
                .output()
            {
                if output.status.success() {
                    let branch = String::from_utf8_lossy(&output.stdout);
                    self.status_bar.set_git_branch(branch.trim());
                }
            }
        }
        self.status_bar
            .set_tool_call_method(self.input.tool_call_method_str());
    }
}

// UI-related Internals
impl App<'_> {
    pub fn new() -> Self {
        let theme = Theme::from_config();
        let palette = theme.palette();
        let shortcuts = Shortcuts::load();
        let mut input = InputArea::new(palette);
        input.set_shortcuts(
            shortcuts.cancel_task().clone(),
            shortcuts.clear_input().clone(),
            shortcuts.paste().clone(),
        );

        Self {
            terminal: None,
            agent: None,
            agent_state: AgentState::new(),
            agent_meta: AgentMeta::new(),
            ui_state: UiState::new(),
            renderer: RenderManager::new(),
            input,
            shortcuts,
            status_bar: StatusBar::new(theme),
            initial_modal: InitialModal::None,
            initial_prompt: None,
            session_options: SessionOptions::default(),
            session_notices: Vec::new(),
            agents_started: 0,
            event_reader: None,
            event_hold_depth: 0,
        }
    }

    /// Drop the main event reader so a nested full-screen view (auth,
    /// permission modal, viewer, ...) can create its own.
    ///
    /// Crossterm has a single global event reader behind a mutex, and an idle
    /// [`crossterm::event::EventStream`] keeps that mutex held in its waker
    /// thread while blocked on input. A nested view constructing a second
    /// stream would then deadlock until the next key press, leaving a black
    /// screen. Dropping the stream shuts its waker thread down and releases
    /// the lock; the global reader itself (and any queued events) survives.
    pub(crate) fn suspend_event_reader(&mut self) {
        self.event_reader = None;
    }

    /// Re-create the main event reader after a nested view exited.
    pub(crate) fn resume_event_reader(&mut self) {
        self.event_reader = Some(crossterm::event::EventStream::new());
    }

    /// Drain `AgentEvent`s on a background task while the TUI loop is
    /// blocked (the auth view, or building a replacement). Broadcast lag
    /// would otherwise drop permission prompts and tool results; if the
    /// live agent is then kept, the session can hang on a prompt the UI
    /// never showed.
    ///
    /// Nested calls share the outer pump: `/auth` holds events for the
    /// whole view, and `finish_replacement` does not start a second one.
    pub(crate) async fn start_holding_events(&mut self) -> Option<EventPump> {
        let agent = self.agent.as_mut()?;
        if self.event_hold_depth > 0 {
            self.event_hold_depth += 1;
            return None;
        }
        self.event_hold_depth = 1;
        let placeholder = agent.events.resubscribe();
        let rx = std::mem::replace(&mut agent.events, placeholder);
        let identity = std::sync::Arc::clone(&agent.identity);
        let task = start_event_pump(rx);
        let _ = task.ready_rx.await;
        Some(EventPump {
            stop_tx: task.stop_tx,
            handle: task.handle,
            identity,
        })
    }

    pub(crate) async fn stop_holding_events(&mut self, pump: Option<EventPump>) -> Vec<AgentEvent> {
        if self.event_hold_depth == 0 {
            return Vec::new();
        }
        self.event_hold_depth -= 1;
        let Some(pump) = pump else {
            return Vec::new();
        };
        let _ = pump.stop_tx.send(());
        let (rx, held) = match pump.handle.await {
            Ok(result) => result,
            Err(_) => return Vec::new(),
        };
        if let Some(agent) = self.agent.as_mut() {
            if std::sync::Arc::ptr_eq(&agent.identity, &pump.identity) {
                agent.events = rx;
            }
        }
        held
    }

    pub(crate) async fn replay_held_events(&mut self, held: Vec<AgentEvent>) -> io::Result<()> {
        for event in held {
            self.handle_agent_event(event).await?;
        }
        Ok(())
    }

    /// Render advisor notices that arrived while an agent replacement was
    /// being built, without replaying the old agent's prompts or state
    /// updates onto its replacement.
    pub(crate) fn show_held_advisor_notices(&mut self, held: &[AgentEvent]) {
        for event in held {
            if matches!(
                event,
                AgentEvent::AdvisorNote { .. } | AgentEvent::AdvisorFailed { .. }
            ) {
                self.show_notice(event);
            }
        }
    }

    pub fn notify(&mut self, msg: &str, duration: std::time::Duration) {
        self.status_bar.set_notification(msg, duration);
    }

    pub async fn run(
        &mut self,
        agent_name: Option<String>,
        restore_session_id: Option<String>,
    ) -> io::Result<()> {
        let x = self.try_run(agent_name, restore_session_id).await;

        let _ = execute!(
            std::io::stdout(),
            crossterm::event::DisableMouseCapture,
            crossterm::event::PopKeyboardEnhancementFlags,
        );
        std::io::stdout().flush().ok();
        let _ = disable_raw_mode();

        if let Err(e) = x {
            println!();
            eprintln!("{}\r\n", e);
        }

        println!();
        println!();
        Ok(())
    }

    async fn try_run(
        &mut self,
        agent_name: Option<String>,
        restore_session_id: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let agent_name_ref = agent_name.as_deref();
        // A restored conversation starts the trigger over. Reset before the
        // agent is armed, so it holds the new empty signals; after start the
        // agent runs in another task and cannot be given a new Arc.
        if restore_session_id.is_some() {
            self.session_options.reset_prewalk_signals();
        }
        let banner =
            self.start_agent(agent_name_ref)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    if let Some(name) = agent_name_ref {
                        format!("could not start custom agent '{}': {}", name, e).into()
                    } else {
                        "could not start shai agent, run shai auth first"
                            .to_string()
                            .into()
                    }
                })?;

        self.terminal = Some(ratatui::init_with_options(TerminalOptions {
            viewport: Viewport::Fullscreen,
        }));

        execute!(std::io::stdout(), crossterm::event::EnableMouseCapture)?;

        if let Some(ref mut terminal) = self.terminal {
            terminal.clear()?;
        }

        self.renderer
            .history_mut()
            .add_text(&super::theme::welcome_text());
        if !banner.is_empty() {
            self.renderer.history_mut().add_text(&banner);
        }
        // Lines about the session's options are shown by the loop below,
        // under a restored conversation rather than above it.

        std::io::stdout().flush().ok();

        if let Some(session_id) = restore_session_id {
            self.restore_session(&session_id).await?;
        }

        // Show initial modal if requested
        match self.initial_modal {
            InitialModal::AgentPicker => {
                self.ui_state.agent_picker = Some(super::agent_picker::AgentPicker::new(
                    self.status_bar.palette(),
                ));
            }
            InitialModal::SessionPicker => {
                let sessions =
                    shai_core::session::SessionPersist::list_sessions().unwrap_or_default();
                self.ui_state.session_picker =
                    Some(SessionPicker::new(sessions, self.status_bar.palette()));
            }
            InitialModal::None => {}
        }

        // Send initial prompt if provided (interactive mode)
        if let Some(prompt) = self.initial_prompt.take() {
            if let Some(ref agent) = self.agent {
                let _ = agent.controller.send_user_input(prompt).await;
            }
        }

        let mut animation_timer = interval(Duration::from_millis(100));
        self.resume_event_reader();

        while !self.ui_state.exit {
            self.show_session_notices();
            self.draw_ui()
                .map_err(|_| -> Box<dyn std::error::Error> { "oops... (x_x)'".into() })?;

            let mut reader = self.event_reader.take().unwrap_or_default();

            tokio::select! {
                agent_event = self.receive_agent_event(), if self.agent.is_some() => {
                    self.event_reader = Some(reader);
                    match agent_event {
                        Some(event) => self.handle_agent_event(event).await?,
                        // Events were missed. A handoff may be among them.
                        None => self.show_unseen_switch(),
                    }
                    reader = self.event_reader.take().unwrap_or_default();
                }

                crossterm_event = reader.next() => {
                    self.event_reader = Some(reader);
                    if let Some(Ok(event)) = crossterm_event {
                        self.handle_crossterm_event(event).await?;
                    }
                    reader = self.event_reader.take().unwrap_or_default();
                }

                _ = animation_timer.tick() => {
                    self.event_reader = Some(reader);
                    if let Some(action) = self.input.check_pending_enter() {
                        self.handle_user_action(action).await?;
                    }
                    reader = self.event_reader.take().unwrap_or_default();
                }
            }

            self.event_reader = Some(reader);
            self.check_permission_queue().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_options::test_support::hand_off;
    use shai_core::agent::Prewalk;
    use shai_core::config::roles::BoundModel;
    use shai_llm::LlmClient;

    /// A handoff to a target that is never contacted: building a client
    /// opens no socket.
    fn prewalk() -> Prewalk {
        Prewalk::new(BoundModel::new(
            Arc::new(LlmClient::ollama("http://127.0.0.1:9/v1".to_string())),
            "qwen3:8b",
        ))
    }

    fn switched() -> AgentEvent {
        AgentEvent::ModelSwitched {
            provider: "ollama".to_string(),
            model: "qwen3:8b".to_string(),
        }
    }

    fn app_with(prewalk: Prewalk) -> App<'static> {
        let mut app = App::new();
        app.agent_meta.set_model("big-model".to_string());
        app.agent_meta.set_provider("openai".to_string());
        app.session_options = SessionOptions::with_prewalk(prewalk);
        app
    }

    fn switch_lines(app: &App<'_>) -> usize {
        app.renderer
            .history()
            .raw_text()
            .matches("prewalk: switched to ollama/qwen3:8b")
            .count()
    }

    #[tokio::test]
    async fn a_model_switch_is_shown_and_ends_the_handoff() {
        let _guard = CONFIG_HOME_LOCK.lock().await;
        let mut app = app_with(prewalk());
        assert!(app.session_options.prewalk_pending());

        app.handle_agent_event(switched()).await.unwrap();

        // The display follows the conversation to its new destination...
        assert_eq!(app.agent_meta.model(), "qwen3:8b");
        assert_eq!(app.agent_meta.provider(), "ollama");
        // ...the scrollback says so, once...
        assert_eq!(switch_lines(&app), 1);
        // ...and an agent started later in this session is not armed again.
        assert!(!app.session_options.prewalk_pending());

        // The same announcement arriving again is not shown twice.
        app.handle_agent_event(switched()).await.unwrap();
        assert_eq!(switch_lines(&app), 1);
    }

    #[tokio::test]
    async fn advisor_notes_and_failures_are_shown_in_the_conversation() {
        let mut app = App::new();
        app.handle_agent_event(AgentEvent::AdvisorNote {
            severity: shai_core::advisor::Severity::Concern,
            note: "the tests were not run".to_string(),
        })
        .await
        .unwrap();
        app.handle_agent_event(AgentEvent::AdvisorFailed {
            error: "model not found".to_string(),
            disabled: true,
        })
        .await
        .unwrap();

        let scrollback = app.renderer.history().raw_text();
        assert!(
            scrollback.contains("advisor (concern): the tests were not run"),
            "{scrollback}"
        );
        assert!(
            scrollback.contains("advisor: review failed (model not found)"),
            "{scrollback}"
        );
        assert!(scrollback.contains("off for the rest of this session"));
        // Each is shown once.
        assert_eq!(scrollback.matches("the tests were not run").count(), 1);
    }

    #[tokio::test]
    async fn other_events_leave_the_handoff_armed() {
        let _guard = CONFIG_HOME_LOCK.lock().await;
        let mut app = app_with(prewalk());

        app.handle_agent_event(AgentEvent::TokenUsage {
            input_tokens: 10,
            output_tokens: 5,
            cached_tokens: 0,
        })
        .await
        .unwrap();
        app.show_unseen_switch();

        assert_eq!(app.agent_meta.model(), "big-model");
        assert!(app.session_options.prewalk_pending());
        assert!(!app.renderer.history().raw_text().contains("prewalk"));
    }

    #[tokio::test]
    async fn a_switch_whose_event_was_lost_is_still_shown_once() {
        let _guard = CONFIG_HOME_LOCK.lock().await;
        // An agent hands off, and its announcement never reaches the loop:
        // the loop fell behind, or the agent was replaced first.
        let handoff = prewalk();
        let mut app = app_with(handoff.clone());
        app.show_unseen_switch();
        assert_eq!(switch_lines(&app), 0);
        hand_off(&handoff, true).await;
        assert!(handoff.has_switched());

        app.show_unseen_switch();
        assert_eq!(switch_lines(&app), 1);
        assert_eq!(app.agent_meta.model(), "qwen3:8b");
        assert_eq!(app.agent_meta.provider(), "ollama");
        assert!(!app.session_options.prewalk_pending());

        // Asked again, or told by the event after all: nothing more to show.
        app.show_unseen_switch();
        app.handle_agent_event(switched()).await.unwrap();
        assert_eq!(switch_lines(&app), 1);
    }

    #[test]
    fn an_agent_is_not_replaced_by_one_that_could_not_start() {
        let _guard = CONFIG_HOME_LOCK.blocking_lock();
        let mut app = App::new();
        assert!(app.may_replace_agent_given(None));
        assert!(app.session_notices.is_empty());
        assert!(!app.may_replace_agent_given(Some(
            "the config file /x/auth.config.json could not be loaded (line 3)".to_string()
        )));
        assert_eq!(
            app.session_notices,
            ["the agent was not replaced: the config file /x/auth.config.json could not be loaded (line 3)"]
        );
    }

    #[test]
    fn waiting_session_notices_are_shown_and_cleared() {
        let _guard = CONFIG_HOME_LOCK.blocking_lock();
        let mut app = App::new();
        app.show_session_notices();
        assert!(app.renderer.history().raw_text().is_empty());

        app.session_notices
            .push("prewalk not armed: this agent cannot change model".to_string());
        app.show_session_notices();
        app.show_session_notices();
        let scrollback = app.renderer.history().raw_text();
        assert_eq!(scrollback.matches("prewalk not armed").count(), 1);
        assert!(app.session_notices.is_empty());
    }

    /// Serializes tests that point `XDG_CONFIG_HOME` at a fixture tree.
    /// Async so the failed-reload test can keep exclusive access across
    /// `swap_agent(...).await` without holding a `std` mutex over an await.
    static CONFIG_HOME_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn set_config_home(home: &std::path::Path) -> Option<String> {
        let previous = std::env::var("XDG_CONFIG_HOME").ok();
        std::env::set_var("XDG_CONFIG_HOME", home);
        previous
    }

    fn restore_config_home(previous: Option<String>) {
        match previous {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }

    /// Restores `XDG_CONFIG_HOME` on drop, including when a test panics.
    /// Keep this guard inside the lock scope so restoration finishes
    /// before another test can acquire the lock.
    struct ConfigHomeGuard {
        previous: Option<String>,
    }

    impl ConfigHomeGuard {
        fn set(home: &std::path::Path) -> Self {
            Self {
                previous: set_config_home(home),
            }
        }
    }

    impl Drop for ConfigHomeGuard {
        fn drop(&mut self) {
            restore_config_home(self.previous.take());
        }
    }

    fn with_config_home<T>(home: &std::path::Path, f: impl FnOnce() -> T) -> T {
        let _lock = CONFIG_HOME_LOCK.blocking_lock();
        let _home = ConfigHomeGuard::set(home);
        f()
    }

    fn broken_auth_home(agent_json: &str) -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        let shai = dir.path().join("shai");
        std::fs::create_dir_all(shai.join("agents")).unwrap();
        std::fs::write(shai.join("auth.config.json"), "{ this is not json").unwrap();
        std::fs::write(shai.join("agents").join("reviewer.config.json"), agent_json).unwrap();
        dir
    }

    fn attach_live_agent(app: &mut App<'_>) {
        use openai_dive::v1::resources::chat::ChatMessage;
        use shai_core::agent::{
            Agent, AgentBuilder, AgentError, Brain, ThinkerContext, ThinkerDecision, ToolBudgetRef,
        };

        struct PauseBrain;

        #[async_trait::async_trait]
        impl Brain for PauseBrain {
            async fn next_step(
                &mut self,
                _: ThinkerContext,
                _: ToolBudgetRef,
            ) -> Result<ThinkerDecision, AgentError> {
                Ok(ThinkerDecision::agent_pause(ChatMessage::Assistant {
                    content: None,
                    reasoning: None,
                    reasoning_content: None,
                    tool_calls: None,
                    name: None,
                    audio: None,
                    refusal: None,
                }))
            }
        }

        let mut agent = AgentBuilder::with_brain(Box::new(PauseBrain)).build();
        let controller = agent.controller();
        let events = agent.watch();
        let handle = tokio::spawn(async move {
            let _ = agent.run().await;
        });
        app.agent = Some(AppRunningAgent {
            handle,
            controller,
            events,
            tools: Vec::new(),
            identity: std::sync::Arc::new(()),
        });
        app.agent_state
            .session_manager_mut()
            .set_session_id("live-session-1");
        app.agent_meta.set_name(Some("reviewer".to_string()));
    }

    #[tokio::test]
    async fn a_failed_reload_keeps_the_live_agent_and_session() {
        let home =
            broken_auth_home(r#"{"name": "reviewer", "description": "needs the auth config"}"#);
        let _guard = CONFIG_HOME_LOCK.lock().await;
        let _home = ConfigHomeGuard::set(home.path());
        let mut app = App::new();
        attach_live_agent(&mut app);
        let replaced = app.swap_agent(Some("reviewer")).await.unwrap();

        assert!(!replaced);
        assert!(
            app.agent.is_some(),
            "the live agent must survive a failed reload"
        );
        assert_eq!(
            app.agent_state.session_manager().session_id(),
            "live-session-1"
        );
        assert!(
            app.session_notices
                .iter()
                .any(|n| n.contains("the agent was not replaced")
                    && n.contains("auth.config.json")),
            "notices={:?}",
            app.session_notices
        );
        if let Some(agent) = app.agent.take() {
            let _ = agent.controller.terminate().await;
            let _ = agent.handle.await;
        }
    }

    #[test]
    fn a_named_agent_with_its_own_provider_can_replace_when_auth_is_broken() {
        let home = broken_auth_home(
            r#"{
                "name": "reviewer",
                "description": "has its own provider",
                "llm_provider": {
                    "provider": "openai",
                    "env_vars": {"OPENAI_API_KEY": "k"},
                    "model": "gpt-4o",
                    "tool_method": "FunctionCall"
                }
            }"#,
        );
        with_config_home(home.path(), || {
            let mut app = App::new();
            assert!(app.may_replace_agent(Some("reviewer")));
            assert!(app.session_notices.is_empty());
        });
    }

    #[tokio::test]
    async fn a_prepared_replacement_does_not_reread_the_agent_file() {
        let home = broken_auth_home(
            r#"{
                "name": "reviewer",
                "description": "has its own provider",
                "llm_provider": {
                    "provider": "openai",
                    "env_vars": {"OPENAI_API_KEY": "k"},
                    "model": "gpt-4o",
                    "tool_method": "FunctionCall"
                }
            }"#,
        );
        let agent_file = home
            .path()
            .join("shai")
            .join("agents")
            .join("reviewer.config.json");

        let _guard = CONFIG_HOME_LOCK.lock().await;
        let _home = ConfigHomeGuard::set(home.path());
        let mut app = App::new();
        attach_live_agent(&mut app);

        let prepared = app
            .prepared_replacement(Some("reviewer"))
            .expect("the reviewer snapshot should load");

        // A later start_agent / AgentConfig::load would fail: the file is gone.
        std::fs::remove_file(&agent_file).unwrap();
        assert!(!agent_file.exists());

        let replaced = app
            .install_replacement(prepared, true)
            .await
            .expect("install from the snapshot should not error");

        assert!(
            replaced,
            "the snapshot must be enough to start the replacement; notices={:?}",
            app.session_notices
        );
        assert!(app.agent.is_some(), "the session must still have an agent");
        assert_eq!(app.agent_meta.name(), Some("reviewer"));
        assert_eq!(app.agent_meta.model(), "gpt-4o");
        assert_eq!(
            app.agent_state.session_manager().session_id(),
            "live-session-1"
        );

        if let Some(agent) = app.agent.take() {
            let _ = agent.controller.terminate().await;
            let _ = agent.handle.await;
        }
    }

    fn due_prewalk() -> Prewalk {
        let prewalk = prewalk();
        prewalk.record_success("write", None);
        prewalk.record_success("todo_write", Some(1));
        assert!(prewalk.trigger_is_due());
        assert!(!prewalk.is_spent());
        prewalk
    }

    fn primary_without_a_provider() -> PreparedAgent {
        PreparedAgent::Primary(
            serde_json::from_str(r#"{"providers":[],"selected_provider":0}"#)
                .expect("empty-provider config should deserialize"),
        )
    }

    #[tokio::test]
    async fn a_failed_restored_replacement_does_not_reset_prewalk_signals() {
        let _guard = CONFIG_HOME_LOCK.lock().await;
        let mut app = App::new();
        let prewalk = due_prewalk();
        app.session_options = SessionOptions::with_prewalk(prewalk.clone());
        attach_live_agent(&mut app);

        let replaced = app
            .install_restored_agent(primary_without_a_provider())
            .await
            .unwrap();

        assert!(!replaced);
        assert!(
            app.agent.is_some(),
            "the live agent must survive a failed restore replacement"
        );
        let kept = app.session_options.prewalk().expect("prewalk still set");
        assert!(
            kept.trigger_is_due(),
            "a failed replacement must not start the trigger over"
        );
        assert!(!kept.is_spent(), "the latch must stay unspent");

        if let Some(agent) = app.agent.take() {
            let _ = agent.controller.terminate().await;
            let _ = agent.handle.await;
        }
    }

    #[tokio::test]
    async fn a_successful_restored_replacement_starts_the_trigger_over() {
        let home = broken_auth_home(
            r#"{
                "name": "reviewer",
                "description": "has its own provider",
                "llm_provider": {
                    "provider": "openai",
                    "env_vars": {"OPENAI_API_KEY": "k"},
                    "model": "gpt-4o",
                    "tool_method": "FunctionCall"
                }
            }"#,
        );
        let _guard = CONFIG_HOME_LOCK.lock().await;
        let _home = ConfigHomeGuard::set(home.path());
        let mut app = App::new();
        let prewalk = due_prewalk();
        app.session_options = SessionOptions::with_prewalk(prewalk.clone());
        attach_live_agent(&mut app);

        let prepared = app
            .prepared_replacement(Some("reviewer"))
            .expect("the reviewer snapshot should load");
        let replaced = app
            .install_restored_agent(prepared)
            .await
            .expect("install from the snapshot should not error");

        assert!(replaced);
        let restored = app.session_options.prewalk().expect("prewalk still set");
        assert!(
            !restored.trigger_is_due(),
            "the restored agent must start the trigger over"
        );
        assert!(!restored.is_spent(), "the one-shot latch must stay unspent");
        // The previous conversation's copy still has the old signals.
        assert!(prewalk.trigger_is_due());

        if let Some(agent) = app.agent.take() {
            let _ = agent.controller.terminate().await;
            let _ = agent.handle.await;
        }
    }

    #[tokio::test]
    async fn a_successful_restored_replacement_keeps_a_spent_latch() {
        let home = broken_auth_home(
            r#"{
                "name": "reviewer",
                "description": "has its own provider",
                "llm_provider": {
                    "provider": "openai",
                    "env_vars": {"OPENAI_API_KEY": "k"},
                    "model": "gpt-4o",
                    "tool_method": "FunctionCall"
                }
            }"#,
        );
        let _guard = CONFIG_HOME_LOCK.lock().await;
        let _home = ConfigHomeGuard::set(home.path());
        let mut app = App::new();
        let prewalk = prewalk();
        hand_off(&prewalk, true).await;
        assert!(prewalk.is_spent());
        app.session_options = SessionOptions::with_prewalk(prewalk.clone());
        attach_live_agent(&mut app);

        let prepared = app
            .prepared_replacement(Some("reviewer"))
            .expect("the reviewer snapshot should load");
        let replaced = app
            .install_restored_agent(prepared)
            .await
            .expect("install from the snapshot should not error");

        assert!(replaced);
        assert!(
            prewalk.is_spent(),
            "resetting signals must not revive a spent latch"
        );
        assert!(
            !app.session_options.prewalk_pending(),
            "a spent handoff is not armed again on the restored agent"
        );

        if let Some(agent) = app.agent.take() {
            let _ = agent.controller.terminate().await;
            let _ = agent.handle.await;
        }
    }

    fn auth_home(auth_json: &str) -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        let shai = dir.path().join("shai");
        std::fs::create_dir_all(&shai).unwrap();
        std::fs::write(shai.join("auth.config.json"), auth_json).unwrap();
        dir
    }

    #[tokio::test]
    async fn a_failed_primary_build_does_not_change_process_env() {
        const KEY: &str = "SHAI_TEST_TUI_REPLACEMENT_ENV";
        let home = auth_home(
            r#"{
                "providers":[{
                    "provider":"not-a-real-provider",
                    "env_vars":{"SHAI_TEST_TUI_REPLACEMENT_ENV":"must-not-leak"},
                    "model":"x",
                    "tool_method":"FunctionCall"
                }],
                "selected_provider":0
            }"#,
        );
        let previous = std::env::var(KEY).ok();
        std::env::remove_var(KEY);

        let _guard = CONFIG_HOME_LOCK.lock().await;
        let _home = ConfigHomeGuard::set(home.path());
        let mut app = App::new();
        attach_live_agent(&mut app);
        let replaced = app
            .swap_agent(None)
            .await
            .expect("a failed build is reported, not a hard error");
        let leaked = std::env::var(KEY).ok();

        match previous {
            Some(value) => std::env::set_var(KEY, value),
            None => std::env::remove_var(KEY),
        }

        assert!(!replaced);
        assert!(
            app.agent.is_some(),
            "the live agent must survive a failed primary build"
        );
        assert!(
            leaked.is_none(),
            "the failed replacement must not export its provider variables"
        );
        assert!(
            app.session_notices
                .iter()
                .any(|n| n.contains("the agent was not replaced")
                    && n.contains("not-a-real-provider")),
            "notices={:?}",
            app.session_notices
        );

        if let Some(agent) = app.agent.take() {
            let _ = agent.controller.terminate().await;
            let _ = agent.handle.await;
        }
    }

    #[tokio::test]
    async fn an_event_pump_keeps_up_with_a_full_broadcast() {
        let (tx, rx) = broadcast::channel(16);
        let task = start_event_pump(rx);
        task.ready_rx.await.expect("event pump should start");
        for i in 0..128 {
            let _ = tx.send(AgentEvent::ThinkingStart);
            if i % 8 == 7 {
                tokio::task::yield_now().await;
            }
        }
        drop(tx);
        let _ = task.stop_tx.send(());
        let (_rx, held) = task.handle.await.expect("event pump should finish");
        assert_eq!(
            held.len(),
            128,
            "a pump that keeps receiving must not lose events to broadcast lag"
        );
    }

    #[tokio::test]
    async fn held_events_are_replayed_when_a_replacement_fails() {
        let _guard = CONFIG_HOME_LOCK.lock().await;
        let mut app = App::new();
        let (txcmd, _rxcmd) =
            tokio::sync::mpsc::unbounded_channel::<shai_core::agent::protocol::SentCommand>();
        let (tx, rx) = broadcast::channel(16);
        app.agent = Some(AppRunningAgent {
            handle: tokio::spawn(async {}),
            controller: shai_core::agent::AgentController { txcmd },
            events: rx,
            tools: Vec::new(),
            identity: std::sync::Arc::new(()),
        });

        let _ = tx.send(AgentEvent::TokenUsage {
            input_tokens: 7,
            output_tokens: 3,
            cached_tokens: 0,
        });
        assert_eq!(app.agent_state.token_counter().input_tokens(), 0);
        assert_eq!(app.agent_state.token_counter().output_tokens(), 0);

        let replaced = app
            .install_restored_agent(primary_without_a_provider())
            .await
            .expect("a failed build is reported, not a hard error");

        assert!(!replaced);
        assert!(app.agent.is_some(), "the live agent must be kept");
        assert_eq!(
            app.agent_state.token_counter().input_tokens(),
            7,
            "held events must be replayed onto the kept agent"
        );
        assert_eq!(app.agent_state.token_counter().output_tokens(), 3);
    }

    #[tokio::test]
    async fn advisor_notices_buffered_during_a_successful_replacement_are_shown() {
        let home = broken_auth_home(
            r#"{
                "name": "reviewer",
                "description": "has its own provider",
                "llm_provider": {
                    "provider": "openai",
                    "env_vars": {"OPENAI_API_KEY": "k"},
                    "model": "gpt-4o",
                    "tool_method": "FunctionCall"
                }
            }"#,
        );
        let _guard = CONFIG_HOME_LOCK.lock().await;
        let _home = ConfigHomeGuard::set(home.path());
        let mut app = App::new();
        let (txcmd, _rxcmd) =
            tokio::sync::mpsc::unbounded_channel::<shai_core::agent::protocol::SentCommand>();
        let (tx, rx) = broadcast::channel(16);
        app.agent = Some(AppRunningAgent {
            handle: tokio::spawn(async {}),
            controller: shai_core::agent::AgentController { txcmd },
            events: rx,
            tools: Vec::new(),
            identity: std::sync::Arc::new(()),
        });

        let prepared = app
            .prepared_replacement(Some("reviewer"))
            .expect("the reviewer snapshot should load");

        let _ = tx.send(AgentEvent::AdvisorNote {
            severity: shai_core::advisor::Severity::Concern,
            note: "buffered advisor note before swap".to_string(),
        });
        let _ = tx.send(AgentEvent::AdvisorFailed {
            error: "buffered failure".to_string(),
            disabled: false,
        });
        let _ = tx.send(AgentEvent::TokenUsage {
            input_tokens: 11,
            output_tokens: 5,
            cached_tokens: 0,
        });

        let replaced = app
            .install_restored_agent(prepared)
            .await
            .expect("install from the snapshot should not error");

        assert!(replaced);
        let scrollback = app.renderer.history().raw_text();
        assert!(
            scrollback.contains("advisor (concern): buffered advisor note before swap"),
            "{scrollback}"
        );
        assert!(
            scrollback.contains("advisor: review failed (buffered failure)"),
            "{scrollback}"
        );
        assert_eq!(
            app.agent_state.token_counter().input_tokens(),
            0,
            "old agent state updates must not replay onto the replacement"
        );

        if let Some(agent) = app.agent.take() {
            let _ = agent.controller.terminate().await;
            let _ = agent.handle.await;
        }
    }
}
