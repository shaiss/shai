// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

//! Options of an agent session that are settled when it starts.
//!
//! They come from the command line and from the auth config, and are resolved
//! before any model is contacted. An option that was asked for and cannot be
//! resolved stops the session from starting: it must not start as if the
//! option had not been given. So does a config file that exists and cannot be
//! read, since it may ask for any of them.
//!
//! Resolving an option is not yet honouring it. Whether it applies to the
//! agent a session runs is decided when that agent is armed, and the user is
//! told when it does not.

use shai_core::advisor::Advisor;
use shai_core::agent::output::{
    advisor_not_attached_notice, advisor_off_notice, advisor_on_notice, prewalk_armed_notice,
    prewalk_disarmed_notice, prewalk_not_armed_notice, prewalk_over_notice,
};
use shai_core::agent::{AgentCore, AgentEvent, Prewalk, PrewalkArmError};
use shai_core::config::advisor::resolve_advisor;
use shai_core::config::config::ShaiConfig;
use shai_core::config::prewalk::resolve_prewalk;
use shai_core::config::roles::{BoundModel, PrimaryConfigError, RoleError};

/// Why an agent gets no advisor when the session's one failed too often
/// under an earlier agent.
const SWITCHED_OFF_EARLIER: &str = "it was switched off earlier, after its reviews kept failing";

/// Why a headless agent run without `--yes` is not armed.
const HEADLESS_WITHOUT_YES: &str = "headless mode without --yes denies write and edit, \
     so the edit that starts the handoff can never happen; pass --yes to arm it";

/// Why a session could not start. The kind decides the process exit code:
/// a refused start (missing or unusable auth config) is 2; any other
/// failure is 1. The kind is structural, not derived from the message.
#[derive(Debug)]
pub struct SessionStartError {
    kind: SessionStartKind,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionStartKind {
    Refused,
    Other,
}

impl SessionStartError {
    pub fn other(message: impl Into<String>) -> Self {
        Self {
            kind: SessionStartKind::Other,
            message: message.into(),
        }
    }

    pub fn refused(message: impl Into<String>) -> Self {
        Self {
            kind: SessionStartKind::Refused,
            message: message.into(),
        }
    }

    /// Classify a start-agent failure, preserving a refused-start kind even
    /// when the display message is rewritten for the user.
    pub fn from_start(agent_name: Option<&str>, err: Box<dyn std::error::Error>) -> Self {
        let kind = start_kind(err.as_ref());
        let message = match agent_name {
            Some(name) => format!("could not start custom agent '{name}': {err}"),
            None => err.to_string(),
        };
        Self { kind, message }
    }

    pub fn exit_code(&self) -> i32 {
        match self.kind {
            SessionStartKind::Refused => 2,
            SessionStartKind::Other => 1,
        }
    }

    pub fn is_refused(&self) -> bool {
        matches!(self.kind, SessionStartKind::Refused)
    }
}

fn start_kind(err: &(dyn std::error::Error + 'static)) -> SessionStartKind {
    if err
        .downcast_ref::<PrimaryConfigError>()
        .is_some_and(|error| error.is_refused_start())
    {
        return SessionStartKind::Refused;
    }
    if let Some(error) = err.downcast_ref::<SessionStartError>() {
        return error.kind;
    }
    let mut source = err.source();
    while let Some(inner) = source {
        if inner
            .downcast_ref::<PrimaryConfigError>()
            .is_some_and(|error| error.is_refused_start())
        {
            return SessionStartKind::Refused;
        }
        if inner
            .downcast_ref::<SessionStartError>()
            .is_some_and(|error| error.is_refused())
        {
            return SessionStartKind::Refused;
        }
        source = inner.source();
    }
    SessionStartKind::Other
}

impl std::fmt::Display for SessionStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SessionStartError {}

impl From<PrimaryConfigError> for SessionStartError {
    fn from(err: PrimaryConfigError) -> Self {
        let kind = if err.is_refused_start() {
            SessionStartKind::Refused
        } else {
            SessionStartKind::Other
        };
        Self {
            kind,
            message: err.to_string(),
        }
    }
}

impl From<std::io::Error> for SessionStartError {
    fn from(err: std::io::Error) -> Self {
        Self::other(err.to_string())
    }
}

/// What a session was asked to do beyond running on the primary model.
#[derive(Clone, Default)]
pub struct SessionOptions {
    /// Value of `--prewalk-into`, kept to resolve the target again when the
    /// config changes during the session.
    prewalk_into: Option<String>,
    /// The handoff this session was asked for, until it is over.
    prewalk: Option<Prewalk>,
    /// The target the user was last told is armed.
    announced: Option<String>,
    /// Where the session went, once the handoff has happened.
    handed_off: Option<String>,
    /// Primary auth config resolved once during `prepare_session` so start-up
    /// builds the primary model without re-reading disk after the gate.
    startup_primary: Option<Result<ShaiConfig, PrimaryConfigError>>,
    /// Whether `--advisor` was given, kept for the same reason as the flag
    /// above.
    advisor_flag: bool,
    /// Second model that reviews the session's steps, if any. It follows the
    /// session from one agent to the next, and so does its review counter.
    advisor: Option<Advisor>,
    /// The advisor model the user was last told is on.
    advisor_announced: Option<String>,
}

impl SessionOptions {
    fn resolve_from(
        prewalk_into: Option<&str>,
        advisor: bool,
        config: Result<&ShaiConfig, &RoleError>,
    ) -> Result<Self, String> {
        if let Some(problem) = Self::unreadable(config) {
            return Err(format!(
                "{problem}. A session does not start on a config file it cannot read, \
                 since the file may ask for options the session would run without: \
                 fix the file, or move it away"
            ));
        }
        let prewalk = Self::resolve_prewalk(prewalk_into, config)?;
        let advisor_handle = Self::resolve_advisor(advisor, config, None)?;
        Ok(Self {
            prewalk_into: prewalk_into.map(str::to_string),
            prewalk: prewalk.map(Prewalk::new),
            announced: None,
            handed_off: None,
            startup_primary: None,
            advisor_flag: advisor,
            advisor: advisor_handle,
            advisor_announced: None,
        })
    }

    /// Resolve session options from an already-loaded (or provisioned)
    /// startup config snapshot, without re-reading `auth.config.json`.
    pub fn resolve_from_loaded(
        prewalk_into: Option<&str>,
        advisor: bool,
        loaded: Result<&ShaiConfig, &RoleError>,
        startup_primary: Result<ShaiConfig, PrimaryConfigError>,
    ) -> Result<Self, String> {
        let mut options = Self::resolve_from(prewalk_into, advisor, loaded)?;
        options.startup_primary = Some(startup_primary);
        Ok(options)
    }

    /// Like [`SessionOptions::resolve_from_loaded`], exiting with status 2 on
    /// an invalid option or unreadable config.
    pub fn resolve_from_loaded_or_exit(
        prewalk_into: Option<&str>,
        advisor: bool,
        loaded: Result<&ShaiConfig, &RoleError>,
        startup_primary: Result<ShaiConfig, PrimaryConfigError>,
    ) -> Self {
        match Self::resolve_from_loaded(prewalk_into, advisor, loaded, startup_primary) {
            Ok(options) => options,
            Err(error) => {
                eprintln!("error: {}", error);
                std::process::exit(2);
            }
        }
    }

    /// The startup primary config snapshot from `prepare_session`, or a fresh
    /// [`SessionOptions::primary_config`] load when none was recorded.
    pub fn startup_primary_config(&self) -> Result<ShaiConfig, PrimaryConfigError> {
        match &self.startup_primary {
            Some(result) => result.clone(),
            None => Self::primary_config(),
        }
    }

    /// Borrowed view of the startup primary config snapshot, if recorded.
    pub fn startup_primary_ref(&self) -> Option<Result<&ShaiConfig, &PrimaryConfigError>> {
        self.startup_primary.as_ref().map(Result::as_ref)
    }

    /// A missing config file asks for nothing. One that is there and cannot
    /// be read may ask for anything: running without what it asks for would
    /// be a guess. Returns what to say about such a file.
    fn unreadable(config: Result<&ShaiConfig, &RoleError>) -> Option<String> {
        match config {
            Err(RoleError::ConfigInvalid { path, reason }) => Some(format!(
                "the config file {path} could not be loaded ({reason})"
            )),
            _ => None,
        }
    }

    /// The config an agent without its own provider runs on, loaded once.
    ///
    /// The built-in default stands in only when there is no config file. A
    /// file that is there and cannot be read is an error, as at start-up:
    /// the primary model is built from this same load, so the file cannot
    /// break between a check and the read that builds the client.
    pub fn primary_config() -> Result<ShaiConfig, PrimaryConfigError> {
        ShaiConfig::primary()
    }

    #[cfg(test)]
    fn primary_config_from_with_env(
        config: Result<ShaiConfig, RoleError>,
        env_setting: Option<&str>,
    ) -> Result<ShaiConfig, PrimaryConfigError> {
        ShaiConfig::primary_from_with_env(config, env_setting)
    }

    /// The handoff target the session is asked for, as things are now.
    fn resolve_prewalk(
        prewalk_into: Option<&str>,
        config: Result<&ShaiConfig, &RoleError>,
    ) -> Result<Option<BoundModel>, String> {
        if let Some(problem) = Self::unreadable(config) {
            return Err(problem);
        }
        resolve_prewalk(prewalk_into, config).map_err(|e| e.to_string())
    }

    /// The advisor the session is asked for, as things are now. `previous`
    /// is the one it had before the config changed: what that one has
    /// already spent stays spent.
    fn resolve_advisor(
        flag: bool,
        config: Result<&ShaiConfig, &RoleError>,
        previous: Option<&Advisor>,
    ) -> Result<Option<Advisor>, String> {
        if let Some(problem) = Self::unreadable(config) {
            return Err(problem);
        }
        let Some((model, limits)) = resolve_advisor(flag, config).map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        // An advisor only resolves against a config that loaded.
        let config = config.map_err(|e| e.to_string())?;
        // The advisor is confined to the directory the session runs in.
        let working_dir = std::env::current_dir().map_err(|e| {
            format!(
                "cannot start the advisor: no working directory ({})",
                e.kind()
            )
        })?;
        match previous {
            Some(previous) => previous.renewed(model, &working_dir, limits, config),
            None => Advisor::new(model, &working_dir, limits, config),
        }
        .map(Some)
        .map_err(|e| e.to_string())
    }

    /// Options with `prewalk` still to come, for tests of the front-ends.
    #[cfg(test)]
    pub(crate) fn with_prewalk(prewalk: Prewalk) -> Self {
        Self {
            prewalk: Some(prewalk),
            ..Self::default()
        }
    }

    /// True once this session has recorded where its handoff went.
    #[cfg(test)]
    pub(crate) fn on_model_switched_is_recorded(&self) -> bool {
        self.handed_off.is_some()
    }

    /// True while the session has an advisor.
    #[cfg(test)]
    pub(crate) fn has_advisor(&self) -> bool {
        self.advisor.is_some()
    }

    /// True while a handoff is still to come.
    #[cfg(test)]
    pub(crate) fn prewalk_pending(&self) -> bool {
        self.prewalk
            .as_ref()
            .is_some_and(|prewalk| !prewalk.is_spent())
    }

    #[cfg(test)]
    pub(crate) fn prewalk(&self) -> Option<&Prewalk> {
        self.prewalk.as_ref()
    }

    /// Start the prewalk trigger over, keeping the one-shot latch.
    ///
    /// Call this before starting the agent that will load a restored
    /// conversation, so that agent is armed with empty signals.
    pub fn reset_prewalk_signals(&mut self) {
        if let Some(prewalk) = self.prewalk.as_mut() {
            prewalk.reset_signals();
        }
    }

    /// Set `agent` up with what this session was asked for.
    ///
    /// Returns the lines there are for the user: one when a handoff is armed
    /// or an advisor attached for the first time or with a new model, one
    /// whenever something the session still has does not apply to this
    /// agent, and one, once, when the advisor is found switched off.
    pub fn arm(&mut self, agent: &mut AgentCore) -> Vec<String> {
        self.arm_prewalk(agent)
            .into_iter()
            .chain(self.attach_advisor(agent))
            .collect()
    }

    fn attach_advisor(&mut self, agent: &mut AgentCore) -> Option<String> {
        let advisor = self.advisor.clone()?;
        if advisor.is_off() {
            // Its reviews failed while an earlier agent was running, and
            // that holds for the session: neither a new agent nor a new
            // model brings it back, so it is not announced as on. The
            // session lets go of it, which is why this is said once.
            self.advisor = None;
            self.advisor_announced = None;
            return Some(advisor_off_notice(SWITCHED_OFF_EARLIER));
        }
        let label = advisor.label();
        let max_calls = advisor.limits().max_calls;
        let left = max_calls.saturating_sub(advisor.calls_made());
        if left == 0 {
            // It has nothing left to review with, whatever agent or model
            // comes next: it is not announced as on, and this is said once.
            self.advisor = None;
            self.advisor_announced = None;
            return Some(advisor_off_notice(&format!(
                "it has used all {max_calls} of its reviews"
            )));
        }
        match agent.set_advisor(advisor) {
            Ok(()) => {
                if self.advisor_announced.as_deref() == Some(label.as_str()) {
                    return None;
                }
                // What it may still do, not what it could do at the start.
                let notice = advisor_on_notice(&label, left);
                self.advisor_announced = Some(label);
                Some(notice)
            }
            Err(error) => {
                self.advisor_announced = None;
                Some(advisor_not_attached_notice(&error.to_string()))
            }
        }
    }

    /// Arm `agent` with the handoff this session was asked for.
    ///
    /// Returns a line for the user when there is something to say: when a
    /// handoff is armed for the first time or for a new target, and whenever
    /// one that is still to come cannot be armed on this agent.
    fn arm_prewalk(&mut self, agent: &mut AgentCore) -> Option<String> {
        // A handoff that happened without this session being told is
        // accounted for here at the latest.
        self.note_switch();
        let Some(prewalk) = self.prewalk.clone() else {
            // An agent started after the handoff runs on its own model. The
            // last thing said was that the conversation had moved, so say it.
            return self.handed_off.as_deref().map(prewalk_over_notice);
        };
        match agent.arm_prewalk(prewalk.clone()) {
            Ok(()) => {
                let label = prewalk.target().label();
                if self.announced.as_deref() == Some(label.as_str()) {
                    return None;
                }
                let notice = prewalk_armed_notice(&label);
                self.announced = Some(label);
                Some(notice)
            }
            Err(error) => {
                self.announced = None;
                if error == PrewalkArmError::Spent {
                    // Taken by an earlier agent whose brain then failed to
                    // switch, as that agent reported. It is not tried again.
                    self.prewalk = None;
                }
                Some(prewalk_not_armed_notice(&error.to_string()))
            }
        }
    }

    /// Arm a headless agent. Headless denies `write` and `edit` unless
    /// `yes` (`--yes`) is given, so without it the first edit that triggers a
    /// handoff can never happen: the agent is not armed and the user is told.
    pub fn arm_headless(&mut self, agent: &mut AgentCore, yes: bool) -> Vec<String> {
        let pending = self
            .prewalk
            .as_ref()
            .is_some_and(|prewalk| !prewalk.is_spent());
        if !yes && pending {
            // The handoff is not armed, but the advisor is read-only and
            // still attaches.
            self.announced = None;
            return std::iter::once(prewalk_not_armed_notice(HEADLESS_WITHOUT_YES))
                .chain(self.attach_advisor(agent))
                .collect();
        }
        self.arm(agent)
    }

    /// Account for a handoff that has happened: the session keeps where it
    /// went and holds nothing to arm any more. Returns the handoff if this
    /// is the first the session hears of it.
    fn note_switch(&mut self) -> Option<Prewalk> {
        if !self.prewalk.as_ref()?.has_switched() {
            return None;
        }
        let prewalk = self.prewalk.take()?;
        self.handed_off = Some(prewalk.target().label());
        Some(prewalk)
    }

    /// An agent has announced that it moved to `provider`/`model`. Returns
    /// false if this session had already accounted for the handoff, in which
    /// case the announcement is a repeat.
    pub fn on_model_switched(&mut self, provider: &str, model: &str) -> bool {
        if self.prewalk.take().is_none() {
            return false;
        }
        self.handed_off = Some(format!("{provider}/{model}"));
        true
    }

    /// The announcement of a handoff that has happened without this session
    /// being told: the event was lost, or the agent was replaced before its
    /// events were read. The handoff is accounted for from then on.
    pub fn take_unseen_switch(&mut self) -> Option<AgentEvent> {
        let prewalk = self.note_switch()?;
        Some(AgentEvent::ModelSwitched {
            provider: prewalk.target().provider().to_string(),
            model: prewalk.target().model().to_string(),
        })
    }

    /// Resolve the options again, after the config may have changed while
    /// the session was running.
    ///
    /// A handoff that is still to come, and the advisor, follow the config:
    /// each is bound to what it resolves to now, and given up if it no
    /// longer resolves. Neither is left bound to credentials or an endpoint
    /// the config no longer holds, and the advisor learns which credentials
    /// to keep out of what it is sent from the config as it is now. Nothing
    /// that was off when the session started is turned on. Returns lines to
    /// show the user.
    pub fn refresh(&mut self) -> Vec<String> {
        let config = ShaiConfig::load_for_roles();
        self.refresh_from(config.as_ref())
    }

    fn refresh_from(&mut self, config: Result<&ShaiConfig, &RoleError>) -> Vec<String> {
        self.refresh_prewalk(config)
            .into_iter()
            .chain(self.refresh_advisor(config))
            .collect()
    }

    fn refresh_advisor(&mut self, config: Result<&ShaiConfig, &RoleError>) -> Option<String> {
        let current = self.advisor.take()?;
        let reason = match Self::resolve_advisor(self.advisor_flag, config, Some(&current)) {
            Ok(Some(advisor)) => {
                // `arm` announces it again if it is not the same model.
                self.advisor = Some(advisor);
                return None;
            }
            Ok(None) => "the config no longer turns it on".to_string(),
            Err(error) => error,
        };
        self.advisor_announced = None;
        Some(advisor_off_notice(&reason))
    }

    fn refresh_prewalk(&mut self, config: Result<&ShaiConfig, &RoleError>) -> Vec<String> {
        let Some(current) = self.prewalk.clone().filter(|prewalk| !prewalk.is_spent()) else {
            return Vec::new();
        };
        let reason = match Self::resolve_prewalk(self.prewalk_into.as_deref(), config) {
            Ok(Some(target)) => {
                // `arm` announces it again if it is not the same model.
                self.prewalk = Some(current.retarget(target));
                return Vec::new();
            }
            Ok(None) => "the config no longer names a target".to_string(),
            Err(error) => error,
        };
        self.prewalk = None;
        self.announced = None;
        vec![prewalk_disarmed_notice(&reason)]
    }
}

/// Handoffs carried out by a real agent, for tests of the front-ends.
#[cfg(test)]
pub(crate) mod test_support {
    use async_trait::async_trait;
    use openai_dive::v1::resources::chat::{ChatMessage, Function, ToolCall};
    use serde_json::json;
    use shai_core::agent::{
        Agent, AgentBuilder, AgentError, Brain, Prewalk, ThinkerContext, ThinkerDecision,
        ToolBudgetRef,
    };
    use shai_core::tools::FsOperationLog;
    use shai_llm::LlmClient;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::time::Duration;

    /// A brain that replays tool calls and then stops. It talks to no model.
    /// It says it can continue on another one; `switches` is whether it then
    /// does.
    struct ReplayBrain {
        steps: VecDeque<(&'static str, serde_json::Value)>,
        switches: bool,
    }

    #[async_trait]
    impl Brain for ReplayBrain {
        async fn next_step(
            &mut self,
            _: ThinkerContext,
            _: ToolBudgetRef,
        ) -> Result<ThinkerDecision, AgentError> {
            let tool_calls = self.steps.pop_front().map(|(name, arguments)| {
                vec![ToolCall {
                    id: format!("call_{name}"),
                    r#type: "function".to_string(),
                    function: Function {
                        name: name.to_string(),
                        arguments: arguments.to_string(),
                    },
                }]
            });
            Ok(ThinkerDecision::agent_pause(ChatMessage::Assistant {
                content: None,
                reasoning: None,
                reasoning_content: None,
                tool_calls,
                name: None,
                audio: None,
                refusal: None,
            }))
        }

        fn switch_model(&mut self, _: Arc<LlmClient>, _: String) -> bool {
            self.switches
        }

        fn can_switch_model(&self) -> bool {
            true
        }
    }

    /// Let a real agent, armed with `prewalk`, plan and write a file, so
    /// that the handoff comes due. With `switches` the agent then moves to
    /// the target; without, its brain fails to. Nobody reads its events.
    pub(crate) async fn hand_off(prewalk: &Prewalk, switches: bool) {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("out.txt");
        let (tools, todos) = AgentBuilder::create_default_tools(Arc::new(FsOperationLog::new()));
        let brain = ReplayBrain {
            steps: [
                (
                    "todo_write",
                    json!({"todos": [{"content": "write the file", "status": "in_progress"}]}),
                ),
                (
                    "write",
                    json!({"files": [{"path": file.to_string_lossy(), "content": "x"}]}),
                ),
            ]
            .into(),
            switches,
        };
        let mut agent = AgentBuilder::with_brain(Box::new(brain))
            .tools(tools)
            .set_todo_storage(todos)
            .goal("create the file")
            .sudo()
            .build();
        agent.arm_prewalk(prewalk.clone()).unwrap();
        tokio::time::timeout(Duration::from_secs(60), agent.run())
            .await
            .expect("the agent run should finish")
            .expect("the agent run should succeed");
        assert!(file.exists());
        assert!(prewalk.is_spent());
        assert_eq!(prewalk.has_switched(), switches);
    }

    /// A handoff target that talks to nothing.
    pub(crate) fn dummy_prewalk() -> Prewalk {
        Prewalk::new(shai_core::config::roles::BoundModel::new(
            Arc::new(LlmClient::ollama("http://127.0.0.1:9/v1".to_string())),
            "target",
        ))
    }

    /// A saved trace that already holds a successful `todo_write` with items
    /// and a successful `write`. Loading it must not make the trigger due.
    pub(crate) fn planned_and_edited_trace() -> Vec<ChatMessage> {
        let call = |name: &str, arguments: &str| ToolCall {
            id: format!("call_{name}"),
            r#type: "function".to_string(),
            function: Function {
                name: name.to_string(),
                arguments: arguments.to_string(),
            },
        };
        let assistant = |tool_calls| ChatMessage::Assistant {
            content: None,
            reasoning: None,
            reasoning_content: None,
            tool_calls: Some(tool_calls),
            name: None,
            audio: None,
            refusal: None,
        };
        let tool = |id: &str, text: &str| ChatMessage::Tool {
            content: openai_dive::v1::resources::chat::ChatMessageContent::Text(text.to_string()),
            tool_call_id: id.to_string(),
        };
        vec![
            ChatMessage::User {
                content: openai_dive::v1::resources::chat::ChatMessageContent::Text(
                    "create the file".to_string(),
                ),
                name: None,
            },
            assistant(vec![call(
                "todo_write",
                r#"{"todos":[{"content":"write the file","status":"in_progress"}]}"#,
            )]),
            tool("call_todo_write", "1 todos written"),
            assistant(vec![call(
                "write",
                r#"{"files":[{"path":"/tmp/already-written.txt","content":"old"}]}"#,
            )]),
            tool("call_write", "wrote the file"),
        ]
    }

    /// Arm a replay agent with `prewalk`, optionally reset signals first (as
    /// a restore path does), load `trace`, then replay `steps`.
    pub(crate) async fn run_restore(
        mut prewalk: Prewalk,
        reset: bool,
        trace: Vec<ChatMessage>,
        steps: Vec<(&'static str, serde_json::Value)>,
    ) {
        if reset {
            prewalk.reset_signals();
        }
        let (tools, todos) = AgentBuilder::create_default_tools(Arc::new(FsOperationLog::new()));
        let brain = ReplayBrain {
            steps: steps.into(),
            switches: true,
        };
        let mut agent = AgentBuilder::with_brain(Box::new(brain))
            .tools(tools)
            .set_todo_storage(todos)
            .sudo()
            .build();
        agent.arm_prewalk(prewalk.clone()).unwrap();
        let controller = agent.controller();
        let run = tokio::spawn(async move { agent.run().await });
        controller
            .load_trace(trace)
            .await
            .expect("the restored trace should load");
        controller
            .send_user_input("continue".to_string())
            .await
            .expect("the next request should start");
        controller
            .wait_turn(Some(60_000))
            .await
            .expect("the replayed step should finish");
        controller.terminate().await.expect("the agent should stop");
        tokio::time::timeout(Duration::from_secs(60), run)
            .await
            .expect("the agent run should finish")
            .expect("the agent task should join")
            .expect("the agent run should succeed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shai_core::agent::AgentBuilder;
    use shai_core::runners::coder::coder::CoderBrain;
    use shai_core::tools::FsOperationLog;
    use shai_llm::LlmClient;
    use std::sync::Arc;

    /// A config with a keyed `openai` entry and, optionally, an `ollama`
    /// entry at `ollama_url` that the role `cheap` points at.
    fn config(ollama_url: Option<&str>, tail: &str) -> ShaiConfig {
        let ollama = ollama_url
            .map(|url| {
                format!(
                    r#", {{"provider": "ollama", "env_vars": {{"OLLAMA_BASE_URL": "{url}"}}, "model": "llama3", "tool_method": "FunctionCall"}}"#
                )
            })
            .unwrap_or_default();
        serde_json::from_str(&format!(
            r#"{{
                "providers": [
                    {{"provider": "openai", "env_vars": {{"OPENAI_API_KEY": "k"}}, "model": "gpt-4o", "tool_method": "FunctionCall"}}
                    {ollama}
                ],
                "selected_provider": 0,
                "roles": {{"cheap": "ollama/qwen3:8b"}}
                {tail}
            }}"#
        ))
        .expect("config should load")
    }

    const URL_A: &str = "http://127.0.0.1:9/v1";

    /// An agent on the coder brain that is never run: no socket is opened.
    fn agent(without_tools: &[&str]) -> AgentCore {
        let (tools, _) = AgentBuilder::create_default_tools(Arc::new(FsOperationLog::new()));
        let tools = tools
            .into_iter()
            .filter(|tool| !without_tools.contains(&tool.name().as_str()))
            .collect();
        let llm = Arc::new(LlmClient::ollama(URL_A.to_string()));
        AgentBuilder::with_brain(Box::new(CoderBrain::new(llm, "primary".to_string())))
            .tools(tools)
            .build()
    }

    /// The one line there is to show.
    fn only(mut notices: Vec<String>) -> String {
        assert_eq!(notices.len(), 1, "{notices:?}");
        notices.remove(0)
    }

    /// A brain that neither changes model nor takes advisor notes.
    struct PlainBrain;

    #[async_trait::async_trait]
    impl shai_core::agent::Brain for PlainBrain {
        async fn next_step(
            &mut self,
            _: shai_core::agent::ThinkerContext,
            _: shai_core::agent::ToolBudgetRef,
        ) -> Result<shai_core::agent::ThinkerDecision, shai_core::agent::AgentError> {
            unreachable!("the agent is never run")
        }
    }

    /// The same config with the role `advisor` on the `ollama` entry.
    fn config_with_advisor(tail: &str) -> ShaiConfig {
        let mut cfg = config(Some(URL_A), tail);
        cfg.roles = shai_core::config::roles::RolesConfig::from_pairs([
            ("cheap", "ollama/qwen3:8b"),
            ("advisor", "ollama/reviewer"),
        ]);
        cfg
    }

    fn invalid() -> RoleError {
        RoleError::ConfigInvalid {
            path: "/home/me/.config/shai/auth.config.json".to_string(),
            reason: "JSON syntax error at line 3 column 7".to_string(),
        }
    }

    #[test]
    fn nothing_asked_for_means_nothing_to_arm() {
        let cfg = config(Some(URL_A), "");
        let mut options = SessionOptions::resolve_from(None, false, Ok(&cfg)).unwrap();
        assert!(!options.prewalk_pending());
        let mut agent = agent(&[]);
        assert_eq!(options.arm_prewalk(&mut agent), None);
        assert!(!agent.is_prewalk_armed());
        assert!(options.refresh_from(Ok(&cfg)).is_empty());
        assert!(options.take_unseen_switch().is_none());

        // The same when there is no config file at all.
        let options =
            SessionOptions::resolve_from(None, false, Err(&RoleError::ConfigMissing)).unwrap();
        assert!(!options.prewalk_pending());
    }

    #[test]
    fn a_config_file_that_cannot_be_read_stops_the_session() {
        // With or without the flag: the file may ask for a handoff.
        for flag in [None, Some("cheap")] {
            let error = SessionOptions::resolve_from(flag, false, Err(&invalid()))
                .err()
                .expect("the session must not start");
            assert!(error.contains("auth.config.json"), "{error}");
            assert!(error.contains("line 3 column 7"), "{error}");
        }
    }

    #[test]
    fn an_unresolvable_target_stops_the_session() {
        let cfg = config(Some(URL_A), "");
        assert!(SessionOptions::resolve_from(Some("planner"), false, Ok(&cfg)).is_err());
        let cfg = config(Some(URL_A), r#", "prewalk": {"into": "planner"}"#);
        assert!(SessionOptions::resolve_from(None, false, Ok(&cfg)).is_err());
        assert!(
            SessionOptions::resolve_from(Some("cheap"), false, Err(&RoleError::ConfigMissing))
                .is_err()
        );
    }

    #[test]
    fn arming_is_announced_once_per_target() {
        let cfg = config(Some(URL_A), "");
        let mut options = SessionOptions::resolve_from(Some("cheap"), false, Ok(&cfg)).unwrap();
        assert!(options.prewalk_pending());

        let mut first = agent(&[]);
        let notice = options
            .arm_prewalk(&mut first)
            .expect("armed for the first time");
        assert!(
            notice.starts_with("prewalk armed:") && notice.contains("ollama/qwen3:8b"),
            "{notice}"
        );
        assert!(first.is_prewalk_armed());

        // An agent that replaces it is armed too, without saying it again.
        let mut second = agent(&[]);
        assert_eq!(options.arm_prewalk(&mut second), None);
        assert!(second.is_prewalk_armed());
    }

    #[test]
    fn an_agent_that_can_never_hand_off_is_not_armed_and_the_user_is_told() {
        let cfg = config(Some(URL_A), "");
        let mut options = SessionOptions::resolve_from(Some("cheap"), false, Ok(&cfg)).unwrap();

        let mut no_todo = agent(&["todo_write"]);
        let notice = options
            .arm_prewalk(&mut no_todo)
            .expect("the user must be told");
        assert!(notice.starts_with("prewalk not armed:"), "{notice}");
        assert!(notice.contains("todo_write"), "{notice}");
        assert!(!no_todo.is_prewalk_armed());

        // Said every time, and the handoff is still there for an agent that
        // can take it, which is announced as armed.
        let mut no_edit = agent(&["write", "edit"]);
        let notice = options
            .arm_prewalk(&mut no_edit)
            .expect("the user must be told");
        assert!(notice.contains("write or edit"), "{notice}");
        assert!(options.prewalk_pending());
        let mut usable = agent(&[]);
        let notice = options.arm_prewalk(&mut usable).expect("armed");
        assert!(notice.starts_with("prewalk armed:"), "{notice}");
    }

    #[test]
    fn headless_without_yes_is_not_armed_and_the_user_is_told() {
        let cfg = config(Some(URL_A), "");
        let mut options = SessionOptions::resolve_from(Some("cheap"), false, Ok(&cfg)).unwrap();

        // Without --yes, write and edit are denied, so the handoff could
        // never come due: no "armed" line, and the reason names --yes.
        let mut denied = agent(&[]);
        let notices = options.arm_headless(&mut denied, false);
        assert_eq!(notices.len(), 1, "{notices:?}");
        let notice = &notices[0];
        assert!(notice.starts_with("prewalk not armed:"), "{notice}");
        assert!(notice.contains("--yes"), "{notice}");
        assert!(!denied.is_prewalk_armed());
        assert!(options.prewalk_pending());

        // With --yes the same agent is armed, and that is announced.
        let mut allowed = agent(&[]);
        let notices = options.arm_headless(&mut allowed, true);
        assert_eq!(notices.len(), 1, "{notices:?}");
        let notice = &notices[0];
        assert!(notice.starts_with("prewalk armed:"), "{notice}");
        assert!(allowed.is_prewalk_armed());

        // Nothing asked for: nothing to say, with or without --yes.
        let mut options = SessionOptions::resolve_from(None, false, Ok(&cfg)).unwrap();
        assert_eq!(
            options.arm_headless(&mut agent(&[]), false),
            Vec::<String>::new()
        );
        assert_eq!(
            options.arm_headless(&mut agent(&[]), true),
            Vec::<String>::new()
        );
    }

    #[test]
    fn headless_without_yes_still_attaches_the_read_only_advisor() {
        let cfg = config_with_advisor("");
        let mut options = SessionOptions::resolve_from(Some("cheap"), true, Ok(&cfg)).unwrap();

        // Without --yes the handoff is not armed, but the advisor writes
        // nothing, so it is attached and announced all the same.
        let mut denied = agent(&[]);
        let notices = options.arm_headless(&mut denied, false);
        assert_eq!(notices.len(), 2, "{notices:?}");
        assert!(notices[0].starts_with("prewalk not armed:"), "{notices:?}");
        assert!(notices[0].contains("--yes"), "{notices:?}");
        assert!(notices[1].starts_with("advisor on:"), "{notices:?}");
        assert!(!denied.is_prewalk_armed());
        assert!(denied.has_advisor());
        assert!(options.prewalk_pending());

        // With only the advisor asked for, --yes makes no difference.
        let mut options = SessionOptions::resolve_from(None, true, Ok(&cfg)).unwrap();
        let mut plain = agent(&[]);
        let notice = only(options.arm_headless(&mut plain, false));
        assert!(notice.starts_with("advisor on:"), "{notice}");
        assert!(plain.has_advisor());
    }

    #[test]
    fn the_primary_model_respects_anonymous_fallback_without_silently_ignoring_broken_files() {
        // The user's file, as loaded.
        let cfg = config(Some(URL_A), "");
        let primary = SessionOptions::primary_config_from_with_env(Ok(cfg), None).unwrap();
        assert_eq!(primary.providers[0].provider, "openai");

        // No file at all under default prompt mode: the built-in default.
        let primary =
            SessionOptions::primary_config_from_with_env(Err(RoleError::ConfigMissing), None)
                .unwrap();
        assert_eq!(
            primary.providers[0].provider,
            ShaiConfig::default().providers[0].provider
        );

        // No file at all under deny: refuse to start with PrimaryConfigError::Missing.
        let error = SessionOptions::primary_config_from_with_env(
            Err(RoleError::ConfigMissing),
            Some("deny"),
        )
        .map(|_| ())
        .expect_err("deny must refuse a missing file");
        assert!(matches!(error, PrimaryConfigError::Missing), "{error:?}");
        assert!(error.is_refused_start());

        // A file that is there and does not load is never replaced by the
        // default: the agent does not start, and the user is told why.
        let error = SessionOptions::primary_config_from_with_env(Err(invalid()), None)
            .map(|_| ())
            .expect_err("no default for a broken file");
        assert!(
            matches!(error, PrimaryConfigError::Invalid { .. }),
            "{error:?}"
        );
        assert!(error.is_refused_start());
        let message = error.to_string();
        assert!(message.contains("auth.config.json"), "{message}");
        assert!(message.contains("line 3 column 7"), "{message}");
    }

    #[test]
    fn a_changed_config_re_aims_or_gives_up_the_handoff() {
        let cfg = config(Some(URL_A), "");
        let mut options = SessionOptions::resolve_from(Some("cheap"), false, Ok(&cfg)).unwrap();
        let mut before = agent(&[]);
        assert!(options.arm_prewalk(&mut before).is_some());

        // The same config: nothing to say, still armed.
        assert!(options.refresh_from(Ok(&cfg)).is_empty());
        assert!(options.prewalk_pending());

        // The role now points at another model: armed again, and announced.
        let other_model: ShaiConfig = serde_json::from_str(
            &serde_json::to_string(&cfg)
                .unwrap()
                .replace("ollama/qwen3:8b", "ollama/phi4"),
        )
        .unwrap();
        assert!(options.refresh_from(Ok(&other_model)).is_empty());
        let notice = options.arm_prewalk(&mut agent(&[])).expect("a new target");
        assert!(notice.contains("ollama/phi4"), "{notice}");

        // The provider entry is gone: the handoff is given up, visibly, and
        // the next agent is not armed with the client bound at start-up.
        let removed = config(None, "");
        let notices = options.refresh_from(Ok(&removed));
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(
            notices[0].starts_with("prewalk disarmed") && notices[0].contains("not configured"),
            "{notices:?}"
        );
        assert!(!options.prewalk_pending());
        let mut after = agent(&[]);
        assert_eq!(options.arm_prewalk(&mut after), None);
        assert!(!after.is_prewalk_armed());

        // Given up for good: a later change does not bring it back.
        assert!(options.refresh_from(Ok(&cfg)).is_empty());
        assert!(!options.prewalk_pending());
    }

    #[test]
    fn a_config_that_stops_loading_or_asking_gives_up_the_handoff() {
        let asking = config(Some(URL_A), r#", "prewalk": {"into": "cheap"}"#);

        let mut options = SessionOptions::resolve_from(None, false, Ok(&asking)).unwrap();
        assert!(options.prewalk_pending());
        let notices = options.refresh_from(Err(&invalid()));
        assert!(notices[0].contains("could not be loaded"), "{notices:?}");
        assert!(!options.prewalk_pending());

        let mut options = SessionOptions::resolve_from(None, false, Ok(&asking)).unwrap();
        let notices = options.refresh_from(Ok(&config(Some(URL_A), "")));
        assert!(
            notices[0].contains("no longer names a target"),
            "{notices:?}"
        );
        assert!(!options.prewalk_pending());

        // A target given on the command line does not depend on the section.
        let mut options = SessionOptions::resolve_from(Some("cheap"), false, Ok(&asking)).unwrap();
        assert!(options
            .refresh_from(Ok(&config(Some(URL_A), "")))
            .is_empty());
        assert!(options.prewalk_pending());
    }

    #[test]
    fn a_switch_is_accounted_for_once() {
        let cfg = config(Some(URL_A), "");
        let mut options = SessionOptions::resolve_from(Some("cheap"), false, Ok(&cfg)).unwrap();
        // Nothing has happened: nothing unseen.
        assert!(options.take_unseen_switch().is_none());
        assert!(options.prewalk_pending());

        // The agent's own announcement arrives: news once, a repeat after.
        assert!(options.on_model_switched("ollama", "qwen3:8b"));
        assert!(!options.on_model_switched("ollama", "qwen3:8b"));
        assert!(!options.prewalk_pending());
        assert!(options.take_unseen_switch().is_none());

        // An agent started after that is not armed, and is not on the
        // target either: the user is told, every time.
        for _ in 0..2 {
            let mut later = agent(&[]);
            let notice = options
                .arm_prewalk(&mut later)
                .expect("the user must be told");
            assert!(
                notice.starts_with("prewalk is over:") && notice.contains("ollama/qwen3:8b"),
                "{notice}"
            );
            assert!(!later.is_prewalk_armed());
        }
        // A config change does not bring the handoff back.
        assert!(options.refresh_from(Ok(&cfg)).is_empty());
        assert!(options
            .arm_prewalk(&mut agent(&[]))
            .is_some_and(|n| n.starts_with("prewalk is over:")));
    }

    #[tokio::test]
    async fn a_switch_nobody_announced_is_accounted_for_when_the_next_agent_is_armed() {
        let cfg = config(Some(URL_A), "");
        let mut options = SessionOptions::resolve_from(Some("cheap"), false, Ok(&cfg)).unwrap();
        let handoff = options.prewalk.clone().expect("a handoff to come");
        test_support::hand_off(&handoff, true).await;

        // Headless mode and any path that skipped `take_unseen_switch`: the
        // next agent is still not armed, and the user is told why.
        let mut next = agent(&[]);
        let notice = options
            .arm_prewalk(&mut next)
            .expect("the user must be told");
        assert!(
            notice.starts_with("prewalk is over:") && notice.contains("ollama/qwen3:8b"),
            "{notice}"
        );
        assert!(!next.is_prewalk_armed());
        assert!(options.take_unseen_switch().is_none());
    }

    #[tokio::test]
    async fn a_handoff_that_failed_is_not_tried_again_and_the_user_is_told() {
        let cfg = config(Some(URL_A), "");
        let mut options = SessionOptions::resolve_from(Some("cheap"), false, Ok(&cfg)).unwrap();
        let handoff = options.prewalk.clone().expect("a handoff to come");
        // An agent takes the handoff and its brain then fails to switch.
        test_support::hand_off(&handoff, false).await;

        // That is not a switch, and is not announced as one.
        assert!(options.take_unseen_switch().is_none());
        assert!(!options.on_model_switched_is_recorded());

        // The next agent is not armed, with the reason, once.
        let mut next = agent(&[]);
        let notice = options
            .arm_prewalk(&mut next)
            .expect("the user must be told");
        assert!(
            notice.starts_with("prewalk not armed:") && notice.contains("already tried"),
            "{notice}"
        );
        assert!(!next.is_prewalk_armed());
        assert_eq!(options.arm_prewalk(&mut agent(&[])), None);
        assert!(options.refresh_from(Ok(&cfg)).is_empty());
    }

    #[test]
    fn the_advisor_is_off_unless_asked_for_and_refused_when_it_cannot_resolve() {
        // A role named `advisor` alone turns nothing on.
        let cfg = config_with_advisor("");
        let options = SessionOptions::resolve_from(None, false, Ok(&cfg)).unwrap();
        assert!(!options.has_advisor());

        // Asked for without the role, or without a config: no session.
        let without_role = config(Some(URL_A), "");
        let error = SessionOptions::resolve_from(None, true, Ok(&without_role))
            .err()
            .expect("the session must not start");
        assert!(error.contains("advisor"), "{error}");
        let enabled = config(Some(URL_A), r#", "advisor": {"enabled": true}"#);
        assert!(SessionOptions::resolve_from(None, false, Ok(&enabled)).is_err());
        assert!(SessionOptions::resolve_from(None, true, Err(&RoleError::ConfigMissing)).is_err());
        assert!(SessionOptions::resolve_from(None, true, Err(&invalid())).is_err());
    }

    #[test]
    fn the_advisor_is_attached_to_each_agent_and_announced_once() {
        let cfg = config_with_advisor("");
        let mut options = SessionOptions::resolve_from(None, true, Ok(&cfg)).unwrap();
        assert!(options.has_advisor());

        let mut first = agent(&[]);
        let notice = only(options.arm(&mut first));
        assert!(
            notice.starts_with("advisor on: ollama/reviewer") && notice.contains("at most 10"),
            "{notice}"
        );
        assert!(first.has_advisor());

        let mut second = agent(&[]);
        assert!(options.arm(&mut second).is_empty());
        assert!(second.has_advisor());

        // From the config alone, with its own limit.
        let cfg = config_with_advisor(r#", "advisor": {"enabled": true, "max_calls": 3}"#);
        let mut options = SessionOptions::resolve_from(None, false, Ok(&cfg)).unwrap();
        let notice = only(options.arm(&mut agent(&[])));
        assert!(notice.contains("at most 3"), "{notice}");
    }

    #[test]
    fn an_agent_that_takes_no_notes_gets_no_advisor_and_the_user_is_told() {
        let cfg = config_with_advisor("");
        let mut options = SessionOptions::resolve_from(Some("cheap"), true, Ok(&cfg)).unwrap();
        let mut plain = AgentBuilder::with_brain(Box::new(PlainBrain)).build();

        // Neither option applies to this agent, and each says so.
        let notices = options.arm(&mut plain);
        assert_eq!(notices.len(), 2, "{notices:?}");
        assert!(notices[0].starts_with("prewalk not armed:"), "{notices:?}");
        assert!(
            notices[1].starts_with("advisor not attached:") && notices[1].contains("notes"),
            "{notices:?}"
        );
        assert!(!plain.has_advisor());
        assert!(!plain.is_prewalk_armed());

        // The session keeps both for an agent that can use them.
        let mut usable = agent(&[]);
        let notices = options.arm(&mut usable);
        assert_eq!(notices.len(), 2, "{notices:?}");
        assert!(notices[0].starts_with("prewalk armed:"), "{notices:?}");
        assert!(notices[1].starts_with("advisor on:"), "{notices:?}");
        assert!(usable.has_advisor());
    }

    #[test]
    fn a_changed_config_renews_or_gives_up_the_advisor() {
        let cfg = config_with_advisor("");
        let mut options = SessionOptions::resolve_from(None, true, Ok(&cfg)).unwrap();
        assert_eq!(options.arm(&mut agent(&[])).len(), 1);

        // The same config: still on, nothing to say.
        assert!(options.refresh_from(Ok(&cfg)).is_empty());
        assert!(options.has_advisor());
        assert!(options.arm(&mut agent(&[])).is_empty());

        // The role points at another model: on, and announced again.
        let other: ShaiConfig = serde_json::from_str(
            &serde_json::to_string(&cfg)
                .unwrap()
                .replace("ollama/reviewer", "ollama/second-opinion"),
        )
        .unwrap();
        assert!(options.refresh_from(Ok(&other)).is_empty());
        let notice = only(options.arm(&mut agent(&[])));
        assert!(notice.contains("ollama/second-opinion"), "{notice}");

        // The role is gone: the advisor is given up, visibly, and the next
        // agent does not get the one that was bound at start-up.
        let notices = options.refresh_from(Ok(&config(Some(URL_A), "")));
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(
            notices[0].starts_with("advisor off for the rest of this session:"),
            "{notices:?}"
        );
        assert!(!options.has_advisor());
        let mut after = agent(&[]);
        assert!(options.arm(&mut after).is_empty());
        assert!(!after.has_advisor());

        // Given up for good, and never turned on by a later change.
        assert!(options.refresh_from(Ok(&cfg)).is_empty());
        assert!(!options.has_advisor());
        let enabled = config_with_advisor(r#", "advisor": {"enabled": true}"#);
        let mut off = SessionOptions::resolve_from(None, false, Ok(&cfg)).unwrap();
        assert!(off.refresh_from(Ok(&enabled)).is_empty());
        assert!(!off.has_advisor());
    }

    /// A provider that answers every request with an error, without a socket.
    struct Unreachable;

    #[async_trait::async_trait]
    impl shai_llm::provider::LlmProvider for Unreachable {
        async fn models(
            &self,
        ) -> Result<
            openai_dive::v1::resources::model::ListModelResponse,
            shai_llm::provider::LlmError,
        > {
            Err("no model listing".into())
        }

        async fn chat(
            &self,
            _: openai_dive::v1::resources::chat::ChatCompletionParameters,
        ) -> Result<
            openai_dive::v1::resources::chat::ChatCompletionResponse,
            shai_llm::provider::LlmError,
        > {
            // Of a kind the client does not try again.
            Err(Box::new(
                openai_dive::v1::error::APIError::InvalidRequestError(
                    "model not found".to_string(),
                ),
            ))
        }

        async fn chat_stream(
            &self,
            _: openai_dive::v1::resources::chat::ChatCompletionParameters,
        ) -> Result<shai_llm::provider::LlmStream, shai_llm::provider::LlmError> {
            Err("no streaming".into())
        }

        fn supports_functions(&self, _: String) -> bool {
            true
        }

        fn supports_structured_output(&self, _: String) -> bool {
            false
        }

        fn name(&self) -> &'static str {
            "unreachable"
        }

        fn info() -> shai_llm::provider::ProviderInfo {
            shai_llm::provider::ProviderInfo {
                name: "unreachable",
                display_name: "Unreachable (tests)",
                env_vars: Vec::new(),
            }
        }
    }

    /// A brain that lists a directory a few times and then stops, without
    /// asking a model. It answers that it takes advisor notes, so that an
    /// advisor can be attached to its agent.
    struct ListingBrain {
        steps: usize,
        directory: String,
    }

    #[async_trait::async_trait]
    impl shai_core::agent::Brain for ListingBrain {
        async fn next_step(
            &mut self,
            _: shai_core::agent::ThinkerContext,
            _: shai_core::agent::ToolBudgetRef,
        ) -> Result<shai_core::agent::ThinkerDecision, shai_core::agent::AgentError> {
            use openai_dive::v1::resources::chat::{ChatMessage, Function, ToolCall};
            let tool_calls = (self.steps > 0).then(|| {
                self.steps -= 1;
                vec![ToolCall {
                    id: format!("call_ls_{}", self.steps),
                    r#type: "function".to_string(),
                    function: Function {
                        name: "ls".to_string(),
                        arguments: serde_json::json!({"directory": self.directory}).to_string(),
                    },
                }]
            });
            Ok(shai_core::agent::ThinkerDecision::agent_pause(
                ChatMessage::Assistant {
                    content: None,
                    reasoning: None,
                    reasoning_content: None,
                    tool_calls,
                    name: None,
                    audio: None,
                    refusal: None,
                },
            ))
        }

        fn takes_advisor_notes(&self) -> bool {
            true
        }
    }

    /// A session whose advisor has just been switched off: an agent of the
    /// session did two steps, and the review of each failed.
    async fn session_with_a_failed_advisor() -> SessionOptions {
        let (options, advisor) = session_after_failed_reviews(10, 2).await;
        assert_eq!(advisor.calls_made(), 2);
        assert!(advisor.is_off());
        options
    }

    /// A session in which an agent did `steps` steps and the review of each
    /// failed, with an advisor allowed `max_calls` reviews.
    async fn session_after_failed_reviews(
        max_calls: u32,
        steps: usize,
    ) -> (SessionOptions, Advisor) {
        use shai_core::advisor::AdvisorLimits;
        use shai_core::agent::Agent;

        let dir = tempfile::TempDir::new().unwrap();
        let advisor = Advisor::new(
            BoundModel::new(
                Arc::new(LlmClient::from_provider(Box::new(Unreachable))),
                "reviewer",
            ),
            dir.path(),
            AdvisorLimits {
                max_calls,
                cooldown_turns: 0,
            },
            &config_with_advisor(""),
        )
        .expect("advisor");
        let mut options = SessionOptions {
            advisor_flag: true,
            advisor: Some(advisor.clone()),
            ..SessionOptions::default()
        };

        let (tools, _) = AgentBuilder::create_default_tools(Arc::new(FsOperationLog::new()));
        let brain = ListingBrain {
            steps,
            directory: dir.path().to_string_lossy().into_owned(),
        };
        let mut agent = AgentBuilder::with_brain(Box::new(brain))
            .tools(tools)
            .goal("look around")
            .sudo()
            .build();
        let notice = only(options.arm(&mut agent));
        assert!(
            notice.starts_with("advisor on: unreachable/reviewer"),
            "{notice}"
        );
        assert!(agent.has_advisor());
        tokio::time::timeout(std::time::Duration::from_secs(60), agent.run())
            .await
            .expect("the agent run should finish")
            .expect("the agent run should succeed");
        (options, advisor)
    }

    #[tokio::test]
    async fn an_advisor_that_has_used_its_reviews_is_not_announced_as_on_again() {
        // One review allowed, and it was made. It failed once, which does
        // not switch the advisor off.
        let (mut options, advisor) = session_after_failed_reviews(1, 1).await;
        assert_eq!(advisor.calls_made(), 1);
        assert!(!advisor.is_off());

        let mut next = agent(&[]);
        let notice = only(options.arm(&mut next));
        assert_eq!(
            notice,
            "advisor off for the rest of this session: it has used all 1 of its reviews"
        );
        assert!(!next.has_advisor());
        // Said once.
        assert!(!options.has_advisor());
        assert!(options.arm(&mut agent(&[])).is_empty());

        // With reviews left, what is announced is what is left.
        let (mut options, advisor) = session_after_failed_reviews(3, 1).await;
        assert_eq!(advisor.calls_made(), 1);
        options.advisor_announced = None;
        let mut next = agent(&[]);
        let notice = only(options.arm(&mut next));
        assert!(notice.ends_with("read-only, at most 2 times"), "{notice}");
        assert!(next.has_advisor());
    }

    #[tokio::test]
    async fn an_advisor_that_was_switched_off_is_not_announced_as_on_again() {
        let cfg = config_with_advisor("");
        // Each case below starts from the same moment of the same session.
        let failed = session_with_a_failed_advisor().await;

        // The config is read again for the next agent and names a model the
        // advisor has not been announced with.
        let mut options = failed.clone();
        assert!(options.refresh_from(Ok(&cfg)).is_empty());
        let mut next = agent(&[]);
        let notice = only(options.arm(&mut next));
        assert_eq!(
            notice,
            "advisor off for the rest of this session: \
             it was switched off earlier, after its reviews kept failing"
        );
        assert!(!next.has_advisor());
        // Said once, and nothing brings the advisor back.
        assert!(!options.has_advisor());
        assert!(options.arm(&mut agent(&[])).is_empty());
        assert!(options.refresh_from(Ok(&cfg)).is_empty());
        let mut later = agent(&[]);
        assert!(options.arm(&mut later).is_empty());
        assert!(!later.has_advisor());

        // The same when the next agent is one that takes no notes, and the
        // one after it is one that does.
        let mut options = failed.clone();
        let mut plain = AgentBuilder::with_brain(Box::new(PlainBrain)).build();
        let notice = only(options.arm(&mut plain));
        assert!(
            notice.starts_with("advisor off for the rest of this session:"),
            "{notice}"
        );
        let mut usable = agent(&[]);
        assert!(options.arm(&mut usable).is_empty());
        assert!(!usable.has_advisor());

        // And when nothing changed at all: the next agent is not attached to
        // an advisor that will not run, and the user is told why.
        let mut options = failed;
        let mut next = agent(&[]);
        let notice = only(options.arm(&mut next));
        assert!(
            notice.starts_with("advisor off for the rest of this session:"),
            "{notice}"
        );
        assert!(!next.has_advisor());
    }

    #[test]
    fn a_config_that_stops_loading_or_asking_gives_up_the_advisor() {
        let enabled = config_with_advisor(r#", "advisor": {"enabled": true}"#);

        let mut options = SessionOptions::resolve_from(None, false, Ok(&enabled)).unwrap();
        assert!(options.has_advisor());
        let notices = options.refresh_from(Err(&invalid()));
        assert!(notices[0].contains("could not be loaded"), "{notices:?}");
        assert!(!options.has_advisor());

        let mut options = SessionOptions::resolve_from(None, false, Ok(&enabled)).unwrap();
        let notices = options.refresh_from(Ok(&config_with_advisor("")));
        assert!(notices[0].contains("no longer turns it on"), "{notices:?}");
        assert!(!options.has_advisor());

        // Asked for on the command line: it does not depend on the section.
        let mut options = SessionOptions::resolve_from(None, true, Ok(&enabled)).unwrap();
        assert!(options
            .refresh_from(Ok(&config_with_advisor("")))
            .is_empty());
        assert!(options.has_advisor());
    }

    #[tokio::test]
    async fn a_restored_trace_does_not_hand_off_until_the_trigger_runs_again() {
        // A fresh process that restores a conversation which already planned
        // and edited: the saved trace does not count. One new write is not
        // enough; the handoff waits for a new todo list as well.
        let prewalk = test_support::dummy_prewalk();
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("out.txt");
        test_support::run_restore(
            prewalk.clone(),
            true,
            test_support::planned_and_edited_trace(),
            vec![(
                "write",
                serde_json::json!({"files": [{"path": file.to_string_lossy(), "content": "x"}]}),
            )],
        )
        .await;
        assert!(file.exists());
        assert!(!prewalk.trigger_is_due());
        assert!(!prewalk.is_spent());
        assert!(!prewalk.has_switched());
    }

    #[tokio::test]
    async fn restoring_another_conversation_does_not_keep_the_previous_signals() {
        // Same process: signals from the conversation just left would make
        // the next request hand off immediately. Reset starts the trigger
        // over before the new agent is armed and the unrelated trace loaded.
        let prewalk = test_support::dummy_prewalk();
        prewalk.record_success("write", None);
        prewalk.record_success("todo_write", Some(1));
        assert!(prewalk.trigger_is_due());

        let mut options = SessionOptions::with_prewalk(prewalk.clone());
        options.reset_prewalk_signals();
        assert!(!options.prewalk.as_ref().unwrap().trigger_is_due());

        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("other.txt");
        test_support::run_restore(
            options.prewalk.clone().unwrap(),
            false,
            vec![openai_dive::v1::resources::chat::ChatMessage::User {
                content: openai_dive::v1::resources::chat::ChatMessageContent::Text(
                    "an unrelated conversation".to_string(),
                ),
                name: None,
            }],
            vec![(
                "write",
                serde_json::json!({"files": [{"path": file.to_string_lossy(), "content": "y"}]}),
            )],
        )
        .await;
        assert!(file.exists());
        // The write ran, but there is still no todo list in this conversation.
        assert!(!options.prewalk.as_ref().unwrap().trigger_is_due());
        assert!(!options.prewalk.as_ref().unwrap().is_spent());
    }
}
