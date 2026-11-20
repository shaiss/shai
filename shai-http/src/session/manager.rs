use openai_dive::v1::resources::chat::ChatMessage;
use shai_core::agent::{Agent, AgentError};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};

use crate::session::{log_event, logger::colored_session_id};
use shai_core::agent::AgentBuilder;
use shai_core::config::config::ShaiConfig;
use shai_core::session::SessionPersist;

use super::AgentSession;

/// Configuration for the session manager
#[derive(Clone)]
pub struct SessionManagerConfig {
    /// Maximum number of concurrent sessions (None = unlimited)
    pub max_sessions: Option<usize>,
    /// Whether sessions are ephemeral or background (ephemeral session is destroyed after a single query)
    pub ephemeral: bool,
    /// Grant every tool to every session (`shai serve --yes`). When false,
    /// sessions run read-only tools and any tool that writes, runs bash or
    /// uses the network is denied at once: HTTP clients cannot answer a
    /// permission prompt.
    pub allow_all_tools: bool,
    /// Auth config loaded at serve startup. Sessions build default agents
    /// from this snapshot instead of reading the file again.
    pub primary: Option<Arc<ShaiConfig>>,
}

impl Default for SessionManagerConfig {
    fn default() -> Self {
        Self {
            max_sessions: Some(100),
            ephemeral: false,
            allow_all_tools: false,
            primary: None,
        }
    }
}

impl std::fmt::Debug for SessionManagerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManagerConfig")
            .field("max_sessions", &self.max_sessions)
            .field("ephemeral", &self.ephemeral)
            .field("allow_all_tools", &self.allow_all_tools)
            .field("primary", &self.primary.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Session manager - manages multiple agent sessions by ID
/// Handles creation, deletion, and access control for sessions
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<String, Arc<AgentSession>>>>,
    max_sessions: Option<usize>,
    ephemeral: bool,
    allow_all_tools: bool,
    primary: Option<Arc<ShaiConfig>>,
}

impl SessionManager {
    pub fn new(config: SessionManagerConfig) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            max_sessions: config.max_sessions,
            ephemeral: config.ephemeral,
            allow_all_tools: config.allow_all_tools,
            primary: config.primary,
        }
    }

    /// Apply the server's tool policy (and an optional restored trace) to a
    /// session's agent. Nobody can answer a permission prompt over HTTP, so
    /// this never grants more than `allow_all_tools` allows.
    fn prepare_agent(
        &self,
        builder: AgentBuilder,
        trace: Option<Vec<ChatMessage>>,
    ) -> AgentBuilder {
        let builder = builder.headless_permissions(self.allow_all_tools);
        match trace {
            Some(trace) => builder.with_traces(trace),
            None => builder,
        }
    }

    async fn create_session(
        &self,
        http_request_id: &String,
        session_id: &str,
        agent_name: Option<String>,
        ephemeral: bool,
        trace: Option<Vec<ChatMessage>>,
    ) -> Result<Arc<AgentSession>, AgentError> {
        info!(
            "[{}] - {} Creating new session",
            http_request_id,
            colored_session_id(session_id)
        );

        // Build the agent from the startup config snapshot so a later edit
        // of the auth file cannot change credentials mid-server.
        let builder = AgentBuilder::create_with_primary(
            agent_name.clone().filter(|name| name != "default"),
            self.primary.as_deref(),
        )
        .await
        .map_err(|e| AgentError::ExecutionError(format!("Failed to create agent: {}", e)))?;

        let mut agent = self.prepare_agent(builder, trace).build();

        let controller = agent.controller();
        let event_rx = agent.watch();

        // Spawn logging task alongside agent
        let mut event_for_logger = event_rx.resubscribe();
        let sid_for_logger = session_id.to_string();
        let logging_task = tokio::spawn(async move {
            while let Ok(event) = event_for_logger.recv().await {
                log_event(&event, &sid_for_logger);
            }
        });

        // Spawn agent task with cleanup logic
        let sessions_for_cleanup = self.sessions.clone();
        let sid_for_cleanup = session_id.to_string();
        let agent_task = tokio::spawn(async move {
            match agent.run().await {
                Ok(_) => {
                    info!(
                        "{} - Agent Terminated",
                        colored_session_id(&sid_for_cleanup)
                    );
                }
                Err(e) => {
                    error!(
                        "{} - Agent execution error: {}",
                        colored_session_id(&sid_for_cleanup),
                        e
                    );
                }
            }
            sessions_for_cleanup.lock().await.remove(&sid_for_cleanup);
            info!(
                "{} - Session removed from manager",
                colored_session_id(&sid_for_cleanup)
            );
        });

        let session = Arc::new(AgentSession::new(
            session_id.to_string(),
            controller,
            event_rx,
            logging_task,
            agent_task,
            agent_name,
            ephemeral,
        ));

        Ok(session)
    }

    /// Get an existing session by ID
    /// If not in memory, attempts to load from disk using the provided agent_name
    /// Returns error if session doesn't exist in memory or on disk
    pub async fn get_session(
        &self,
        http_request_id: &str,
        session_id: &str,
        agent_name: String,
    ) -> Result<Arc<AgentSession>, AgentError> {
        // First check in-memory sessions
        {
            let sessions = self.sessions.lock().await;
            if let Some(session) = sessions.get(session_id) {
                info!(
                    "[{}] - {} Using existing in-memory session",
                    http_request_id,
                    colored_session_id(session_id)
                );
                return Ok(session.clone());
            }
        }

        // Try to load from disk
        match SessionPersist::load_session(session_id) {
            Ok(session_data) => {
                info!(
                    "[{}] - {} Loading session from disk",
                    http_request_id,
                    colored_session_id(session_id)
                );

                // Restore the session with the saved trace
                let session = self
                    .create_session(
                        &http_request_id.to_string(),
                        session_id,
                        Some(agent_name),
                        false,                    // Loaded sessions are not ephemeral
                        Some(session_data.trace), // Initialize with saved trace
                    )
                    .await?;

                // Store in manager
                let mut sessions = self.sessions.lock().await;
                sessions.insert(session_id.to_string(), session.clone());

                Ok(session)
            }
            Err(e) => {
                error!("Failed to load session {} from disk: {}", session_id, e);
                Err(AgentError::ExecutionError(format!(
                    "Session not found: {}",
                    session_id
                )))
            }
        }
    }

    /// Create a new session with the given ID
    /// Returns error if session already exists
    pub async fn create_new_session(
        &self,
        http_request_id: &str,
        session_id: &str,
        agent_name: Option<String>,
        ephemeral: bool,
    ) -> Result<Arc<AgentSession>, AgentError> {
        // Check if ephemeral-only mode is enforced
        if self.ephemeral && !ephemeral {
            return Err(AgentError::ExecutionError(
                "Only Ephemeral session are authorized on this server".to_string(),
            ));
        }

        let mut sessions = self.sessions.lock().await;

        // Check if session already exists
        if sessions.contains_key(session_id) {
            return Err(AgentError::ExecutionError(format!(
                "Session already exists: {}",
                session_id
            )));
        }

        // Check max sessions limit (counts both ephemeral and non-ephemeral)
        if let Some(max) = self.max_sessions {
            if sessions.len() >= max {
                return Err(AgentError::ExecutionError(format!(
                    "Maximum number of sessions reached: {}",
                    max
                )));
            }
        }

        let session = self
            .create_session(
                &http_request_id.to_string(),
                session_id,
                agent_name,
                ephemeral,
                None,
            )
            .await?;

        // Store all sessions in hashmap (ephemeral sessions will be automatically cleaned up when agent terminates)
        sessions.insert(session_id.to_string(), session.clone());

        Ok(session)
    }

    /// Cancel a session (stop the agent)
    pub async fn cancel_session(
        &self,
        http_request_id: &String,
        session_id: &str,
    ) -> Result<(), AgentError> {
        if let Some(session) = self.sessions.lock().await.get(session_id) {
            session.cancel(http_request_id).await?;
        }
        Ok(())
    }

    /// Get the number of active sessions
    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use openai_dive::v1::resources::chat::{ChatMessageContent, Function, ToolCall};
    use shai_core::agent::{AgentEvent, Brain, ThinkerContext, ThinkerDecision, ToolBudgetRef};
    use shai_core::tools::{
        create_tool, AnyTool, BashToolConfig, FsOperationLog, TodoStorage, ToolResult,
    };
    use std::time::Duration;

    /// Brain that makes one tool call, then stops.
    struct OneCallBrain {
        call: Option<(String, serde_json::Value)>,
    }

    #[async_trait]
    impl Brain for OneCallBrain {
        async fn next_step(
            &mut self,
            _: ThinkerContext,
            _: ToolBudgetRef,
        ) -> Result<ThinkerDecision, AgentError> {
            let message = |content, tool_calls| ChatMessage::Assistant {
                content,
                reasoning: None,
                reasoning_content: None,
                tool_calls,
                name: None,
                audio: None,
                refusal: None,
            };
            Ok(match self.call.take() {
                Some((name, args)) => ThinkerDecision::agent_continue(message(
                    None,
                    Some(vec![ToolCall {
                        id: "call_1".to_string(),
                        r#type: "function".to_string(),
                        function: Function {
                            name,
                            arguments: args.to_string(),
                        },
                    }]),
                )),
                None => ThinkerDecision::agent_pause(message(
                    Some(ChatMessageContent::Text("done".to_string())),
                    None,
                )),
            })
        }
    }

    fn tool(name: &str) -> Box<dyn AnyTool> {
        create_tool(
            name,
            Arc::new(FsOperationLog::new()),
            Arc::new(TodoStorage::new()),
            &[],
            &BashToolConfig::default(),
        )
        .unwrap()
    }

    fn scratch_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("shai-http-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Run one tool call through a session agent wired like `create_session`:
    /// a controller and an event stream exist, but no client answers prompts.
    /// Returns the tool result and whether a permission prompt was sent.
    async fn run_session_tool(
        config: SessionManagerConfig,
        tool_name: &str,
        args: serde_json::Value,
    ) -> (ToolResult, bool) {
        let manager = SessionManager::new(config);
        let builder = AgentBuilder::with_brain(Box::new(OneCallBrain {
            call: Some((tool_name.to_string(), args)),
        }))
        .tools(vec![tool(tool_name)])
        .goal("go");
        let mut agent = manager.prepare_agent(builder, None).build();
        let controller = agent.controller();
        let mut events = agent.watch();
        let task = tokio::spawn(async move { agent.run().await });

        let mut prompted = false;
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match events.recv().await.expect("event stream closed") {
                    AgentEvent::PermissionRequired { .. } => prompted = true,
                    AgentEvent::ToolCallCompleted { result, .. } => break result,
                    _ => {}
                }
            }
        })
        .await
        .expect("session blocked instead of answering the tool call");

        drop(controller);
        task.abort();
        (result, prompted)
    }

    #[tokio::test]
    async fn session_denies_bash_by_default() {
        let dir = scratch_dir();
        let marker = dir.join("ran");
        let (result, prompted) = run_session_tool(
            SessionManagerConfig::default(),
            "bash",
            serde_json::json!({"command": format!("touch {}", marker.display())}),
        )
        .await;
        assert!(!prompted, "session sent a prompt no HTTP client can answer");
        assert!(result.is_error(), "{result:?}");
        let text = result.to_string();
        assert!(
            text.contains("permission denied") && text.contains("--yes"),
            "{text}"
        );
        assert!(!marker.exists(), "bash ran without --yes");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn session_denies_write_by_default() {
        let dir = scratch_dir();
        let target = dir.join("out.txt");
        let (result, prompted) = run_session_tool(
            SessionManagerConfig::default(),
            "write",
            serde_json::json!({"files": [{"path": target.to_string_lossy(), "content": "x"}]}),
        )
        .await;
        assert!(!prompted);
        assert!(result.is_error(), "{result:?}");
        assert!(!target.exists(), "write ran without --yes");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn session_allows_read_only_tools_by_default() {
        let dir = scratch_dir();
        let file = dir.join("notes.txt");
        std::fs::write(&file, "session-read-ok").unwrap();
        let (result, prompted) = run_session_tool(
            SessionManagerConfig::default(),
            "read",
            serde_json::json!({"files": [{"path": file.to_string_lossy()}]}),
        )
        .await;
        assert!(!prompted);
        assert!(result.is_success(), "{result:?}");
        assert!(result.to_string().contains("session-read-ok"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn session_allow_all_tools_runs_bash() {
        let dir = scratch_dir();
        let marker = dir.join("ran");
        let config = SessionManagerConfig {
            allow_all_tools: true,
            ..SessionManagerConfig::default()
        };
        let (result, prompted) = run_session_tool(
            config,
            "bash",
            serde_json::json!({"command": format!("touch {}", marker.display())}),
        )
        .await;
        assert!(!prompted);
        assert!(result.is_success(), "{result:?}");
        assert!(marker.exists(), "bash did not run with --yes");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sessions_keep_the_startup_config_snapshot() {
        let snapshot: ShaiConfig = serde_json::from_str(
            r#"{"providers":[{"provider":"openai","env_vars":{"OPENAI_API_KEY":"k"},"model":"snapshot-model","tool_method":"FunctionCall"}],"selected_provider":0}"#,
        )
        .unwrap();
        let manager = SessionManager::new(SessionManagerConfig {
            primary: Some(Arc::new(snapshot)),
            ..SessionManagerConfig::default()
        });
        assert_eq!(
            manager.primary.as_ref().unwrap().providers[0].model,
            "snapshot-model"
        );
        // create_session passes this snapshot to AgentBuilder::create_with_primary;
        // a later change to the auth file is not reread.
        assert!(manager.primary.is_some());
    }

    fn snapshot_with_key(key: &str) -> ShaiConfig {
        serde_json::from_str(&format!(
            r#"{{"providers":[{{"provider":"openai","env_vars":{{"OPENAI_API_KEY":"{key}"}},"model":"snapshot-model","tool_method":"FunctionCall"}}],"selected_provider":0}}"#
        ))
        .unwrap()
    }

    #[test]
    fn debug_does_not_contain_the_auth_config_key() {
        let config = SessionManagerConfig {
            primary: Some(Arc::new(snapshot_with_key("sk-test-do-not-leak"))),
            ..SessionManagerConfig::default()
        };
        let debug = format!("{config:?}");
        assert!(
            !debug.contains("sk-test-do-not-leak"),
            "Debug leaked the key: {debug}"
        );
    }

    #[tokio::test]
    async fn create_session_uses_the_startup_snapshot_when_the_auth_file_is_broken() {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _guard = LOCK.lock().await;

        let dir = scratch_dir();
        let shai = dir.join("config").join("shai");
        std::fs::create_dir_all(&shai).unwrap();
        std::fs::write(shai.join("auth.config.json"), "{ this is not json").unwrap();

        fn take_var(key: &str) -> Option<String> {
            std::env::var(key).ok()
        }
        fn put_var(key: &str, previous: Option<String>) {
            match previous {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }

        let previous = [
            "XDG_CONFIG_HOME",
            "HOME",
            "SHAI_MODEL",
            "SHAI_SESSION_PERSIST_ENABLE",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "OPENAI_API_KEY",
        ]
        .map(take_var);
        std::env::set_var("XDG_CONFIG_HOME", dir.join("config"));
        std::env::set_var("HOME", dir.join("home"));
        std::env::set_var("SHAI_MODEL", "snapshot-model");
        std::env::set_var("SHAI_SESSION_PERSIST_ENABLE", "false");
        std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:9");
        std::env::set_var("HTTP_PROXY", "http://127.0.0.1:9");

        let restore = || {
            for (key, value) in [
                "XDG_CONFIG_HOME",
                "HOME",
                "SHAI_MODEL",
                "SHAI_SESSION_PERSIST_ENABLE",
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "OPENAI_API_KEY",
            ]
            .into_iter()
            .zip(previous)
            {
                put_var(key, value);
            }
        };

        let without = SessionManager::new(SessionManagerConfig::default());
        let without_result = without
            .create_new_session("req-1", "snapshot-session-missing", None, true)
            .await;
        let without_error = match without_result {
            Ok(_) => {
                restore();
                panic!("a broken auth file and no snapshot must not start a session");
            }
            Err(error) => error.to_string(),
        };
        assert!(
            without_error.contains("could not be loaded")
                || without_error.to_lowercase().contains("config"),
            "{without_error}"
        );

        let manager = SessionManager::new(SessionManagerConfig {
            primary: Some(Arc::new(snapshot_with_key("k"))),
            ..SessionManagerConfig::default()
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            manager.create_new_session("req-2", "snapshot-session-ok", None, true),
        )
        .await;
        match result {
            Err(_) => {
                restore();
                panic!("create_new_session hung; the snapshot path must not call the network");
            }
            Ok(Err(error)) => {
                restore();
                panic!("create_new_session should use the snapshot, not the broken file: {error}");
            }
            Ok(Ok(session)) => {
                let _ = manager
                    .cancel_session(&"req-2".to_string(), "snapshot-session-ok")
                    .await;
                assert_eq!(session.session_id, "snapshot-session-ok");
            }
        }
        restore();
        let _ = std::fs::remove_dir_all(dir);
    }
}
