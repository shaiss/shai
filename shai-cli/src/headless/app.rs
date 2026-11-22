use std::sync::Arc;

use crate::headless::tools::ToolConfig;
use crate::session_options::{SessionOptions, SessionStartError};

use super::tools::{list_all_tools, restrict_toolbox, ToolName};
use openai_dive::v1::resources::chat::{ChatMessage, ChatMessageContent};
use shai_core::agent::{
    Agent, AgentBuilder, AgentCore, AgentError, AgentResult, Brain, LoggingConfig,
    StdoutEventManager,
};
use shai_core::config::agent::AgentConfig;
use shai_core::config::config::ShaiConfig;
use shai_core::runners::coder::coder::CoderBrain;
use shai_core::runners::searcher::searcher::SearcherBrain;
use shai_llm::LlmClient;

/// Finish a headless agent. Nobody can answer a permission prompt here, so
/// read-only tools run and every other tool is denied immediately, unless
/// `yes` (`--yes`) grants full access.
fn build_headless_agent(
    builder: AgentBuilder,
    initial_trace: Vec<ChatMessage>,
    yes: bool,
) -> AgentCore {
    builder
        .with_traces(initial_trace)
        .headless_permissions(yes)
        .build()
}

pub enum AgentKind {
    Coder,
    #[allow(dead_code)] // TODO: reserved for future "searcher" agent mode
    Searcher,
}

pub struct AppHeadless {
    kind: AgentKind,
    temperature: Option<f32>,
    session_options: SessionOptions,
}

impl AppHeadless {
    pub fn new() -> Self {
        Self {
            kind: AgentKind::Coder,
            temperature: None,
            session_options: SessionOptions::default(),
        }
    }

    pub fn set_session_options(&mut self, session_options: SessionOptions) {
        self.session_options = session_options;
    }

    pub fn set_temperature(&mut self, temperature: f32) {
        self.temperature = Some(temperature);
    }

    pub async fn run(
        &self,
        initial_trace: Vec<ChatMessage>,
        tools: Option<String>,
        remove: Option<String>,
        trace: bool,
        agent_name: Option<String>,
        yes: bool,
    ) -> Result<(), SessionStartError> {
        // Configure internal debug logging to file
        /*
        let _ = LoggingConfig::default()
            .level("debug")
            .file_path("agent_debug.log")
            .init();
        */

        // Validate that we have some input
        if initial_trace.is_empty() {
            eprintln!("Error: Please provide a prompt for the coder agent");
            eprintln!(
                "Usage: shai \"your prompt here\" or using pipe echo \"your prompt here\" | shai"
            );
            return Ok(());
        }

        let mut agent = if let Some(agent_name) = agent_name {
            // Load the agent config directly so a PrimaryConfigError (for example
            // an omitted `llm_provider` with `anonymous_fallback: deny` and no
            // primary config) stays typed and exits 2 (#67).
            let config = AgentConfig::load_with_primary_result(
                &agent_name,
                self.session_options.startup_primary_ref(),
            )
            .map_err(|e| SessionStartError::from_start(Some(&agent_name), e))?;
            let mut builder = AgentBuilder::from_config(config)
                .await
                .map_err(|e| SessionStartError::from_start(Some(&agent_name), e.into()))?;

            // --tools / --remove narrow the agent's own tools, never widen them
            if tools.is_some() || remove.is_some() {
                let (toolbox, missing) = restrict_toolbox(
                    std::mem::take(&mut builder.available_tools),
                    tools.as_deref(),
                    remove.as_deref(),
                )
                .map_err(|e| SessionStartError::other(e.to_string()))?;
                for tool in missing {
                    eprintln!(
                        "Warning: agent '{}' does not provide tool '{}', ignoring it",
                        agent_name, tool
                    );
                }
                builder.available_tools = toolbox;
            }

            build_headless_agent(builder, initial_trace, yes)
        } else {
            // Use default agent with provided tools
            // One load of the config, which also builds the primary model:
            // a file that breaks after the start-up check stops the run
            // instead of falling back to the built-in default.
            let config = self.session_options.startup_primary_config()?;
            let (llm_client, model) = config
                .get_llm_from_config()
                .await
                .map_err(|e| SessionStartError::other(e.to_string()))?;
            eprintln!(
                "\x1b[2m░ {} on {}\x1b[0m",
                model,
                llm_client.provider().name()
            );

            // Handle tool selection if needed
            if tools.is_some() || remove.is_some() {
                // Need custom tool configuration
                let tools = ToolConfig::from_args(tools.as_deref(), remove.as_deref())
                    .map_err(|e| SessionStartError::other(e.to_string()))?;

                let toolbox = tools.build_toolbox();
                let brain: Box<dyn Brain> = match self.kind {
                    AgentKind::Coder => Box::new(CoderBrain::new(Arc::new(llm_client), model)),
                    AgentKind::Searcher => {
                        Box::new(SearcherBrain::new(Arc::new(llm_client), model))
                    }
                };

                build_headless_agent(
                    AgentBuilder::with_brain(brain).tools(toolbox),
                    initial_trace,
                    yes,
                )
            } else {
                // Use default agent, on the model built above
                build_headless_agent(
                    AgentBuilder::default_with_llm(Arc::new(llm_client), model),
                    initial_trace,
                    yes,
                )
            }
        };

        if let Some(temp) = self.temperature {
            *agent.temperature.write().await = temp;
        }

        // One line on stderr when a handoff is armed, or when one was asked
        // for and this agent cannot take it. The switch itself is announced,
        // also in one line, by the event handler below.
        let mut session_options = self.session_options.clone();
        if let Some(notice) = session_options.arm_headless(&mut agent, yes) {
            eprintln!("{}", shai_core::agent::output::notice_line(&notice));
        }

        let result = agent
            .with_event_handler(StdoutEventManager::new())
            .run()
            .await;

        finish_headless_run(result, trace).map_err(|e| SessionStartError::other(e.to_string()))
    }
}

/// Print the headless result and return an error when the agent did not
/// succeed, so the process exits non-zero. Exit 0 used to be returned
/// after `Agent failed: …` as well.
fn finish_headless_run(
    result: Result<AgentResult, AgentError>,
    trace: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Ok(AgentResult {
            success,
            message: _,
            trace: agent_trace,
        }) => {
            if trace {
                println!("{}", serde_json::to_string_pretty(&agent_trace)?);
            } else if let Some(message) = agent_trace.last() {
                match message {
                    ChatMessage::Assistant {
                        content: Some(ChatMessageContent::Text(content)),
                        ..
                    } => {
                        println!("{}", content);
                    }
                    ChatMessage::Tool { content, .. } => {
                        println!("{}", content);
                    }
                    _ => {}
                }
            }
            if !success {
                eprintln!("Agent failed");
                return Err("agent did not succeed".into());
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("Agent failed: {}", e);
            Err(e.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use openai_dive::v1::resources::chat::{Function, ToolCall};
    use shai_core::agent::{AgentEvent, ThinkerContext, ThinkerDecision, ToolBudgetRef};
    use shai_core::tools::{create_tool, AnyTool, BashToolConfig, FsOperationLog, TodoStorage};
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

    /// Run one tool call through a headless agent, wired like `run()`:
    /// an event printer is attached but nobody answers prompts.
    /// Returns the tool message the model got back and whether a prompt was sent.
    async fn run_headless(tool_name: &str, args: serde_json::Value, yes: bool) -> (String, bool) {
        let builder = AgentBuilder::with_brain(Box::new(OneCallBrain {
            call: Some((tool_name.to_string(), args)),
        }))
        .tools(vec![tool(tool_name)]);
        let trace = vec![ChatMessage::User {
            content: ChatMessageContent::Text("go".to_string()),
            name: None,
        }];
        let prompted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = prompted.clone();
        let mut agent = build_headless_agent(builder, trace, yes).on_event(move |event| {
            if matches!(event, AgentEvent::PermissionRequired { .. }) {
                seen.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let result = tokio::time::timeout(Duration::from_secs(10), agent.run())
            .await
            .expect("headless run blocked instead of finishing")
            .expect("headless run failed");
        let tool_output = result
            .trace
            .iter()
            .find_map(|m| match m {
                ChatMessage::Tool {
                    content: ChatMessageContent::Text(text),
                    ..
                } => Some(text.clone()),
                _ => None,
            })
            .expect("no tool result in trace");
        (
            tool_output,
            prompted.load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    fn assert_denied(output: &str, prompted: bool) {
        assert!(
            !prompted,
            "headless sent a permission prompt nobody can answer"
        );
        assert!(
            output.contains("permission denied") && output.contains("--yes"),
            "unclear denial: {output}"
        );
    }

    #[tokio::test]
    async fn headless_denies_bash_without_yes() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let (output, prompted) = run_headless(
            "bash",
            serde_json::json!({"command": format!("touch {}", marker.display())}),
            false,
        )
        .await;
        assert_denied(&output, prompted);
        assert!(!marker.exists(), "bash ran without --yes");
    }

    #[tokio::test]
    async fn headless_denies_write_without_yes() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.txt");
        let (output, prompted) = run_headless(
            "write",
            serde_json::json!({"files": [{"path": target.to_string_lossy(), "content": "x"}]}),
            false,
        )
        .await;
        assert_denied(&output, prompted);
        assert!(!target.exists(), "write ran without --yes");
    }

    #[tokio::test]
    async fn headless_allows_read_only_tools_without_yes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("notes.txt");
        std::fs::write(&file, "headless-read-ok").unwrap();
        let (output, prompted) = run_headless(
            "read",
            serde_json::json!({"files": [{"path": file.to_string_lossy()}]}),
            false,
        )
        .await;
        assert!(!prompted);
        assert!(output.contains("headless-read-ok"), "{output}");
    }

    #[tokio::test]
    async fn headless_yes_allows_bash_and_write() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let (_, prompted) = run_headless(
            "bash",
            serde_json::json!({"command": format!("touch {}", marker.display())}),
            true,
        )
        .await;
        assert!(!prompted);
        assert!(marker.exists(), "bash did not run with --yes");

        let target = dir.path().join("out.txt");
        let (_, prompted) = run_headless(
            "write",
            serde_json::json!({"files": [{"path": target.to_string_lossy(), "content": "x"}]}),
            true,
        )
        .await;
        assert!(!prompted);
        assert!(target.exists(), "write did not run with --yes");
    }

    #[test]
    fn finish_headless_run_errors_when_the_agent_does_not_succeed() {
        let failed = AgentResult {
            success: false,
            message: "Agent completed".to_string(),
            trace: vec![],
        };
        let error =
            finish_headless_run(Ok(failed), false).expect_err("success: false must not exit 0");
        assert!(error.to_string().contains("did not succeed"), "{error}");

        let error = finish_headless_run(Err(AgentError::ExecutionError("boom".into())), false)
            .expect_err("Agent failed must not exit 0");
        assert!(error.to_string().contains("boom"), "{error}");

        let ok = AgentResult {
            success: true,
            message: "Agent completed".to_string(),
            trace: vec![],
        };
        finish_headless_run(Ok(ok), false).expect("a successful run still exits 0");
    }
}
