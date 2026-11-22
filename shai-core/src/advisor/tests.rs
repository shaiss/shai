// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

//! The advisor exercised through the real agent loop.
//!
//! Two scripted models: one drives the agent, the other plays the advisor.
//! Each records every request it receives, so the tests can check what the
//! advisor was shown and offered, and what reached the agent afterwards.

use super::review::ADVISOR_PROMPT;
use super::*;
use crate::agent::actions::advisor::ADVISOR_TASK;
use crate::agent::scripted_llm::{call, calls, text, Reply, Script, Served};
use crate::agent::{
    Agent, AgentBuilder, AgentEvent, AgentResult, InternalAgentState, PublicAgentState,
};
use crate::config::config::ProviderConfig;
use crate::runners::coder::CoderBrain;
use crate::tools::{FsOperationLog, TodoStorage};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use tempfile::TempDir;

const MAIN: &str = "main";
const ADVISOR: &str = "advisor";
const ADVISOR_MODEL: &str = "advisor-model";
/// A credential of a configured provider, which must never reach the advisor.
const PROVIDER_KEY: &str = "pk-live-0123456789abcdefghij";
/// The token of a configured MCP server: no shape or name gives it away.
const MCP_TOKEN: &str = "mcp-access-9f8e7d6c5b4a";
/// A value of the environment under a name that no list of names has.
const ENV_SECRET: &str = "runner-says-open-sesame-42";

fn config_with_a_secret() -> ShaiConfig {
    let mut config = ShaiConfig::default();
    config.providers.push(ProviderConfig {
        provider: "openai".to_string(),
        env_vars: HashMap::from([("OPENAI_API_KEY".to_string(), PROVIDER_KEY.to_string())]),
        model: "gpt-4o".to_string(),
        tool_method: shai_llm::ToolCallMethod::FunctionCall,
    });
    config.mcp_configs.insert(
        "tracker".to_string(),
        crate::tools::mcp::McpConfig::Http {
            url: "https://mcp.example.com".to_string(),
            auth: Some(crate::tools::mcp::mcp_config::OAuthToken {
                access_token: MCP_TOKEN.to_string(),
                expires_at: None,
            }),
        },
    );
    config
}

/// The environment the advisor of these tests is told about, in place of the
/// one the tests happen to run in.
fn environment() -> Vec<(String, String)> {
    [
        ("CI_RUNNER_GREETING", ENV_SECRET),
        ("NODE_ENV", "production"),
        ("PWD", "/srv/work/project"),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value.to_string()))
    .collect()
}

/// An advisor that knows nothing of the machine the tests run on.
fn advisor_on(script: &Script, dir: &Path, limits: AdvisorLimits, config: &ShaiConfig) -> Advisor {
    Advisor::with_environment(
        BoundModel::new(script.client(ADVISOR), ADVISOR_MODEL),
        dir,
        limits,
        config,
        environment(),
    )
    .expect("advisor")
}

fn limits(max_calls: u32, cooldown_turns: u32) -> AdvisorLimits {
    AdvisorLimits {
        max_calls,
        cooldown_turns,
    }
}

fn says(verdict: &str) -> Reply {
    Reply::Message(text(verdict))
}

fn ls(path: &Path) -> ChatMessage {
    call("ls", json!({"directory": path.to_string_lossy()}))
}

/// `count` steps that each list `path`, then a final answer.
fn steps(path: &Path, count: usize) -> Vec<ChatMessage> {
    let mut replies: Vec<ChatMessage> = (0..count).map(|_| ls(path)).collect();
    replies.push(text("done"));
    replies
}

struct Outcome {
    main: Script,
    advisor: Script,
    handle: Option<Advisor>,
    events: Vec<AgentEvent>,
    todos: std::sync::Arc<TodoStorage>,
    result: AgentResult,
}

impl Outcome {
    fn notes(&self) -> Vec<(Severity, String)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                AgentEvent::AdvisorNote { severity, note } => Some((*severity, note.clone())),
                _ => None,
            })
            .collect()
    }

    fn failures(&self) -> Vec<bool> {
        self.events
            .iter()
            .filter_map(|event| match event {
                AgentEvent::AdvisorFailed { disabled, .. } => Some(*disabled),
                _ => None,
            })
            .collect()
    }

    /// How many times the agent started waiting for the advisor.
    fn advisor_phases(&self) -> usize {
        self.events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    AgentEvent::StatusChanged {
                        new_status: PublicAgentState::Processing { task_name, .. },
                        ..
                    } if task_name == ADVISOR_TASK
                )
            })
            .count()
    }
}

/// The conversation a request carried, as one string. The system prompt is
/// left out: the agent's is assembled from the repository the tests run in,
/// and the advisor's is compared with its fixed text where that matters.
fn all_text(request: &Served) -> String {
    request
        .messages
        .iter()
        .filter(|message| !matches!(message, ChatMessage::System { .. }))
        .map(|message| serde_json::to_string(message).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every message in a request, including system prompts. Used when asserting
/// that a note or a secret is absent from what was sent.
fn all_payloads(request: &Served) -> String {
    request
        .messages
        .iter()
        .map(|message| serde_json::to_string(message).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

fn tool_results(request: &Served) -> Vec<String> {
    request
        .messages
        .iter()
        .filter_map(|message| match message {
            ChatMessage::Tool {
                content: ChatMessageContent::Text(text),
                ..
            } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

/// Run the real agent loop on `main_replies`, with an advisor answering
/// `advisor_replies` when `advisor_limits` is given.
async fn run(
    dir: &Path,
    main_replies: Vec<ChatMessage>,
    advisor_replies: Vec<Reply>,
    advisor_limits: Option<AdvisorLimits>,
) -> Outcome {
    run_with(dir, main_replies, advisor_replies, advisor_limits, true).await
}

async fn run_with(
    dir: &Path,
    main_replies: Vec<ChatMessage>,
    advisor_replies: Vec<Reply>,
    advisor_limits: Option<AdvisorLimits>,
    sudo: bool,
) -> Outcome {
    let main = Script::new(main_replies);
    let advisor = Script::with_replies(advisor_replies);
    let (tools, todos) =
        AgentBuilder::create_default_tools(std::sync::Arc::new(FsOperationLog::new()));
    let brain = CoderBrain::new(main.client(MAIN), "main-model".to_string());

    let mut builder = AgentBuilder::with_brain(Box::new(brain))
        .tools(tools)
        .set_todo_storage(todos.clone())
        .goal("tidy the project");
    if sudo {
        builder = builder.sudo();
    }
    let handle = advisor_limits
        .map(|advisor_limits| advisor_on(&advisor, dir, advisor_limits, &config_with_a_secret()));
    let mut agent = builder.build();
    if let Some(handle) = &handle {
        agent
            .set_advisor(handle.clone())
            .expect("the coder brain takes advisor notes");
    }
    assert_eq!(agent.has_advisor(), handle.is_some());

    // Without sudo, a subscriber would make the agent wait for a permission
    // answer; with none, a write is denied outright.
    let mut events_rx = sudo.then(|| agent.watch());
    let result = tokio::time::timeout(Duration::from_secs(60), agent.run())
        .await
        .expect("the agent run should finish")
        .expect("the agent run should succeed");

    let mut events = Vec::new();
    if let Some(rx) = events_rx.as_mut() {
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
    }
    Outcome {
        main,
        advisor,
        handle,
        events,
        todos,
        result,
    }
}

#[tokio::test]
async fn a_session_without_an_advisor_never_calls_one() {
    let dir = TempDir::new().unwrap();
    let outcome = run(
        dir.path(),
        steps(dir.path(), 3),
        vec![says("blocker: x")],
        None,
    )
    .await;

    assert_eq!(outcome.main.served().len(), 4);
    assert!(outcome.advisor.served().is_empty());
    assert!(outcome.notes().is_empty());
}

#[tokio::test]
async fn a_note_reaches_the_agent_at_its_next_step_and_nowhere_else() {
    let dir = TempDir::new().unwrap();
    let outcome = run(
        dir.path(),
        steps(dir.path(), 2),
        vec![says("concern: the tests were not run")],
        Some(limits(10, 5)),
    )
    .await;

    // One review, after the first step; the cooldown covers the second.
    assert_eq!(outcome.advisor.served().len(), 1);
    assert_eq!(
        outcome.notes(),
        [(Severity::Concern, "the tests were not run".to_string())]
    );

    let main = outcome.main.served();
    assert_eq!(main.len(), 3);
    // Before the review there is nothing to show.
    assert!(!all_payloads(&main[0]).contains("[advisor note"));
    assert!(!all_text(&main[0]).contains("advisor note"));

    // The next request carries the note, at the end of the tool result of
    // the step that was reviewed, inside its fixed frame.
    let results = tool_results(&main[1]);
    assert_eq!(results.len(), 1);
    let expected = AdvisorNote {
        severity: Severity::Concern,
        text: "the tests were not run".to_string(),
    }
    .for_agent();
    assert!(results[0].ends_with(&expected), "{}", results[0]);
    assert!(results[0].len() > expected.len(), "the tool output is kept");
    // It is in a tool result, not in a message of its own.
    assert_eq!(main[1].messages.len(), main[0].messages.len() + 2);

    // It is shown once: the request after that does not have it...
    assert!(!all_payloads(&main[2]).contains("[advisor note"));
    assert!(!all_text(&main[2]).contains("advisor note"));
    // ...and it never enters the stored conversation.
    let stored = serde_json::to_string(&outcome.result.trace).unwrap();
    assert!(!stored.contains("advisor note"), "{stored}");
    assert!(!stored.contains("the tests were not run"), "{stored}");

    // The user is told when the note is produced: after the first reply and
    // before the second.
    let at = outcome
        .events
        .iter()
        .position(|event| matches!(event, AgentEvent::AdvisorNote { .. }))
        .unwrap();
    let replies_before = outcome.events[..at]
        .iter()
        .filter(|event| matches!(event, AgentEvent::BrainResult { .. }))
        .count();
    assert_eq!(replies_before, 1);
}

#[tokio::test]
async fn nothing_to_say_means_nothing_is_shown() {
    let dir = TempDir::new().unwrap();
    for verdict in ["NONE", "Looks fine to me.", "", "warning: not a severity"] {
        let outcome = run(
            dir.path(),
            steps(dir.path(), 2),
            vec![says(verdict)],
            Some(limits(10, 5)),
        )
        .await;

        assert_eq!(outcome.advisor.served().len(), 1, "{verdict:?}");
        assert!(outcome.notes().is_empty(), "{verdict:?}");
        assert!(outcome.failures().is_empty(), "{verdict:?}");
        for request in outcome.main.served() {
            assert!(!all_text(&request).contains("advisor note"), "{verdict:?}");
        }
    }
}

#[tokio::test]
async fn reviews_follow_the_cooldown() {
    let dir = TempDir::new().unwrap();
    let outcome = run(
        dir.path(),
        steps(dir.path(), 7),
        (0..7).map(|_| says("NONE")).collect(),
        Some(limits(10, 2)),
    )
    .await;

    // Steps 1, 4 and 7 are reviewed; two steps are skipped after each review.
    let reviews = outcome.advisor.served();
    assert_eq!(reviews.len(), 3);
    assert_eq!(outcome.handle.as_ref().unwrap().calls_made(), 3);

    // Each review is shown the steps since the previous one, no more.
    let steps_shown: Vec<usize> = reviews
        .iter()
        .map(|review| all_text(review).matches("Result of ls").count())
        .collect();
    assert_eq!(steps_shown, [1, 3, 3]);
    // And the user's request, for context.
    assert!(all_text(&reviews[2]).contains("tidy the project"));
}

#[tokio::test]
async fn the_session_cap_bounds_the_number_of_reviews() {
    let dir = TempDir::new().unwrap();
    let outcome = run(
        dir.path(),
        steps(dir.path(), 9),
        (0..9).map(|_| says("nit: again")).collect(),
        Some(limits(2, 1)),
    )
    .await;

    // Every other step would be reviewed; the cap stops it at two.
    assert_eq!(outcome.advisor.served().len(), 2);
    assert_eq!(outcome.notes().len(), 2);
    let advisor = outcome.handle.as_ref().unwrap();
    assert_eq!(advisor.calls_made(), 2);
    assert_eq!(advisor.limits(), limits(2, 1));
    // The agent waited for the advisor twice and never again.
    assert_eq!(outcome.advisor_phases(), 2);
    // The agent itself ran to the end.
    assert_eq!(outcome.main.served().len(), 10);
}

#[tokio::test]
async fn a_session_out_of_reviews_does_not_look_at_the_conversation() {
    let dir = TempDir::new().unwrap();
    let advisor_script = Script::new(vec![]);
    let main = Script::new(vec![]);
    let listing = ls(dir.path());
    let listed = ChatMessage::Tool {
        tool_call_id: match &listing {
            ChatMessage::Assistant {
                tool_calls: Some(calls),
                ..
            } => calls[0].id.clone(),
            _ => unreachable!("a tool call"),
        },
        content: ChatMessageContent::Text("a.txt".to_string()),
    };
    let step = vec![user_message("tidy the project"), listing, listed];

    // With a review left, a completed step like this one is reviewed.
    let advisor = advisor_on(
        &advisor_script,
        dir.path(),
        limits(2, 0),
        &ShaiConfig::default(),
    );
    assert!(advisor.take_call());
    let mut agent = agent_with(&main, &advisor);
    agent.tool_ctx.trace.write().await.extend(step.clone());
    assert!(agent.start_advisor_review().await);
    assert_eq!(advisor.calls_made(), 2);
    assert!(matches!(
        &agent.state,
        InternalAgentState::Processing { task_name, .. } if task_name == ADVISOR_TASK
    ));

    // With none left, nothing is done for one. Nobody can read the
    // conversation while it is held for writing: describing its steps for a
    // review that cannot happen would wait here until the time is up.
    let mut agent = agent_with(&main, &advisor);
    agent.tool_ctx.trace.write().await.extend(step);
    let mut events = agent.watch();
    let conversation = agent.tool_ctx.trace.clone();
    let held = conversation.write().await;
    for _ in 0..5 {
        let started = tokio::time::timeout(Duration::from_secs(5), agent.start_advisor_review())
            .await
            .expect("the conversation was read for a review that cannot happen");
        assert!(!started);
    }
    drop(held);
    assert_eq!(advisor.calls_made(), 2);
    assert!(matches!(agent.state, InternalAgentState::Starting));
    assert!(events.try_recv().is_err(), "nothing is announced");
    assert!(!advisor.is_off());
}

#[tokio::test]
async fn the_cap_is_shared_by_every_agent_of_the_session() {
    let dir = TempDir::new().unwrap();
    let advisor_script = Script::new((0..9).map(|_| text("NONE")).collect());
    let advisor = advisor_on(
        &advisor_script,
        dir.path(),
        limits(3, 1),
        &ShaiConfig::default(),
    );

    // Two agents in a row, as when a front-end rebuilds its agent.
    for _ in 0..2 {
        let main = Script::new(steps(dir.path(), 5));
        let (tools, _) =
            AgentBuilder::create_default_tools(std::sync::Arc::new(FsOperationLog::new()));
        let brain = CoderBrain::new(main.client(MAIN), "main-model".to_string());
        let mut agent = AgentBuilder::with_brain(Box::new(brain))
            .tools(tools)
            .goal("tidy the project")
            .sudo()
            .build();
        agent.set_advisor(advisor.clone()).unwrap();
        tokio::time::timeout(Duration::from_secs(60), agent.run())
            .await
            .unwrap()
            .unwrap();
    }

    // Three reviews each would be due; three in total are allowed.
    assert_eq!(advisor_script.served().len(), 3);
    assert_eq!(advisor.calls_made(), 3);
}

/// The advisor asks for every tool that could change something or reach the
/// network. None of them exists for it.
#[tokio::test]
async fn the_advisor_cannot_call_bash_write_edit_or_fetch() {
    let dir = TempDir::new().unwrap();
    let by_bash = dir.path().join("by-bash.txt");
    let by_write = dir.path().join("by-write.txt");
    let existing = dir.path().join("existing.txt");
    std::fs::write(&existing, "untouched").unwrap();

    // A request to this server would mean `fetch` ran.
    let mut server = mockito::Server::new_async().await;
    let fetched = server
        .mock("GET", mockito::Matcher::Any)
        .expect(0)
        .create_async()
        .await;

    let forbidden = calls(&[
        (
            "bash",
            json!({"command": format!("touch {}", by_bash.display())}),
        ),
        (
            "write",
            json!({"files": [{"path": by_write.to_string_lossy(), "content": "pwned"}]}),
        ),
        (
            "edit",
            json!({"files": [{"path": existing.to_string_lossy(), "edits": [
                {"old_string": "untouched", "new_string": "pwned"}
            ]}]}),
        ),
        ("fetch", json!({"url": server.url()})),
        (
            "todo_write",
            json!({"todos": [{"content": "injected", "status": "pending"}]}),
        ),
        (
            "memory_write",
            json!({"scope": "project", "content": "injected"}),
        ),
        // A spelling the main agent's dispatcher would resolve to a tool.
        ("functions.bash", json!({"command": "id"})),
    ]);
    let outcome = run(
        dir.path(),
        steps(dir.path(), 1),
        vec![Reply::Message(forbidden), says("nit: nothing else to try")],
        Some(limits(10, 5)),
    )
    .await;

    let reviews = outcome.advisor.served();
    assert_eq!(reviews.len(), 2);
    // Only the four read-only tools are ever on offer.
    for review in &reviews {
        assert_eq!(review.tools, ADVISOR_TOOL_ALLOWLIST);
    }

    // Every call was answered with a refusal, and none of them ran.
    let refusals = tool_results(&reviews[1]);
    assert_eq!(refusals.len(), 7);
    for refusal in &refusals {
        assert!(
            refusal.starts_with("error: there is no tool named"),
            "{refusal}"
        );
        assert!(refusal.ends_with("read, ls, find, grep."), "{refusal}");
    }
    assert!(!by_bash.exists());
    assert!(!by_write.exists());
    assert_eq!(std::fs::read_to_string(&existing).unwrap(), "untouched");
    fetched.assert_async().await;
    assert!(outcome.todos.get_all().await.is_empty());

    // The review still ends the only way it can: with a note.
    assert_eq!(
        outcome.notes(),
        [(Severity::Nit, "nothing else to try".to_string())]
    );
}

#[tokio::test]
async fn the_advisor_reads_inside_the_working_directory_only() {
    let tmp = TempDir::new().unwrap();
    let work = tmp.path().join("work");
    std::fs::create_dir_all(work.join("src")).unwrap();
    std::fs::create_dir_all(work.join(".shai/sessions")).unwrap();
    std::fs::write(work.join("src/lib.rs"), "pub fn inside() {}\n").unwrap();
    std::fs::write(work.join(".env"), "TOKEN=dotenv-value-123456\n").unwrap();
    std::fs::write(work.join(".shai/sessions/s.json"), "transcript-text").unwrap();
    std::fs::write(tmp.path().join("outside.txt"), "outside-text\n").unwrap();
    let outside = tmp.path().join("outside.txt");

    let probes = calls(&[
        ("read", json!({"path": "src/lib.rs"})),
        ("read", json!({"path": "../outside.txt"})),
        ("read", json!({"path": outside.to_string_lossy()})),
        ("read", json!({"path": ".env"})),
        ("read", json!({"path": ".shai/sessions/s.json"})),
        ("grep", json!({"pattern": "text|value", "path": ".."})),
        ("grep", json!({"pattern": "text|value|inside"})),
        ("find", json!({"pattern": "."})),
    ]);
    let outcome = run(
        &work,
        steps(&work, 1),
        vec![Reply::Message(probes), says("NONE")],
        Some(limits(10, 5)),
    )
    .await;

    let results = tool_results(&outcome.advisor.served()[1]);
    assert_eq!(results.len(), 8);
    assert!(results[0].contains("pub fn inside() {}"), "{}", results[0]);
    for refused in &results[1..6] {
        assert!(refused.starts_with("error:"), "{refused}");
    }
    // Searches cover the tree and nothing but the tree, minus what is off
    // limits inside it.
    // They say what they left out, so that "not found" is not read as "not
    // there": here the `.env` file and the `.shai` directory.
    let skipped = "\n[2 entries were skipped because they may hold credentials or internal state]";
    assert_eq!(
        results[6],
        format!("src/lib.rs:1: pub fn inside() {{}}{skipped}")
    );
    assert_eq!(results[7], format!("src/lib.rs{skipped}"));

    let seen = all_text(&outcome.advisor.served()[1]);
    for hidden in ["outside-text", "dotenv-value-123456", "transcript-text"] {
        assert!(!seen.contains(hidden), "{hidden} reached the advisor");
    }
}

#[tokio::test]
async fn secrets_and_the_environment_are_kept_out_of_what_the_advisor_is_sent() {
    let dir = TempDir::new().unwrap();
    let notes = dir.path().join("notes.md");
    let leaky = format!(
        "deploy with key {PROVIDER_KEY}\nDB_PASSWORD=correct-horse-battery\nAuthorization: Bearer abcdefghijklmnopqrstuvwx\nthe runner said {ENV_SECRET}\ntracker access {MCP_TOKEN}\nbuilt for production in /srv/work/project\n"
    );
    // The secret passes through the agent's own conversation twice: in the
    // arguments of its tool call, and in what the advisor then reads.
    let main_replies = vec![
        call(
            "write",
            json!({"files": [{"path": notes.to_string_lossy(), "content": leaky}]}),
        ),
        text("done"),
    ];
    let outcome = run(
        dir.path(),
        main_replies,
        vec![
            Reply::Message(call("read", json!({"path": "notes.md"}))),
            says(&format!("concern: the key {PROVIDER_KEY} is in notes.md")),
        ],
        Some(limits(10, 5)),
    )
    .await;
    assert_eq!(std::fs::read_to_string(&notes).unwrap(), leaky);

    let reviews = outcome.advisor.served();
    assert_eq!(reviews.len(), 2);
    for review in &reviews {
        let sent = all_payloads(review);
        for secret in [
            // Known to the process: a provider setting, an MCP token, a
            // value of the environment.
            PROVIDER_KEY,
            MCP_TOKEN,
            ENV_SECRET,
            // Recognized by what surrounds them.
            "correct-horse-battery",
            "abcdefghijklmnopqrstuvwx",
        ] {
            assert!(!sent.contains(secret), "{secret} was sent to the advisor");
        }
        assert!(sent.contains("[redacted]"));
        // What is plainly not a secret is still there to be reviewed.
        assert!(
            sent.contains("built for production in /srv/work/project"),
            "{sent}"
        );
        assert_eq!(review.model, ADVISOR_MODEL);

        // The instructions are the fixed text: nothing about the machine,
        // the working directory or the environment is added to them.
        assert!(matches!(
            &review.messages[0],
            ChatMessage::System { content: ChatMessageContent::Text(prompt), .. }
                if prompt == ADVISOR_PROMPT
        ));
    }
    // The file the advisor read came back redacted too.
    let read_back = &tool_results(&reviews[1])[0];
    assert!(
        read_back.contains("deploy with key [redacted]"),
        "{read_back}"
    );

    // Nor does a secret come back out through the note.
    let notes = outcome.notes();
    assert_eq!(notes.len(), 1);
    assert!(!notes[0].1.contains(PROVIDER_KEY), "{}", notes[0].1);
    assert_eq!(notes[0].1, "the key (redacted) is in notes.md");
}

#[tokio::test]
async fn a_digest_is_sent_as_it_was_built() {
    let dir = TempDir::new().unwrap();
    let script = Script::new(vec![text("NONE")]);
    let advisor = advisor_on(
        &script,
        dir.path(),
        AdvisorLimits::default(),
        &config_with_a_secret(),
    );
    let reviewer = advisor.reviewer();

    // Code that names what it handles and holds no secret, a command with
    // quotes inside quotes, and a key the process knows: all of it inside
    // the JSON of tool calls, where quotes and line breaks are escaped.
    let write = call(
        "write",
        json!({"files": [{
            "path": "src/creds.rs",
            "content": "pub struct Creds {\n    pub password: String,\n    pub token: Token,\n    pub name: String,\n}\n\nclass Login:\n    token: str\n    expires: int\n",
        }]}),
    );
    let run = call(
        "bash",
        json!({
            "command": format!(
                "export DB_PASSWORD=\"$DB_PASSWORD\"\necho \"it's \\\"done\\\"\" && curl -H \"X-Key: {PROVIDER_KEY}\" https://example.com"
            ),
        }),
    );
    let result_of = |assistant: &ChatMessage, content: &str| match assistant {
        ChatMessage::Assistant {
            tool_calls: Some(calls),
            ..
        } => ChatMessage::Tool {
            tool_call_id: calls[0].id.clone(),
            content: ChatMessageContent::Text(content.to_string()),
        },
        _ => unreachable!("a tool call"),
    };
    let trace = vec![
        user_message("add the struct"),
        write.clone(),
        result_of(&write, "1 file written"),
        run.clone(),
        result_of(&run, "it's \"done\"\nline two"),
    ];
    let digest = digest::build_digest(&trace, 0, &reviewer.redactor).expect("steps to show");
    assert!(digest.as_str().contains("calls write with {"));
    assert!(digest.as_str().contains("calls bash with {"));

    assert_eq!(reviewer.review(&digest).await, Ok(None));
    let reviews = script.served();
    assert_eq!(reviews.len(), 1);
    let sent = match &reviews[0].messages[1] {
        ChatMessage::User {
            content: ChatMessageContent::Text(sent),
            ..
        } => sent.clone(),
        other => panic!("the digest is the user message, not {other:?}"),
    };
    // Not a character of it is rewritten on the way out.
    assert_eq!(sent, digest.as_str());
    // What had to go was taken out when the digest was built.
    assert!(!sent.contains(PROVIDER_KEY), "{sent}");
    assert!(sent.contains("[redacted]"), "{sent}");
}

#[tokio::test]
async fn a_failing_advisor_never_stops_the_agent_and_is_switched_off() {
    let dir = TempDir::new().unwrap();
    let outcome = run(
        dir.path(),
        steps(dir.path(), 7),
        vec![
            Reply::Fail("model not found"),
            Reply::Fail("model not found"),
            says("blocker: never asked for"),
        ],
        Some(limits(10, 1)),
    )
    .await;

    // Two reviews fail; the advisor is then left alone for good.
    assert_eq!(outcome.advisor.served().len(), 2);
    assert_eq!(outcome.failures(), [false, true]);
    assert!(outcome.notes().is_empty());

    // The agent went through all of its steps regardless, on its own model.
    assert_eq!(outcome.main.served_by(), [MAIN; 8]);
    for request in outcome.main.served() {
        assert!(!all_text(&request).contains("advisor note"));
    }
}

#[tokio::test]
async fn a_review_that_runs_out_of_rounds_leaves_no_note() {
    let dir = TempDir::new().unwrap();
    // The advisor keeps calling tools and never concludes.
    let stalling: Vec<Reply> = (0..20)
        .map(|_| Reply::Message(call("ls", json!({}))))
        .collect();
    let outcome = run(
        dir.path(),
        steps(dir.path(), 1),
        stalling,
        Some(limits(10, 5)),
    )
    .await;

    let reviews = outcome.advisor.served();
    assert_eq!(reviews.len(), review::MAX_ROUNDS);
    // The last round offers no tool at all.
    assert!(reviews.last().unwrap().tools.is_empty());
    assert!(outcome.notes().is_empty());
    assert_eq!(outcome.main.served().len(), 2);
}

#[tokio::test]
async fn the_final_round_keeps_a_text_verdict_and_does_not_run_tools() {
    use openai_dive::v1::resources::chat::{Function, ToolCall};
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("canary.txt"), "should-not-be-looked-up\n").unwrap();
    // Five lookups, then a last reply that both calls a tool and gives a
    // verdict. The last round must keep the verdict and not start the
    // lookup there is no later request to receive.
    let mut stalling: Vec<Reply> = (0..review::MAX_ROUNDS - 1)
        .map(|_| Reply::Message(call("ls", json!({}))))
        .collect();
    stalling.push(Reply::Message(ChatMessage::Assistant {
        content: Some(ChatMessageContent::Text(
            "nit: the last lookup was not needed".to_string(),
        )),
        reasoning: None,
        reasoning_content: None,
        tool_calls: Some(vec![ToolCall {
            id: "call_final".to_string(),
            r#type: "function".to_string(),
            function: Function {
                name: "read".to_string(),
                arguments: r#"{"path": "canary.txt"}"#.to_string(),
            },
        }]),
        name: None,
        audio: None,
        refusal: None,
    }));
    let outcome = run(
        dir.path(),
        steps(dir.path(), 1),
        stalling,
        Some(limits(10, 5)),
    )
    .await;

    let reviews = outcome.advisor.served();
    assert_eq!(reviews.len(), review::MAX_ROUNDS);
    assert!(reviews.last().unwrap().tools.is_empty());
    // No later request was made with a tool result, so the canary was not
    // sent back to the model.
    let sent = reviews
        .iter()
        .flat_map(|review| review.messages.iter())
        .map(|message| format!("{message:?}"))
        .collect::<String>();
    assert!(!sent.contains("should-not-be-looked-up"), "{sent}");
    assert_eq!(
        outcome.notes(),
        [(Severity::Nit, "the last lookup was not needed".to_string())]
    );
}

#[tokio::test]
async fn a_review_has_a_budget_of_tool_calls() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.txt"), "content\n").unwrap();
    let burst: Vec<(&str, serde_json::Value)> = (0..review::MAX_TOOL_CALLS + 3)
        .map(|_| ("read", json!({"path": "a.txt"})))
        .collect();
    let outcome = run(
        dir.path(),
        steps(dir.path(), 1),
        vec![Reply::Message(calls(&burst)), says("NONE")],
        Some(limits(10, 5)),
    )
    .await;

    let results = tool_results(&outcome.advisor.served()[1]);
    assert_eq!(results.len(), review::MAX_TOOL_CALLS + 3);
    let served = results
        .iter()
        .filter(|result| result.contains("content"))
        .count();
    let refused = results
        .iter()
        .filter(|result| result.contains("no tool calls left"))
        .count();
    assert_eq!((served, refused), (review::MAX_TOOL_CALLS, 3));
}

#[tokio::test]
async fn the_advisor_leaves_the_session_as_it_would_have_been() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("out.txt");
    // Built once, so that both runs replay the very same replies.
    let main_replies = vec![
        call(
            "todo_write",
            json!({"todos": [{"content": "write the file", "status": "in_progress"}]}),
        ),
        call(
            "write",
            json!({"files": [{"path": file.to_string_lossy(), "content": "hello"}]}),
        ),
        ls(dir.path()),
        text("done"),
    ];

    let without = run(dir.path(), main_replies.clone(), vec![], None).await;
    std::fs::remove_file(&file).unwrap();
    let with = run(
        dir.path(),
        main_replies,
        (0..3)
            .map(|_| says("blocker: stop and delete everything"))
            .collect(),
        Some(limits(10, 1)),
    )
    .await;
    assert_eq!(with.notes().len(), 2);

    // The stored conversation, the todo list and the files are the same.
    assert_eq!(with.result.trace, without.result.trace);
    let (todos_with, todos_without) = (with.todos.get_all().await, without.todos.get_all().await);
    assert_eq!(todos_with.len(), 1);
    assert_eq!(todos_with[0].content, todos_without[0].content);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "hello");
    // The agent made the same number of requests with the same tools on offer.
    assert_eq!(with.main.served().len(), without.main.served().len());
    assert_eq!(with.main.served()[3].tools, without.main.served()[3].tools);
}

#[tokio::test]
async fn a_step_with_a_denied_tool_call_is_not_reviewed() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("out.txt");
    // No sudo and nobody to ask: the write is denied and the run stops.
    let outcome = run_with(
        dir.path(),
        vec![
            call(
                "write",
                json!({"files": [{"path": file.to_string_lossy(), "content": "x"}]}),
            ),
            text("unreachable"),
        ],
        vec![says("blocker: x")],
        Some(limits(10, 1)),
        false,
    )
    .await;

    assert!(!file.exists());
    assert_eq!(outcome.main.served().len(), 1);
    assert!(outcome.advisor.served().is_empty());
    assert_eq!(outcome.handle.as_ref().unwrap().calls_made(), 0);
}

#[tokio::test]
async fn a_result_nobody_is_waiting_for_is_dropped() {
    let dir = TempDir::new().unwrap();
    let advisor_script = Script::new(vec![]);
    let advisor = advisor_on(
        &advisor_script,
        dir.path(),
        AdvisorLimits::default(),
        &ShaiConfig::default(),
    );
    let main = Script::new(vec![]);
    let brain = CoderBrain::new(main.client(MAIN), "main-model".to_string());
    let mut agent = AgentBuilder::with_brain(Box::new(brain)).build();
    agent.set_advisor(advisor).unwrap();

    // The agent is not in an advisor phase: a result that shows up anyway,
    // from a review that was cancelled, must not be applied or move it.
    let note = AdvisorNote {
        severity: Severity::Blocker,
        text: "late".to_string(),
    };
    agent
        .finish_advisor_review(1, Ok(Some(note)))
        .await
        .unwrap();
    assert!(agent.take_advisor_note().is_none());
    assert!(matches!(
        agent.state,
        crate::agent::InternalAgentState::Starting
    ));
}

/// An agent on the coder brain, with the default tools, served by `main`.
fn agent_with(main: &Script, advisor: &Advisor) -> crate::agent::AgentCore {
    let (tools, _) = AgentBuilder::create_default_tools(std::sync::Arc::new(FsOperationLog::new()));
    let brain = CoderBrain::new(main.client(MAIN), "main-model".to_string());
    let mut agent = AgentBuilder::with_brain(Box::new(brain))
        .tools(tools)
        .goal("tidy the project")
        .sudo()
        .build();
    agent.set_advisor(advisor.clone()).unwrap();
    agent
}

/// Wait until `script` has received `count` requests.
async fn served_reaches(script: &Script, count: usize) {
    tokio::time::timeout(Duration::from_secs(60), async {
        while script.served().len() < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the request should have been made");
}

#[tokio::test]
async fn a_review_is_given_up_when_the_user_speaks() {
    let dir = TempDir::new().unwrap();
    let main = Script::new(vec![ls(dir.path()), text("hello")]);
    // The advisor is asked and never answers.
    let advisor_script = Script::with_replies(vec![Reply::Hold]);
    let advisor = advisor_on(
        &advisor_script,
        dir.path(),
        limits(10, 5),
        &ShaiConfig::default(),
    );
    let mut agent = agent_with(&main, &advisor);
    let controller = agent.controller();
    let mut events = agent.watch();
    let run = tokio::spawn(async move { agent.run().await });

    // The first step is done and under review: the agent waits.
    served_reaches(&advisor_script, 1).await;
    assert_eq!(main.served().len(), 1);

    // The user does not: the review is dropped and the agent answers them.
    controller
        .send_user_input("never mind, just say hello".to_string())
        .await
        .unwrap();
    served_reaches(&main, 2).await;
    controller.wait_turn(Some(60_000)).await.unwrap();

    let request = &main.served()[1];
    assert!(all_text(request).contains("never mind, just say hello"));
    assert!(!all_text(request).contains("advisor note"));
    // The review that was started counts, and nothing came of it.
    assert_eq!(advisor.calls_made(), 1);
    assert_eq!(advisor_script.served().len(), 1);
    assert!(!advisor.is_off());

    controller.terminate().await.unwrap();
    let joined = tokio::time::timeout(Duration::from_secs(60), run)
        .await
        .expect("the agent task must exit after terminate");
    let result = joined.expect("the agent task must not panic");
    assert!(
        result.is_ok(),
        "terminate should complete the agent, got {result:?}"
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(
                event,
                AgentEvent::AdvisorNote { .. } | AgentEvent::AdvisorFailed { .. }
            ),
            "{event:?}"
        );
    }
}

#[tokio::test]
async fn a_review_that_takes_too_long_is_dropped_as_a_failure() {
    let dir = TempDir::new().unwrap();
    let main = Script::new(steps(dir.path(), 4));
    let advisor_script = Script::with_replies(vec![Reply::Hold, Reply::Hold, Reply::Hold]);
    let advisor = advisor_on(
        &advisor_script,
        dir.path(),
        limits(10, 1),
        &ShaiConfig::default(),
    )
    .with_review_timeout(Duration::from_millis(50));
    let mut agent = agent_with(&main, &advisor);
    let mut events = agent.watch();
    tokio::time::timeout(Duration::from_secs(60), agent.run())
        .await
        .expect("the agent run should finish")
        .expect("the agent run should succeed");

    // Two reviews were waited for and given up; the second one switched the
    // advisor off, so there was no third. The agent did all of its steps.
    assert_eq!(advisor_script.served().len(), 2);
    assert_eq!(main.served_by(), [MAIN; 5]);
    assert!(advisor.is_off());
    let mut failures = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let AgentEvent::AdvisorFailed { error, disabled } = event {
            failures.push((error, disabled));
        }
    }
    assert_eq!(
        failures,
        [
            ("the review took too long".to_string(), false),
            ("the review took too long".to_string(), true),
        ]
    );
}

#[tokio::test]
async fn an_advisor_that_was_switched_off_stays_off_for_the_next_agent() {
    let dir = TempDir::new().unwrap();
    let advisor_script = Script::with_replies(vec![
        Reply::Fail("model not found"),
        Reply::Fail("model not found"),
        says("blocker: never asked for"),
    ]);
    let advisor = advisor_on(
        &advisor_script,
        dir.path(),
        limits(10, 1),
        &ShaiConfig::default(),
    );

    // The first agent of the session sees it fail twice.
    let first = Script::new(steps(dir.path(), 4));
    let mut agent = agent_with(&first, &advisor);
    tokio::time::timeout(Duration::from_secs(60), agent.run())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(advisor_script.served().len(), 2);
    assert!(advisor.is_off());

    // An agent that replaces it, as a front-end builds one, does not bring
    // the advisor back, and neither does setting it up again for a config
    // that has changed.
    let renewed = advisor
        .renewed_with_environment(
            BoundModel::new(advisor_script.client(ADVISOR), ADVISOR_MODEL),
            dir.path(),
            limits(10, 1),
            &ShaiConfig::default(),
            environment(),
        )
        .unwrap();
    for handle in [&advisor, &renewed] {
        let next = Script::new(steps(dir.path(), 4));
        let mut agent = agent_with(&next, handle);
        assert!(!agent.has_advisor());
        tokio::time::timeout(Duration::from_secs(60), agent.run())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(next.served_by(), [MAIN; 5]);
    }
    assert_eq!(advisor_script.served().len(), 2);
}

#[tokio::test]
async fn the_cooldown_carries_over_to_the_next_agent() {
    let dir = TempDir::new().unwrap();
    let advisor_script = Script::with_replies(vec![says("NONE"), says("NONE")]);
    let advisor = advisor_on(
        &advisor_script,
        dir.path(),
        limits(10, 2),
        &ShaiConfig::default(),
    );

    // One step, reviewed. Then a new agent: its first two steps fall in the
    // cooldown of that review, its third is reviewed.
    for (step_count, reviews_so_far) in [(1, 1), (2, 1), (1, 2)] {
        let main = Script::new(steps(dir.path(), step_count));
        let mut agent = agent_with(&main, &advisor);
        tokio::time::timeout(Duration::from_secs(60), agent.run())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(advisor_script.served().len(), reviews_so_far);
    }
    assert_eq!(advisor.calls_made(), 2);
}

#[tokio::test]
async fn steps_done_again_after_a_regenerate_are_reviewed_again() {
    let dir = TempDir::new().unwrap();
    let main = Script::new(vec![
        ls(dir.path()),
        text("first answer"),
        ls(dir.path()),
        text("second answer"),
    ]);
    let advisor_script =
        Script::with_replies(vec![says("nit: first review"), says("NONE"), says("NONE")]);
    let advisor = advisor_on(
        &advisor_script,
        dir.path(),
        limits(10, 0),
        &ShaiConfig::default(),
    );
    let mut agent = agent_with(&main, &advisor);
    let controller = agent.controller();
    let run = tokio::spawn(async move { agent.run().await });

    // One step, one review, then the answer.
    served_reaches(&main, 2).await;
    controller.wait_turn(Some(60_000)).await.unwrap();
    assert_eq!(advisor_script.served().len(), 1);

    // The user asks for the answer again: the agent redoes its step.
    controller.regenerate().await.unwrap();
    served_reaches(&main, 4).await;
    controller.wait_turn(Some(60_000)).await.unwrap();

    // That step is shown to the advisor, although the conversation is no
    // longer than it was at the first review.
    let reviews = advisor_script.served();
    assert_eq!(reviews.len(), 2);
    let digest = all_text(&reviews[1]);
    assert!(digest.contains("calls ls with"), "{digest}");
    assert!(digest.contains("Result of ls"), "{digest}");
    assert_eq!(advisor.calls_made(), 2);

    controller.terminate().await.unwrap();
    let joined = tokio::time::timeout(Duration::from_secs(60), run)
        .await
        .expect("the agent task must exit after terminate");
    let result = joined.expect("the agent task must not panic");
    assert!(
        result.is_ok(),
        "terminate should complete the agent, got {result:?}"
    );
}

#[tokio::test]
async fn a_failed_review_does_not_count_as_having_looked() {
    let dir = TempDir::new().unwrap();
    let outcome = run(
        dir.path(),
        vec![
            call("ls", json!({"directory": dir.path().to_string_lossy()})),
            call("todo_read", json!({})),
            text("done"),
        ],
        vec![Reply::Fail("try later"), says("NONE")],
        Some(limits(10, 0)),
    )
    .await;

    let reviews = outcome.advisor.served();
    assert_eq!(reviews.len(), 2);
    // The second review is shown the step the first one failed on, too.
    let digest = all_text(&reviews[1]);
    assert!(digest.contains("calls ls with"), "{digest}");
    assert!(digest.contains("calls todo_read with"), "{digest}");
    assert_eq!(outcome.failures(), [false]);
}

#[test]
fn where_this_process_keeps_its_records_is_out_of_reach_wherever_that_is() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("var/transcripts")).unwrap();
    std::fs::write(dir.path().join("var/transcripts/s.json"), "transcript-text").unwrap();
    std::fs::write(dir.path().join("var/readme.md"), "fine").unwrap();
    let script = Script::new(vec![]);
    let advisor = Advisor::with_environment(
        BoundModel::new(script.client(ADVISOR), ADVISOR_MODEL),
        dir.path(),
        AdvisorLimits::default(),
        &ShaiConfig::default(),
        [(
            "SHAI_SESSION_PERSIST_FOLDER".to_string(),
            dir.path()
                .join("var/transcripts")
                .to_string_lossy()
                .into_owned(),
        )],
    )
    .unwrap();
    let reviewer = advisor.reviewer();
    assert!(reviewer.fs.resolve("var/transcripts/s.json").is_err());
    assert!(reviewer.fs.resolve("var/readme.md").is_ok());
}

#[test]
fn a_working_directory_inside_a_records_folder_is_refused() {
    let dir = TempDir::new().unwrap();
    let records = dir.path().join("records");
    let day = records.join("day");
    std::fs::create_dir_all(&day).unwrap();
    std::fs::write(day.join("README.md"), "ok\n").unwrap();
    let script = Script::new(vec![]);
    for root in [&day, &records] {
        let error = Advisor::with_environment(
            BoundModel::new(script.client(ADVISOR), ADVISOR_MODEL),
            root,
            AdvisorLimits::default(),
            &ShaiConfig::default(),
            [(
                "SHAI_SESSION_FOLDER".to_string(),
                records.to_string_lossy().into_owned(),
            )],
        )
        .unwrap_err();
        assert!(
            matches!(error, AdvisorError::WorkingDir(_)),
            "{root:?}: {error}"
        );
    }
}

#[test]
fn a_renewed_advisor_still_refuses_the_old_records_path() {
    let dir = TempDir::new().unwrap();
    let old = dir.path().join("old-transcripts");
    let new = dir.path().join("new-transcripts");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::create_dir_all(&new).unwrap();
    std::fs::write(old.join("s.json"), "old-transcript").unwrap();
    std::fs::write(new.join("s.json"), "new-transcript").unwrap();
    std::fs::write(dir.path().join("README.md"), "ok\n").unwrap();
    let script = Script::new(vec![]);
    let env_for = |folder: &Path| {
        let mut env = environment();
        env.push((
            "SHAI_SESSION_PERSIST_FOLDER".to_string(),
            folder.to_string_lossy().into_owned(),
        ));
        env
    };
    let advisor = Advisor::with_environment(
        BoundModel::new(script.client(ADVISOR), ADVISOR_MODEL),
        dir.path(),
        AdvisorLimits::default(),
        &ShaiConfig::default(),
        env_for(&old),
    )
    .unwrap();
    assert!(advisor
        .reviewer()
        .fs
        .resolve("old-transcripts/s.json")
        .is_err());
    let renewed = advisor
        .renewed_with_environment(
            BoundModel::new(script.client(ADVISOR), ADVISOR_MODEL),
            dir.path(),
            AdvisorLimits::default(),
            &ShaiConfig::default(),
            env_for(&new),
        )
        .unwrap();
    assert!(renewed
        .reviewer()
        .fs
        .resolve("old-transcripts/s.json")
        .is_err());
    assert!(renewed
        .reviewer()
        .fs
        .resolve("new-transcripts/s.json")
        .is_err());
    assert!(renewed.reviewer().fs.resolve("README.md").is_ok());
}

/// An advisor confined to `dir` that is told `environment` and never asked.
fn advisor_in(dir: &Path, config: &ShaiConfig, environment: &[(&str, &Path)]) -> Advisor {
    Advisor::with_environment(
        BoundModel::new(Script::new(vec![]).client(ADVISOR), ADVISOR_MODEL),
        dir,
        AdvisorLimits::default(),
        config,
        environment
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string_lossy().into_owned())),
    )
    .expect("advisor")
}

#[test]
fn the_log_of_this_process_is_out_of_reach_wherever_it_is_written() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("logs")).unwrap();
    std::fs::write(dir.path().join("logs/shai.log"), "what the agent did").unwrap();
    std::fs::write(dir.path().join("logs/build.log"), "what the build did").unwrap();

    let log_file = dir.path().join("logs/shai.log");
    let advisor = advisor_in(
        dir.path(),
        &ShaiConfig::default(),
        &[("SHAI_LOG_FILE", log_file.as_path())],
    );
    let reviewer = advisor.reviewer();
    assert!(reviewer.fs.resolve("logs/shai.log").is_err());
    // Neither read by name nor met in a search of the directory it is in.
    let logs = reviewer.fs.resolve("logs").unwrap();
    assert!(!reviewer.fs.may_visit(&logs.join("shai.log"), false, false));
    // The files next to it are the project's.
    assert!(reviewer.fs.resolve("logs/build.log").is_ok());
    assert!(reviewer.fs.may_visit(&logs.join("build.log"), false, false));
    // The logger writes one file a day, named after the configured one.
    std::fs::write(dir.path().join("logs/shai.log.2026-11-16"), "what it did").unwrap();
    assert!(reviewer.fs.resolve("logs/shai.log.2026-11-16").is_err());
    assert!(!reviewer
        .fs
        .may_visit(&logs.join("shai.log.2026-11-16"), false, false));

    // Not set, the same file is a file like any other.
    let advisor = advisor_in(dir.path(), &ShaiConfig::default(), &[]);
    assert!(advisor.reviewer().fs.resolve("logs/shai.log").is_ok());
}

#[cfg(unix)]
#[test]
fn the_working_directory_is_also_known_by_the_name_the_session_gives_it() {
    use std::os::unix::fs::symlink;
    let tmp = TempDir::new().unwrap();
    // The system's own name of the directory, as `current_dir` gives it.
    let work = tmp.path().canonicalize().unwrap().join("work");
    std::fs::create_dir_all(work.join("src")).unwrap();
    std::fs::write(work.join("src/lib.rs"), "pub fn inside() {}\n").unwrap();
    let other = work.parent().unwrap().join("other");
    std::fs::create_dir_all(other.join("src")).unwrap();
    std::fs::write(other.join("src/lib.rs"), "pub fn outside() {}\n").unwrap();
    // The session was started through a link, and its shell says so.
    let link = work.parent().unwrap().join("link-to-work");
    symlink(&work, &link).unwrap();
    let through = |name: &Path| name.join("src/lib.rs").to_string_lossy().into_owned();

    let advisor = advisor_in(&work, &ShaiConfig::default(), &[("PWD", link.as_path())]);
    let reviewer = advisor.reviewer();
    let inside = work.join("src/lib.rs");
    // A path written the way the agent's commands print it is understood,
    // and so is the system's.
    assert_eq!(reviewer.fs.resolve(&through(&link)), Ok(inside.clone()));
    assert_eq!(reviewer.fs.resolve(&through(&work)), Ok(inside.clone()));
    assert_eq!(reviewer.fs.resolve("src/lib.rs"), Ok(inside.clone()));
    assert!(reviewer.fs.resolve(&through(&other)).is_err());

    // Without that name in the environment the path is outside.
    let advisor = advisor_in(&work, &ShaiConfig::default(), &[]);
    assert!(advisor.reviewer().fs.resolve(&through(&link)).is_err());

    // A name is only taken when it is another name of the same directory:
    // not one of another directory, not a relative one, and not one that a
    // link and the text of the path resolve differently. Through the link
    // `up`, the last of these leads to the working directory; read as text
    // it is a directory next to `up` that has nothing to do with it.
    let link_to_other = work.parent().unwrap().join("link-to-other");
    symlink(&other, &link_to_other).unwrap();
    let elsewhere = work.parent().unwrap().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    symlink(&other, elsewhere.join("up")).unwrap();
    let climbing = elsewhere.join("up").join("..").join("work");
    assert_eq!(climbing.canonicalize().unwrap(), work);
    let as_text = elsewhere.join("work");
    for (name, outside) in [
        (other.as_path(), other.as_path()),
        (link_to_other.as_path(), link_to_other.as_path()),
        (Path::new("link-to-work"), link.as_path()),
        (Path::new("."), link.as_path()),
        (climbing.as_path(), as_text.as_path()),
    ] {
        let advisor = advisor_in(&work, &ShaiConfig::default(), &[("PWD", name)]);
        let reviewer = advisor.reviewer();
        // Confined to the working directory all the same.
        assert_eq!(reviewer.fs.resolve("src/lib.rs"), Ok(inside.clone()));
        assert_eq!(reviewer.fs.resolve("."), Ok(work.clone()));
        assert!(
            reviewer.fs.resolve(&through(outside)).is_err(),
            "{} is not a name of the working directory",
            outside.display()
        );
    }
}

#[test]
fn what_the_mcp_servers_of_the_config_hold_is_kept_out_too() {
    use crate::tools::mcp::mcp_config::OAuthToken;
    use crate::tools::mcp::McpConfig;
    // Credentials written into the address of a server: nothing about their
    // shape or the words around them says what they are.
    const URL_PASSWORD: &str = "wanders-over-hills-51";
    const URL_QUERY_VALUE: &str = "lantern-under-bridge-7";
    const SSE_QUERY_VALUE: &str = "orchard-behind-mill-33";
    // A credential in the path of an address, and two given to a command.
    const PATH_TOKEN: &str = "zp-tok-9f8e7d6c5b4a39281706";
    const STDIO_OPTION_VALUE: &str = "plainlooking9f8e7d6c5b4a";
    const STDIO_VARIABLE_VALUE: &str = "meadow-past-river-12";
    const STDIO_URL_PASSWORD: &str = "Xk29fjq0Lmz8Qw";

    let mut config = ShaiConfig::default();
    config.mcp_configs.insert(
        "tracker".to_string(),
        McpConfig::Http {
            url: format!(
                "https://reader:{URL_PASSWORD}@mcp.example.com/v1?access={URL_QUERY_VALUE}"
            ),
            auth: Some(OAuthToken {
                access_token: MCP_TOKEN.to_string(),
                expires_at: None,
            }),
        },
    );
    config.mcp_configs.insert(
        "events".to_string(),
        McpConfig::Sse {
            url: format!("https://events.example.net/sse?access={SSE_QUERY_VALUE}"),
        },
    );
    config.mcp_configs.insert(
        "local".to_string(),
        McpConfig::Stdio {
            command: "npx".to_string(),
            args: [
                "--yes",
                "some-mcp-package",
                "--api-key",
                STDIO_OPTION_VALUE,
                "--workspace",
                "team-backend-services",
                &format!("SERVICE_TOKEN={STDIO_VARIABLE_VALUE}"),
                "--auth-mode",
                "client_credentials",
                "--author",
                "Jane Developer",
                "-e",
                &format!("DATABASE_URL=postgres://app:{STDIO_URL_PASSWORD}@db.internal:5432/app"),
            ]
            .map(str::to_string)
            .to_vec(),
        },
    );
    config.mcp_configs.insert(
        "gateway".to_string(),
        McpConfig::Sse {
            url: "https://apim.example.net/openai/deployments/gpt-4o-mini-2024-07-18/mcp"
                .to_string(),
        },
    );
    config.mcp_configs.insert(
        "hosted".to_string(),
        McpConfig::Sse {
            url: format!("https://actions.example.org/mcp/{PATH_TOKEN}/sse"),
        },
    );

    let dir = TempDir::new().unwrap();
    let advisor = advisor_in(dir.path(), &config, &[]);
    let redactor = &advisor.reviewer().redactor;
    for secret in [
        URL_PASSWORD,
        URL_QUERY_VALUE,
        SSE_QUERY_VALUE,
        MCP_TOKEN,
        PATH_TOKEN,
        STDIO_OPTION_VALUE,
        STDIO_VARIABLE_VALUE,
        STDIO_URL_PASSWORD,
    ] {
        let sent = redactor.redact(&format!("the server answered {secret} and went on"));
        assert!(
            !sent.contains(secret) && sent.contains("[redacted]"),
            "{sent}"
        );
    }
    // Where the servers are, and how a local one is started, is not a
    // secret: the advisor can still read about them.
    let sent = redactor
        .redact("connects to mcp.example.com and events.example.net, starts some-mcp-package");
    for readable in ["mcp.example.com", "events.example.net", "some-mcp-package"] {
        assert!(sent.contains(readable), "{sent}");
    }
    // What a server is set up with but is not a credential stays readable.
    for plain in [
        "client_credentials",
        "Jane Developer",
        "gpt-4o-mini-2024-07-18",
    ] {
        let text = format!("uses {plain} here");
        assert_eq!(redactor.redact(&text), text);
    }
}

#[test]
fn an_agent_whose_brain_takes_no_notes_gets_no_advisor() {
    use crate::agent::brain::{Brain, ThinkerContext, ThinkerDecision, ToolBudgetRef};
    use crate::agent::{AdvisorAttachError, AgentError};

    /// A brain that keeps the default: it does not show notes to its model.
    struct Deaf;

    #[async_trait::async_trait]
    impl Brain for Deaf {
        async fn next_step(
            &mut self,
            _: ThinkerContext,
            _: ToolBudgetRef,
        ) -> Result<ThinkerDecision, AgentError> {
            unreachable!("the agent is never run")
        }
    }

    let dir = TempDir::new().unwrap();
    let script = Script::new(vec![]);
    let advisor = advisor_on(
        &script,
        dir.path(),
        AdvisorLimits::default(),
        &ShaiConfig::default(),
    );

    let mut deaf = AgentBuilder::with_brain(Box::new(Deaf)).build();
    assert_eq!(
        deaf.set_advisor(advisor.clone()),
        Err(AdvisorAttachError::NoNotes)
    );
    assert!(!deaf.has_advisor());

    // The coder brain does take them. A refusal also removes an advisor
    // that was attached before.
    let brain = CoderBrain::new(script.client(MAIN), "main-model".to_string());
    let mut agent = AgentBuilder::with_brain(Box::new(brain)).build();
    assert_eq!(agent.set_advisor(advisor.clone()), Ok(()));
    assert!(agent.has_advisor());
    let held = agent.brain.clone();
    let busy = held.try_write().expect("nothing else holds the brain");
    assert_eq!(agent.set_advisor(advisor), Err(AdvisorAttachError::NoNotes));
    drop(busy);
    assert!(!agent.has_advisor());
    assert!(script.served().is_empty());
}

#[test]
fn a_renewed_advisor_keeps_the_reviews_already_spent() {
    let dir = TempDir::new().unwrap();
    let script = Script::new(vec![]);
    let advisor = advisor_on(&script, dir.path(), limits(3, 1), &ShaiConfig::default());
    assert!(advisor.take_call());
    advisor.elapse_cooldown();
    assert!(advisor.take_call());

    // Set up again after a config change: another model, a lower cap.
    let renewed = advisor
        .renewed_with_environment(
            BoundModel::new(script.client("other"), "other-model"),
            dir.path(),
            limits(2, 1),
            &config_with_a_secret(),
            environment(),
        )
        .unwrap();
    assert_eq!(renewed.label(), "other/other-model");
    assert_eq!(renewed.limits(), limits(2, 1));
    assert_eq!(renewed.calls_made(), 2);
    // Two were spent before; with a cap of two, none is left.
    assert!(!renewed.take_call());

    // The counter is one and the same from then on.
    let roomier = advisor
        .renewed_with_environment(
            BoundModel::new(script.client("other"), "other-model"),
            dir.path(),
            limits(4, 1),
            &ShaiConfig::default(),
            environment(),
        )
        .unwrap();
    roomier.elapse_cooldown();
    assert!(roomier.take_call());
    assert_eq!(advisor.calls_made(), 3);
    assert_eq!(renewed.calls_made(), 3);

    // It keeps out the credentials of the config and of the environment it
    // was set up again with.
    for secret in [PROVIDER_KEY, MCP_TOKEN, ENV_SECRET] {
        let sent = renewed
            .reviewer()
            .redactor
            .redact(&format!("it printed {secret} twice"));
        assert!(
            !sent.contains(secret) && sent.contains("[redacted]"),
            "{sent}"
        );
    }

    // A directory that cannot be used is still refused.
    assert!(advisor
        .renewed_with_environment(
            BoundModel::new(script.client("other"), "other-model"),
            &dir.path().join("missing"),
            limits(4, 1),
            &ShaiConfig::default(),
            environment(),
        )
        .is_err());
    assert!(script.served().is_empty());
}

#[test]
fn the_working_directory_must_exist() {
    let dir = TempDir::new().unwrap();
    let script = Script::new(vec![]);
    let error = Advisor::with_environment(
        BoundModel::new(script.client(ADVISOR), ADVISOR_MODEL),
        &dir.path().join("missing"),
        AdvisorLimits::default(),
        &ShaiConfig::default(),
        environment(),
    )
    .unwrap_err();
    assert!(matches!(error, AdvisorError::WorkingDir(_)));

    let advisor = advisor_on(
        &script,
        dir.path(),
        AdvisorLimits::default(),
        &config_with_a_secret(),
    );
    assert_eq!(advisor.label(), "advisor/advisor-model");
    // Nothing it knows shows up when it is printed.
    assert!(!format!("{advisor:?}").contains(PROVIDER_KEY));
}

// ---- attaching a note to a request ------------------------------------------

fn tool_message(content: &str) -> ChatMessage {
    ChatMessage::Tool {
        tool_call_id: "call_1".to_string(),
        content: ChatMessageContent::Text(content.to_string()),
    }
}

fn user_message(content: &str) -> ChatMessage {
    ChatMessage::User {
        content: ChatMessageContent::Text(content.to_string()),
        name: None,
    }
}

fn system_message(content: &str) -> ChatMessage {
    ChatMessage::System {
        content: ChatMessageContent::Text(content.to_string()),
        name: None,
    }
}

#[test]
fn a_note_goes_at_the_end_of_the_last_tool_result() {
    let mut trace = vec![
        user_message("go"),
        calls(&[("ls", json!({})), ("ls", json!({}))]),
        tool_message("first"),
        tool_message("second"),
    ];
    attach_note(&mut trace, "NOTE");
    assert_eq!(trace[2], tool_message("first"));
    assert_eq!(trace[3], tool_message("second\n\nNOTE"));

    // A harness message after the tool results is stepped over.
    let mut trace = vec![
        user_message("go"),
        call("ls", json!({})),
        tool_message("result"),
        system_message("Post-edit verification reported diagnostics"),
    ];
    attach_note(&mut trace, "NOTE");
    assert_eq!(trace[2], tool_message("result\n\nNOTE"));
    assert_eq!(
        trace[3],
        system_message("Post-edit verification reported diagnostics")
    );
}

#[test]
fn a_note_with_no_tool_result_to_carry_it_is_dropped() {
    // The user has spoken since the step, or the step called no tool: the
    // note is never turned into a message of its own.
    for mut trace in [
        vec![],
        vec![user_message("go")],
        vec![
            user_message("go"),
            call("ls", json!({})),
            tool_message("result"),
            user_message("wait"),
        ],
        vec![
            user_message("go"),
            call("ls", json!({})),
            tool_message("result"),
            text("all done"),
        ],
    ] {
        let before = trace.clone();
        attach_note(&mut trace, "NOTE");
        assert_eq!(trace, before);
    }
}

#[test]
fn a_custom_agents_credentials_are_kept_out_of_what_is_sent() {
    let dir = TempDir::new().unwrap();
    let advisor = advisor_on(
        &Script::new(vec![]),
        dir.path(),
        limits(1, 0),
        &ShaiConfig::default(),
    );
    let secret = "ollama-custom-secret-key";
    // Absent from the session config and from the test environment.
    assert!(advisor
        .reviewer()
        .redactor
        .redact(&format!("tool said {secret}"))
        .contains(secret));
    let advisor = advisor.include_settings([("OLLAMA_API_KEY", secret)]);
    let sent = advisor
        .reviewer()
        .redactor
        .redact(&format!("tool said {secret} as bare text"));
    assert!(!sent.contains(secret), "{sent}");
    assert!(sent.contains("[redacted]"), "{sent}");
}

#[test]
fn an_empty_shai_dir_override_does_not_refuse_the_project() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("README.md"), "ok\n").unwrap();
    let advisor = Advisor::with_environment(
        BoundModel::new(Script::new(vec![]).client(ADVISOR), ADVISOR_MODEL),
        dir.path(),
        limits(1, 0),
        &ShaiConfig::default(),
        vec![
            ("SHAI_LOG_DIR".to_string(), String::new()),
            ("SHAI_SESSION_FOLDER".to_string(), String::new()),
        ],
    )
    .expect("an empty override is ignored, the advisor starts");
    let (bytes, _) = advisor
        .reviewer()
        .fs
        .read("README.md", 1024)
        .expect("the project is still readable");
    assert_eq!(bytes, b"ok\n");
}

#[test]
fn a_second_review_cannot_be_reserved_before_the_cooldown_elapses() {
    let dir = TempDir::new().unwrap();
    let advisor = advisor_on(
        &Script::new(vec![]),
        dir.path(),
        limits(3, 1),
        &ShaiConfig::default(),
    );
    assert!(advisor.take_call());
    assert!(!advisor.take_call());
    advisor.elapse_cooldown();
    assert!(advisor.take_call());
}

#[test]
fn the_first_review_stays_eligible_after_a_larger_cooldown_is_set() {
    let dir = TempDir::new().unwrap();
    let advisor = advisor_on(
        &Script::new(vec![]),
        dir.path(),
        limits(3, 2),
        &ShaiConfig::default(),
    );
    assert_eq!(advisor.calls_made(), 0);
    let renewed = advisor
        .renewed_with_environment(
            BoundModel::new(Script::new(vec![]).client(ADVISOR), ADVISOR_MODEL),
            dir.path(),
            limits(3, 5),
            &ShaiConfig::default(),
            environment(),
        )
        .unwrap();
    assert!(renewed.step_completed());
    assert!(renewed.take_call());
}
