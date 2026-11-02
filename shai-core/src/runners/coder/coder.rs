use std::sync::Arc;

use async_trait::async_trait;
use openai_dive::v1::resources::chat::{
    ChatCompletionParametersBuilder, ChatMessage, ChatMessageContent,
};
use shai_llm::client::LlmClient;
use shai_llm::tool::LlmToolCall;
use tracing::debug;

use crate::agent::brain::ThinkerDecision;
use crate::agent::brain::ToolBudgetRef;
use crate::agent::{AgentBuilder, AgentCore, AgentError, Brain, ThinkerContext};
use crate::tools::types::{ContainsAnyTool, IntoToolBox};

use super::prompt::{get_todo_read, render_system_prompt_template, PLAN_MODE_PROMPT};
use crate::runners::compacter::compact_trace_if_needed;

#[derive(Clone)]
pub struct CoderBrain {
    pub llm: Arc<LlmClient>,
    pub model: String,
    pub system_prompt_template: String,
    pub temperature: f32,
    pub cached_prompt: Option<String>,
}

impl CoderBrain {
    pub fn new(llm: Arc<LlmClient>, model: String) -> Self {
        debug!(target: "brain::coder", provider =?llm.provider_name(), model = ?model);
        Self {
            llm,
            model,
            system_prompt_template: "{{CODER_BASE_PROMPT}}".to_string(),
            temperature: 0.0,
            cached_prompt: None,
        }
    }

    pub fn with_custom_prompt(
        llm: Arc<LlmClient>,
        model: String,
        system_prompt_template: String,
        temperature: f32,
    ) -> Self {
        debug!(target: "brain::coder", provider =?llm.provider_name(), model = ?model);
        Self {
            llm,
            model,
            system_prompt_template,
            temperature,
            cached_prompt: None,
        }
    }
}

#[async_trait]
impl Brain for CoderBrain {
    async fn next_step(
        &mut self,
        context: ThinkerContext,
        budget: ToolBudgetRef,
    ) -> Result<ThinkerDecision, AgentError> {
        let mut trace = context.trace.clone();

        // Apply session-level trace compaction if needed
        if context.max_trace_chars > 0 {
            let metadata = context.tool_call_metadata.read().await.clone();
            compact_trace_if_needed(&mut trace, context.max_trace_chars, &metadata);
        }

        // Render the user's system prompt template (cached after first call)
        let system_prompt = match &self.cached_prompt {
            Some(cached) => cached.clone(),
            None => {
                let rendered = render_system_prompt_template(&self.system_prompt_template);
                self.cached_prompt = Some(rendered.clone());
                rendered
            }
        };

        // Add todo status if available
        let mut system_prompt_full = system_prompt.clone();
        if let Some(tool) = context.available_tools.get_tool("todo_read") {
            let todo_status = get_todo_read(&tool).await;
            system_prompt_full += &todo_status;
        }

        // Add plan mode instructions
        if context.is_plan_mode {
            system_prompt_full += "\n\n";
            system_prompt_full += PLAN_MODE_PROMPT;
        }

        // Inject active system prompts
        if !context.active_prompts.is_empty() {
            let loaded = crate::tools::prompts::load_active_prompts(&context.active_prompts);
            for (name, body) in loaded {
                system_prompt_full += "\n\n--- Active system prompt: ";
                system_prompt_full += &name;
                system_prompt_full += " ---\n";
                system_prompt_full += &body;
            }
        }

        // Inject dynamic budget awareness hints
        let tool_calls = budget.count;
        if let Some(soft_budget) = budget.soft_limit {
            if tool_calls >= soft_budget {
                // Critical notice every 5 calls once soft budget is exceeded
                if tool_calls == soft_budget || (tool_calls - soft_budget).is_multiple_of(5) {
                    system_prompt_full += "\n\n--- CRITICAL ---\n";
                    system_prompt_full += &format!(
                        "You have made {} tool calls — you may be going too deep. Step back and assess whether you already have the information you need.",
                        tool_calls
                    );
                }
            } else if tool_calls >= soft_budget * 9 / 10 {
                system_prompt_full += "\n\n--- BUDGET WARNING ---\n";
                system_prompt_full += &format!(
                    "You have used {}/{} tool calls. Prioritize completing the task immediately.",
                    tool_calls, soft_budget
                );
            } else if tool_calls >= soft_budget * 7 / 10 {
                system_prompt_full += "\n\n--- Progress note ---\n";
                system_prompt_full += &format!(
                    "You have used {}/{} tool calls. Be efficient with your remaining calls.",
                    tool_calls, soft_budget
                );
            } else if tool_calls > 0 && tool_calls.is_multiple_of(5) {
                // Gentle reminder every 5 calls below soft budget
                system_prompt_full += "\n\n--- Progress Checkpoint ---\n";
                system_prompt_full += &format!(
                    "You have made {} tool calls so far. Briefly assess your progress: what have you accomplished, what remains, and what is the most efficient path forward?",
                    tool_calls
                );
            }
        } else {
            // No soft budget configured — use periodic checkpoint every 10 calls
            if tool_calls > 0 && tool_calls.is_multiple_of(10) {
                system_prompt_full += "\n\n--- Progress Checkpoint ---\n";
                system_prompt_full += &format!(
                    "You have made {} tool calls so far. Briefly assess your progress: what have you accomplished, what remains, and what is the most efficient path forward?",
                    tool_calls
                );
            }
        }

        trace.insert(
            0,
            ChatMessage::System {
                content: ChatMessageContent::Text(system_prompt_full),
                name: None,
            },
        );

        // get next step with custom temperature
        debug!(target: "brain::coder", temperature = context.temperature, "temperature");
        let request = ChatCompletionParametersBuilder::default()
            .model(&self.model)
            .messages(trace)
            .temperature(context.temperature)
            .build()
            .map_err(|e| AgentError::LlmError(e.to_string()))?;

        let brain_decision = self
            .llm
            .chat_with_tools(
                request,
                &context.available_tools.into_toolbox(),
                context.method,
            )
            .await
            .map_err(|e| AgentError::LlmError(shai_llm::describe_llm_error(&e.to_string())))?;

        // Extract token usage information
        let token_usage = brain_decision.usage.as_ref().map(|usage| {
            let input = usage.prompt_tokens.unwrap_or(0);
            let output = usage.completion_tokens.unwrap_or(0);
            let cached = usage
                .prompt_tokens_details
                .as_ref()
                .map(|d| d.cached_tokens)
                .unwrap_or(0);
            (input, output, cached)
        });

        debug!(target: "brain::coder", usage = ?brain_decision.usage, "LLM response usage");

        // stop here if there's no other tool calls
        let message = brain_decision.choices.into_iter().next().unwrap().message;
        if let ChatMessage::Assistant { tool_calls, .. } = &message {
            if tool_calls.as_ref().is_none_or(|calls| calls.is_empty()) {
                // A turn with neither tool calls nor any text would pause the
                // agent with nothing on screen: the user sees it "just stop".
                if let Some(err) = empty_response_error(&message) {
                    return Err(err);
                }
                return Ok(match token_usage {
                    Some((input_tokens, output_tokens, cached_tokens)) => {
                        ThinkerDecision::agent_pause_with_tokens(
                            message,
                            input_tokens,
                            output_tokens,
                            cached_tokens,
                        )
                    }
                    None => ThinkerDecision::agent_pause(message),
                });
            }
        }
        Ok(match token_usage {
            Some((input_tokens, output_tokens, cached_tokens)) => {
                ThinkerDecision::agent_continue_with_tokens(
                    message,
                    input_tokens,
                    output_tokens,
                    cached_tokens,
                )
            }
            None => ThinkerDecision::agent_continue(message),
        })
    }
}

/// Error for an assistant turn that carries no tool call, no text and no
/// reasoning. Small local models do this when stuck; without an error the agent
/// pauses silently (ovh/shai issue 101, "gets into a loop and quits").
/// Returns `None` when the message has something to show or is not an assistant turn.
pub(crate) fn empty_response_error(message: &ChatMessage) -> Option<AgentError> {
    let ChatMessage::Assistant {
        content,
        reasoning_content,
        tool_calls,
        ..
    } = message
    else {
        return None;
    };
    if tool_calls.as_ref().is_some_and(|calls| !calls.is_empty()) {
        return None;
    }
    let content_empty = content.as_ref().is_none_or(|c| match c {
        ChatMessageContent::Text(t) => t.trim().is_empty(),
        _ => false,
    });
    let reasoning_empty = reasoning_content
        .as_deref()
        .is_none_or(|r| r.trim().is_empty());
    (content_empty && reasoning_empty).then(|| {
        AgentError::InvalidResponse(
            "the model returned an empty response (no answer and no tool call), so the agent stopped. Send another message to continue, or try a different model.".to_string(),
        )
    })
}

/// Coder agent factory — returns AgentCore directly so callers can configure working_dir.
pub fn coder(llm: Arc<LlmClient>, model: String) -> AgentCore {
    let fs_log = Arc::new(crate::tools::FsOperationLog::new());
    let (tools, todo_storage) = AgentBuilder::create_default_tools(fs_log);

    AgentBuilder::with_brain(Box::new(CoderBrain::new(llm.clone(), model)))
        .tools(tools)
        .set_todo_storage(todo_storage)
        .build()
}

#[cfg(test)]
mod empty_response_tests {
    use super::*;
    use openai_dive::v1::resources::chat::{Function, ToolCall};

    fn assistant(
        content: Option<&str>,
        reasoning: Option<&str>,
        tool_calls: Option<Vec<ToolCall>>,
    ) -> ChatMessage {
        ChatMessage::Assistant {
            content: content.map(|c| ChatMessageContent::Text(c.to_string())),
            reasoning: None,
            reasoning_content: reasoning.map(String::from),
            refusal: None,
            name: None,
            audio: None,
            tool_calls,
        }
    }

    #[test]
    fn empty_turn_is_an_error_the_user_can_see() {
        for msg in [
            assistant(None, None, None),
            assistant(Some(""), None, None),
            assistant(Some("  \n\t"), Some(" "), Some(vec![])),
        ] {
            let err = empty_response_error(&msg).expect("empty turn must be reported");
            assert!(err.to_string().contains("empty response"), "{err}");
        }
    }

    #[test]
    fn turns_with_text_reasoning_or_tool_calls_pass() {
        let call = ToolCall {
            id: "1".into(),
            r#type: "function".into(),
            function: Function {
                name: "read".into(),
                arguments: "{}".into(),
            },
        };
        assert!(empty_response_error(&assistant(Some("done"), None, None)).is_none());
        assert!(empty_response_error(&assistant(None, Some("thinking"), None)).is_none());
        assert!(empty_response_error(&assistant(None, None, Some(vec![call]))).is_none());
    }
}
