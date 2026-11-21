// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

//! The digest of recent agent steps that an advisor review is given.
//!
//! The advisor is shown as little as it needs: the user's latest request and
//! what the agent did since the previous review. Not the system prompt (which
//! describes the machine), not earlier parts of the conversation, not the
//! agent's private reasoning.
//!
//! Each piece is redacted on its own and then cut to a bounded size, in that
//! order: a secret is removed while it is whole, and what a redaction takes
//! out can never reach into the next piece.

use super::redact::Redactor;
use openai_dive::v1::resources::chat::{ChatMessage, ChatMessageContent};
use std::collections::HashMap;

/// A digest as [`build_digest`] put it together: every piece of it went
/// through the redactor on its own before it was added.
///
/// Only this module can make one, so a review cannot be handed text that
/// skipped redaction, and it has no reason to redact the whole a second
/// time. A second pass over the assembled text would not read it as the
/// first one did: the arguments of a tool call are JSON by then, with their
/// quotes and line breaks escaped, and ordinary code the first pass rightly
/// left alone could be taken for a secret and hidden from the review.
#[derive(Debug)]
pub(crate) struct RedactedDigest(String);

impl RedactedDigest {
    /// The text to send to the advisor.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Most characters of the user's request shown to the advisor.
const MAX_REQUEST_CHARS: usize = 2_000;
/// Most characters of one agent message shown.
const MAX_MESSAGE_CHARS: usize = 1_500;
/// Most characters of one tool call's arguments shown.
const MAX_ARGUMENT_CHARS: usize = 1_200;
/// Most characters of one tool result shown.
const MAX_RESULT_CHARS: usize = 2_000;
/// Most characters of the steps section. Older steps are dropped first.
const MAX_STEPS_CHARS: usize = 12_000;

fn clip(text: &str, max: usize) -> String {
    let text = text.trim();
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let cut: String = text.chars().take(max).collect();
        format!("{cut} [...]")
    }
}

/// Redact and clip the user's request messages, keeping the latest one
/// when the joined text would exceed [`MAX_REQUEST_CHARS`]. Earlier
/// context is added only if it fits, in the original order.
fn clip_request<'a>(
    messages: impl IntoIterator<Item = &'a str>,
    redactor: &Redactor,
) -> Vec<String> {
    let messages: Vec<String> = messages
        .into_iter()
        .map(|text| redactor.redact(text))
        .collect();
    if messages.is_empty() {
        return Vec::new();
    }
    let latest = clip(messages.last().unwrap(), MAX_REQUEST_CHARS);
    let latest_len = latest.chars().count();
    let mut kept = vec![latest];
    let mut used = latest_len;
    // Walk earlier messages from newest to oldest, then restore order.
    for text in messages.iter().rev().skip(1) {
        let candidate = clip(text, MAX_REQUEST_CHARS);
        let size = candidate.chars().count();
        // A blank line is inserted between messages when they are joined.
        let gap = 2;
        if used + gap + size > MAX_REQUEST_CHARS {
            break;
        }
        used += gap + size;
        kept.push(candidate);
    }
    kept.reverse();
    kept
}

fn text_of(content: &ChatMessageContent) -> Option<&str> {
    match content {
        ChatMessageContent::Text(text) => Some(text),
        _ => None,
    }
}

/// Describe `trace[since..]` for the advisor, with the user's latest request
/// as context. `since` is the length the trace had at the previous review.
///
/// Returns `None` when the agent has done nothing since then that could be
/// reviewed: there is no step to show.
pub(crate) fn build_digest(
    trace: &[ChatMessage],
    since: usize,
    redactor: &Redactor,
) -> Option<RedactedDigest> {
    // The request is the user's last message, together with the messages
    // that came right before it without the agent answering in between: a
    // prompt and the text piped along with it are one request.
    let last_user = trace
        .iter()
        .rposition(|message| matches!(message, ChatMessage::User { .. }));
    let first_user = last_user.map(|last| {
        trace[..last]
            .iter()
            .rposition(|message| !matches!(message, ChatMessage::User { .. }))
            .map_or(0, |index| index + 1)
    });
    let request: Vec<String> = match (first_user, last_user) {
        (Some(first), Some(last)) => clip_request(
            trace[first..=last]
                .iter()
                .filter_map(|message| match message {
                    ChatMessage::User { content, .. } => text_of(content),
                    _ => None,
                }),
            redactor,
        ),
        _ => Vec::new(),
    };

    // Never reach back before the current request, and tolerate a trace that
    // got shorter since the previous review.
    let after_request = last_user.map_or(0, |index| index + 1);
    let start = since.min(trace.len()).max(after_request);

    // Tool results only carry a call id: recover the tool names.
    let mut tool_names: HashMap<&str, &str> = HashMap::new();
    for message in trace {
        if let ChatMessage::Assistant {
            tool_calls: Some(calls),
            ..
        } = message
        {
            for call in calls {
                tool_names.insert(call.id.as_str(), call.function.name.as_str());
            }
        }
    }

    let mut entries: Vec<String> = Vec::new();
    for message in &trace[start..] {
        match message {
            ChatMessage::Assistant {
                content,
                tool_calls,
                ..
            } => {
                let mut entry = String::from("Agent:");
                if let Some(text) = content.as_ref().and_then(text_of) {
                    if !text.trim().is_empty() {
                        entry.push(' ');
                        entry.push_str(&clip(&redactor.redact(text), MAX_MESSAGE_CHARS));
                    }
                }
                for call in tool_calls.iter().flatten() {
                    entry.push_str(&format!(
                        "\n  calls {} with {}",
                        redactor.redact(&call.function.name),
                        clip(
                            &redactor.redact_json(&call.function.arguments),
                            MAX_ARGUMENT_CHARS
                        )
                    ));
                }
                entries.push(entry);
            }
            ChatMessage::Tool {
                tool_call_id,
                content,
            } => {
                let name = tool_names.get(tool_call_id.as_str()).unwrap_or(&"tool");
                entries.push(format!(
                    "Result of {}:\n{}",
                    redactor.redact(name),
                    clip(
                        &redactor.redact(text_of(content).unwrap_or("")),
                        MAX_RESULT_CHARS
                    )
                ));
            }
            ChatMessage::System { content, .. } => {
                entries.push(format!(
                    "Harness message:\n{}",
                    clip(
                        &redactor.redact(text_of(content).unwrap_or("")),
                        MAX_MESSAGE_CHARS
                    )
                ));
            }
            _ => {}
        }
    }
    if entries.is_empty() {
        return None;
    }

    // Keep the most recent steps when there is too much to show.
    let mut kept: Vec<String> = Vec::new();
    let mut used = 0;
    let mut dropped = false;
    for entry in entries.into_iter().rev() {
        let size = entry.chars().count();
        if used + size > MAX_STEPS_CHARS && !kept.is_empty() {
            dropped = true;
            break;
        }
        used += size;
        kept.push(entry);
    }
    kept.reverse();

    let mut digest = format!(
        "## The user's request\n{}\n\n## What the agent did since your last review\n",
        // Messages were selected so the latest request always fits and
        // earlier context is included only when it does. Already redacted.
        request.join("\n\n")
    );
    if dropped {
        digest.push_str("[earlier steps omitted]\n\n");
    }
    digest.push_str(&kept.join("\n\n"));
    Some(RedactedDigest(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::scripted_llm::{call, text};
    use serde_json::json;

    fn user(content: &str) -> ChatMessage {
        ChatMessage::User {
            content: ChatMessageContent::Text(content.to_string()),
            name: None,
        }
    }

    /// The tool message answering the single call of `assistant`.
    fn result_of(assistant: &ChatMessage, content: &str) -> ChatMessage {
        let ChatMessage::Assistant {
            tool_calls: Some(calls),
            ..
        } = assistant
        else {
            panic!("not a tool call");
        };
        ChatMessage::Tool {
            tool_call_id: calls[0].id.clone(),
            content: ChatMessageContent::Text(content.to_string()),
        }
    }

    /// The text of the digest `redactor` leaves of `trace`.
    fn digest_text(trace: &[ChatMessage], since: usize, redactor: &Redactor) -> Option<String> {
        build_digest(trace, since, redactor).map(|digest| digest.as_str().to_string())
    }

    /// A digest with nothing to redact.
    fn plain_digest(trace: &[ChatMessage], since: usize) -> Option<String> {
        digest_text(trace, since, &Redactor::default())
    }

    fn session() -> Vec<ChatMessage> {
        let read = call("read", json!({"files": [{"path": "src/lib.rs"}]}));
        let read_result = result_of(&read, "fn old() {}");
        let edit = call("edit", json!({"files": [{"path": "src/lib.rs"}]}));
        let edit_result = result_of(&edit, "1 edit applied");
        vec![
            user("earlier request"),
            text("earlier answer"),
            user("rename old to new"),
            read,
            read_result,
            edit,
            edit_result,
        ]
    }

    #[test]
    fn shows_the_current_request_and_the_steps_since_the_last_review() {
        let trace = session();
        let digest = plain_digest(&trace, 0).unwrap();

        assert!(digest.starts_with("## The user's request\nrename old to new\n"));
        // Nothing from before the current request.
        assert!(!digest.contains("earlier"), "{digest}");
        // Each call with its arguments, each result with the tool's name.
        assert!(digest.contains(r#"calls read with {"files":[{"path":"src/lib.rs"}]}"#));
        assert!(digest.contains("Result of read:\nfn old() {}"), "{digest}");
        assert!(
            digest.contains("Result of edit:\n1 edit applied"),
            "{digest}"
        );

        // A later review only gets what is new.
        let digest = plain_digest(&trace, 5).unwrap();
        assert!(digest.contains("rename old to new"));
        assert!(!digest.contains("Result of read"), "{digest}");
        assert!(
            digest.contains("Result of edit:\n1 edit applied"),
            "{digest}"
        );
    }

    #[test]
    fn there_is_no_digest_without_a_step_to_show() {
        let trace = session();
        // Everything was reviewed already.
        assert_eq!(plain_digest(&trace, trace.len()), None);
        // The trace got shorter since the last review, as after a
        // regenerate, and nothing has been done again yet.
        assert_eq!(plain_digest(&trace[..3], 40), None);
        // Nothing but the request, or nothing at all.
        assert_eq!(plain_digest(&[user("go")], 0), None);
        assert_eq!(plain_digest(&[], 3), None);

        // Once the agent has acted again, those steps are shown, wherever
        // the previous review had got to.
        let digest = plain_digest(&trace[..5], 40);
        assert_eq!(digest, None);
        let digest = plain_digest(&trace[..5], 3).unwrap();
        assert!(digest.contains("Result of read"), "{digest}");
    }

    #[test]
    fn a_request_made_of_several_messages_is_shown_whole() {
        // Headless mode sends the prompt and the piped text as two messages.
        let list = call("ls", json!({"directory": "."}));
        let trace = vec![
            user("earlier request"),
            text("earlier answer"),
            user("explain what this log says"),
            user("ERROR disk full on /dev/sda1"),
            list.clone(),
            result_of(&list, "a.txt"),
        ];
        let digest = plain_digest(&trace, 0).unwrap();
        assert!(
            digest.starts_with(
                "## The user's request\nexplain what this log says\n\nERROR disk full on /dev/sda1\n"
            ),
            "{digest}"
        );
        assert!(!digest.contains("earlier"), "{digest}");
    }

    #[test]
    fn a_request_of_many_messages_is_clipped_as_a_whole() {
        let list = call("ls", json!({"directory": "."}));
        let mut trace: Vec<ChatMessage> = (0..50)
            .map(|i| user(&format!("{i:02} {}", "x".repeat(1_900))))
            .collect();
        trace.push(list.clone());
        trace.push(result_of(&list, "a.txt"));
        let digest = plain_digest(&trace, 0).unwrap();
        let request = digest
            .strip_prefix("## The user's request\n")
            .and_then(|rest| rest.split("\n\n## What the agent did").next())
            .unwrap();
        assert!(
            request.chars().count() <= MAX_REQUEST_CHARS + " [...]".len(),
            "{}",
            request.chars().count()
        );
        // The latest message is kept; earlier context does not fit.
        assert!(request.starts_with("49 "), "{request}");
        assert!(request.ends_with(" [...]"), "{request}");
        assert!(!request.contains("00 "), "{request}");
        assert!(digest.contains("calls ls"), "{digest}");
    }

    #[test]
    fn a_short_latest_message_is_kept_when_earlier_context_is_long() {
        let list = call("ls", json!({"directory": "."}));
        let trace = vec![
            user(&"context ".repeat(800)),
            user("do the rename now"),
            list.clone(),
            result_of(&list, "a.txt"),
        ];
        let digest = plain_digest(&trace, 0).unwrap();
        let request = digest
            .strip_prefix("## The user's request\n")
            .and_then(|rest| rest.split("\n\n## What the agent did").next())
            .unwrap();
        assert!(request.contains("do the rename now"), "{request}");
        assert!(
            request.chars().count() <= MAX_REQUEST_CHARS + " [...]".len(),
            "{}",
            request.chars().count()
        );
    }

    #[test]
    fn leaves_out_the_agents_reasoning() {
        let trace = vec![
            user("go"),
            ChatMessage::Assistant {
                content: Some(ChatMessageContent::Text("visible answer".to_string())),
                reasoning: Some("private thoughts".to_string()),
                reasoning_content: Some("more private thoughts".to_string()),
                tool_calls: None,
                name: None,
                audio: None,
                refusal: None,
            },
        ];
        let digest = plain_digest(&trace, 0).unwrap();
        assert!(digest.contains("Agent: visible answer"), "{digest}");
        assert!(!digest.contains("private"), "{digest}");
    }

    #[test]
    fn every_piece_and_the_whole_are_bounded() {
        let big = "x".repeat(50_000);
        let write = call("write", json!({"files": [{"path": "a", "content": big}]}));
        let write_result = result_of(&write, &big);
        let mut trace = vec![user(&big), write.clone(), write_result.clone()];
        let digest = plain_digest(&trace, 0).unwrap();
        assert!(digest.chars().count() < 6_000, "{}", digest.chars().count());
        assert!(digest.contains("[...]"));

        // Many steps: the most recent are kept, the oldest go.
        for index in 0..40 {
            let step = call("ls", json!({"directory": format!("dir-{index}")}));
            trace.push(result_of(&step, &"y".repeat(1_500)));
            trace.insert(trace.len() - 1, step);
        }
        let digest = plain_digest(&trace, 0).unwrap();
        assert!(
            digest.chars().count() < 16_000,
            "{}",
            digest.chars().count()
        );
        assert!(digest.contains("[earlier steps omitted]"));
        assert!(digest.contains("dir-39"));
        assert!(!digest.contains("dir-0\""), "{}", &digest[..300]);
    }

    #[test]
    fn a_secret_is_removed_whole_before_anything_is_cut() {
        const KEY: &str = "known-provider-key-0123456789";
        let redactor = Redactor::new([("SOME_API_KEY", KEY)], Vec::<(String, String)>::new(), &[]);
        // The secret sits across every limit a piece is cut at.
        let straddling = |limit: usize| format!("{}{KEY} tail", "x".repeat(limit - 10));
        let run = call("bash", json!({"command": straddling(MAX_ARGUMENT_CHARS)}));
        let trace = vec![
            user(&straddling(MAX_REQUEST_CHARS)),
            ChatMessage::Assistant {
                content: Some(ChatMessageContent::Text(straddling(MAX_MESSAGE_CHARS))),
                reasoning: None,
                reasoning_content: None,
                tool_calls: None,
                name: None,
                audio: None,
                refusal: None,
            },
            run.clone(),
            result_of(&run, &straddling(MAX_RESULT_CHARS)),
        ];
        let digest = digest_text(&trace, 0, &redactor).unwrap();
        // Not the key, and not the start of it left behind by a cut.
        assert!(!digest.contains("known-provider"), "{digest}");
        assert!(!digest.contains("known-"), "{digest}");
    }

    #[test]
    fn what_a_redaction_removes_stays_inside_its_own_step() {
        let redactor = Redactor::default();
        // A key printed without its end marker, as when a tool cut it, and
        // a quoted assignment inside the JSON of a call.
        let cat = call("bash", json!({"command": "cat deploy_key"}));
        let risky = call(
            "bash",
            json!({"command": "export DB_PASS=\"s3cret value\" && rm -rf build ../other"}),
        );
        let trace = vec![
            user("clean up"),
            cat.clone(),
            result_of(
                &cat,
                "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\nAAAAB3Nza",
            ),
            risky.clone(),
            result_of(&risky, "removed"),
        ];
        let digest = digest_text(&trace, 0, &redactor).unwrap();
        assert!(!digest.contains("b3Blbn"), "{digest}");
        assert!(!digest.contains("s3cret"), "{digest}");
        // The step after the key is still there for the advisor to see.
        assert!(digest.contains("rm -rf build ../other"), "{digest}");
        assert!(digest.contains("Result of bash:\nremoved"), "{digest}");
    }
}
