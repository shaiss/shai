// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

//! Notices: events the user must be told about in one plain line.
//!
//! Each front-end shows them in its own way (a line in the TUI scrollback,
//! one line on stderr in headless mode), but the wording is shared so that
//! the same thing is said everywhere.

use crate::agent::AgentEvent;

/// The one-line notice for `event`, or `None` when the event is not a notice.
///
/// The text is plain: no colour codes and no line breaks.
pub fn notice_text(event: &AgentEvent) -> Option<String> {
    match event {
        AgentEvent::ModelSwitched { provider, model } => Some(format!(
            "prewalk: switched to {}/{}, the conversation continues there",
            provider, model
        )),
        AgentEvent::AdvisorNote { severity, note } => {
            Some(format!("advisor ({}): {}", severity, note))
        }
        AgentEvent::AdvisorFailed { error, disabled } => Some(if *disabled {
            format!(
                "advisor: review failed ({}); the advisor is off for the rest of this session",
                error
            )
        } else {
            format!("advisor: review failed ({})", error)
        }),
        _ => None,
    }
}

/// The notice shown when a session starts with an advisor.
pub fn advisor_on_notice(model: &str, max_calls: u32) -> String {
    format!(
        "advisor on: {} reviews this session's steps, read-only, at most {} times",
        model, max_calls
    )
}

/// The notice shown when an advisor that was asked for is not attached to
/// the agent that is starting. `reason` says why.
pub fn advisor_not_attached_notice(reason: &str) -> String {
    format!("advisor not attached: {}", reason)
}

/// The notice shown when the advisor of a session is given up while the
/// session is running, because it stopped resolving. `reason` says why.
pub fn advisor_off_notice(reason: &str) -> String {
    format!("advisor off for the rest of this session: {}", reason)
}

/// The notice shown when a session starts with a prewalk armed.
pub fn prewalk_armed_notice(target: &str) -> String {
    format!(
        "prewalk armed: this session moves to {} after its first edit, once it has a todo list",
        target
    )
}

/// The notice shown when a prewalk that was asked for is not armed on the
/// agent that is starting. `reason` says why.
pub fn prewalk_not_armed_notice(reason: &str) -> String {
    format!("prewalk not armed: {}", reason)
}

/// The notice shown when a prewalk that was armed is given up before it
/// happened, because its target stopped resolving. `reason` says why.
pub fn prewalk_disarmed_notice(reason: &str) -> String {
    format!(
        "prewalk disarmed, this session stays on its model: {}",
        reason
    )
}

/// The notice shown when an agent is started after the handoff of its
/// session has happened: it does not start on the target, and nothing moves
/// it there. `target` is where the earlier agent went.
pub fn prewalk_over_notice(target: &str) -> String {
    format!(
        "prewalk is over: the handoff to {} already happened in this session, and the agent starting now runs on its own model",
        target
    )
}

/// A notice as one line for a terminal, in the style of the start-up banner.
pub fn notice_line(notice: &str) -> String {
    format!("\x1b[2m\u{2591} {}\x1b[0m", notice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_model_switch_is_a_one_line_notice() {
        let text = notice_text(&AgentEvent::ModelSwitched {
            provider: "ollama".to_string(),
            model: "qwen3:8b".to_string(),
        })
        .expect("a switch must be announced");
        assert!(text.contains("ollama/qwen3:8b"), "{text}");
        assert_eq!(text.lines().count(), 1);
        assert!(!text.contains('\u{1b}'));

        let armed = prewalk_armed_notice("ollama/qwen3:8b");
        assert!(armed.contains("ollama/qwen3:8b"), "{armed}");
        assert_eq!(armed.lines().count(), 1);

        for notice in [
            prewalk_not_armed_notice("this agent cannot change model"),
            prewalk_disarmed_notice("role \"cheap\" is not configured"),
            prewalk_over_notice("ollama/qwen3:8b"),
        ] {
            assert!(notice.starts_with("prewalk "), "{notice}");
            assert_eq!(notice.lines().count(), 1);
            assert!(!notice.contains('\u{1b}'));
            // On a terminal it is still one line, dimmed.
            let line = notice_line(&notice);
            assert!(line.contains(&notice));
            assert_eq!(line.lines().count(), 1);
        }
    }

    #[test]
    fn advisor_events_are_one_line_notices() {
        let note = notice_text(&AgentEvent::AdvisorNote {
            severity: crate::advisor::Severity::Blocker,
            note: "this deletes the repository".to_string(),
        })
        .unwrap();
        assert_eq!(note, "advisor (blocker): this deletes the repository");

        let failed = |disabled| {
            notice_text(&AgentEvent::AdvisorFailed {
                error: "the review took too long".to_string(),
                disabled,
            })
            .unwrap()
        };
        assert_eq!(
            failed(false),
            "advisor: review failed (the review took too long)"
        );
        assert!(failed(true).ends_with("the advisor is off for the rest of this session"));

        let on = advisor_on_notice("openai/gpt-4o-mini", 10);
        assert!(
            on.contains("openai/gpt-4o-mini") && on.contains("10"),
            "{on}"
        );
        for text in [note, failed(true), on] {
            assert_eq!(text.lines().count(), 1);
        }
    }

    #[test]
    fn ordinary_events_are_not_notices() {
        assert!(notice_text(&AgentEvent::ThinkingStart).is_none());
        assert!(notice_text(&AgentEvent::UserInput {
            input: "hello".to_string()
        })
        .is_none());
    }
}
