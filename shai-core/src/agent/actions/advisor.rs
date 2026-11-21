// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

//! Running advisor reviews from the agent loop.
//!
//! A review happens at a step boundary: every tool result of the step is in
//! the trace and the next LLM call has not started. The agent then spends a
//! `Processing` phase waiting for the advisor, exactly as it does for its own
//! brain or tools, so the wait can be cancelled the same way and the loop
//! keeps serving commands meanwhile.
//!
//! The advisor itself only ever receives a text digest. What comes back is a
//! note for the next step and an event for the user; the trace, the todo list
//! and the permission state are not touched here.

use crate::advisor::digest::build_digest;
use crate::advisor::review::{sanitize_line, MAX_FAILURE_CHARS};
use crate::advisor::{Advisor, AdvisorNote};
use crate::agent::{AgentCore, AgentError, AgentEvent, InternalAgentEvent, InternalAgentState};
use chrono::Utc;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// Why an advisor cannot be attached to an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AdvisorAttachError {
    /// The agent's brain does not show advisor notes to its model: reviews
    /// would be paid for and never reach the agent they are meant for.
    #[error("this agent does not take notes from an advisor")]
    NoNotes,
}

/// Name of the processing phase spent waiting for the advisor.
pub(crate) const ADVISOR_TASK: &str = "advisor";

/// The advisor of one agent, with what the agent keeps about its reviews.
///
/// What the session has spent of the advisor (reviews, cooldown, failures)
/// is in the [`Advisor`] handle, which outlives the agent. What is here is
/// about this agent's conversation.
pub(crate) struct AdvisorSession {
    advisor: Advisor,
    /// Length of the trace up to which a review has succeeded.
    reviewed_upto: usize,
    pending: Option<(u64, usize)>,
    /// A note waiting to be shown to the agent at its next step.
    note: Option<AdvisorNote>,
}

impl AdvisorSession {
    pub(crate) fn new(advisor: Advisor) -> Self {
        Self {
            advisor,
            reviewed_upto: 0,
            pending: None,
            note: None,
        }
    }
}

impl AgentCore {
    /// Attach an advisor to this agent, replacing the one it had.
    ///
    /// Refused, leaving the agent without an advisor, when its brain would
    /// not pass the notes on. The caller is expected to tell the user.
    pub fn set_advisor(&mut self, mut advisor: Advisor) -> Result<(), AdvisorAttachError> {
        if !self.redaction_secrets.is_empty() {
            advisor = advisor.include_settings(
                self.redaction_secrets
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            );
        }
        self.advisor = None;
        // Nothing else holds the brain before the agent runs. If something
        // does, the question cannot be answered, and the answer is no.
        let takes_notes = self
            .brain
            .try_read()
            .map(|brain| brain.takes_advisor_notes())
            .unwrap_or(false);
        if !takes_notes {
            return Err(AdvisorAttachError::NoNotes);
        }
        self.advisor = Some(AdvisorSession::new(advisor));
        Ok(())
    }

    /// True when this agent has an advisor that may still run.
    pub fn has_advisor(&self) -> bool {
        self.advisor
            .as_ref()
            .is_some_and(|session| !session.advisor.is_off())
    }

    /// The advisor's note for the step about to start, if there is one.
    ///
    /// The note is handed over once. If the request that carries it fails or
    /// is interrupted, it is not repeated: by then it is about a moment the
    /// conversation has left, and the user has been shown it either way.
    pub(crate) fn take_advisor_note(&mut self) -> Option<String> {
        self.advisor
            .as_mut()
            .and_then(|session| session.note.take())
            .map(|note| note.for_agent())
    }

    /// The trace was cut back to `len` messages, as when the user asks for
    /// an answer again. What the agent does from there has not been
    /// reviewed, wherever the previous review had got to, and a note about
    /// what was removed has nothing left to be about.
    pub(crate) fn advisor_rewound(&mut self, len: usize) {
        if let Some(session) = self.advisor.as_mut() {
            session.reviewed_upto = session.reviewed_upto.min(len);
            session.note = None;
        }
    }

    /// At a step boundary, start a review if one is due.
    ///
    /// Returns true when a review was started; the agent is then in a
    /// `Processing` phase until [`AgentCore::finish_advisor_review`] runs.
    pub(crate) async fn start_advisor_review(&mut self) -> bool {
        let Some(session) = self.advisor.as_mut() else {
            return false;
        };
        // Switched off, out of reviews or in the cooldown of the last one:
        // the conversation is not even read.
        if !session.advisor.step_completed() {
            return false;
        }

        let reviewer = session.advisor.reviewer();
        let review_timeout = session.advisor.review_timeout();
        let trace = self.tool_ctx.trace.read().await.clone();
        // No step to show, no review: the session's budget is for reviews
        // that have something to look at.
        let Some(digest) = build_digest(&trace, session.reviewed_upto, &reviewer.redactor) else {
            return false;
        };
        // A review is taken out of the budget last, so that nothing above
        // uses it up, and in one step: another agent of the session may
        // have taken the last one since the budget was looked at.
        if !session.advisor.take_call() {
            return false;
        }
        self.next_review_id += 1;
        let review_id = self.next_review_id;
        session.pending = Some((review_id, trace.len()));

        let results = self.tool_ctx.internal_tx.clone();
        let cancellation_token = CancellationToken::new();
        let cancelled = cancellation_token.clone();
        tokio::spawn(async move {
            tokio::select! {
                outcome = tokio::time::timeout(review_timeout, reviewer.review(&digest)) => {
                    let outcome = outcome
                        .unwrap_or_else(|_| Err("the review took too long".to_string()));
                    let _ = results.send(InternalAgentEvent::AdvisorCompleted { review_id, outcome });
                }
                _ = cancelled.cancelled() => {}
            }
        });

        self.set_state(InternalAgentState::Processing {
            task_name: ADVISOR_TASK.to_string(),
            tools_exec_at: Utc::now(),
            cancellation_token,
        })
        .await;
        true
    }

    /// Take the result of a review and let the agent continue.
    pub(crate) async fn finish_advisor_review(
        &mut self,
        review_id: u64,
        outcome: Result<Option<AdvisorNote>, String>,
    ) -> Result<(), AgentError> {
        let waiting = matches!(
            &self.state,
            InternalAgentState::Processing { task_name, .. } if task_name == ADVISOR_TASK
        );
        let Some(session) = self.advisor.as_mut() else {
            return Ok(());
        };
        // A result for a review the agent stopped waiting for (the user
        // spoke, or the task was stopped) is dropped: it must not move the
        // agent out of whatever it is doing now.
        let reviewed_upto = match session.pending {
            Some((pending, upto)) if waiting && pending == review_id => upto,
            _ => {
                debug!(target: "agent::advisor", review_id, "dropping a late advisor result");
                return Ok(());
            }
        };
        session.pending = None;

        let failed = outcome.is_err();
        let switched_off = session.advisor.review_ended(failed);
        let event = match outcome {
            Ok(note) => {
                // Only a review that came back counts as having looked at
                // these steps: after a failed one they are shown again.
                session.reviewed_upto = reviewed_upto;
                session.note = note.clone();
                note.map(|note| AgentEvent::AdvisorNote {
                    severity: note.severity,
                    note: note.text,
                })
            }
            Err(reason) => Some(AgentEvent::AdvisorFailed {
                // Reasons made up by the reviewer are plain already; this
                // is for the ones that are not.
                error: sanitize_line(&reason, MAX_FAILURE_CHARS),
                disabled: switched_off || session.advisor.is_off(),
            }),
        };
        if let Some(event) = event {
            let _ = self.emit_event(event).await;
        }

        self.set_state(InternalAgentState::Running).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisor::{AdvisorLimits, Severity};
    use crate::agent::scripted_llm::Script;
    use crate::agent::AgentBuilder;
    use crate::config::config::ShaiConfig;
    use crate::config::roles::BoundModel;
    use crate::runners::coder::CoderBrain;

    /// An agent that is never run, with an advisor that is never asked.
    fn agent_with_an_advisor(dir: &std::path::Path) -> AgentCore {
        let script = Script::new(vec![]);
        let advisor = Advisor::with_environment(
            BoundModel::new(script.client("advisor"), "advisor-model"),
            dir,
            AdvisorLimits::default(),
            &ShaiConfig::default(),
            Vec::new(),
        )
        .expect("advisor");
        let brain = CoderBrain::new(script.client("main"), "main-model".to_string());
        let mut agent = AgentBuilder::with_brain(Box::new(brain)).build();
        agent
            .set_advisor(advisor)
            .expect("the coder brain takes advisor notes");
        agent
    }

    fn a_note() -> AdvisorNote {
        AdvisorNote {
            severity: Severity::Concern,
            text: "the tests were not run".to_string(),
        }
    }

    fn session(agent: &mut AgentCore) -> &mut AdvisorSession {
        agent.advisor.as_mut().expect("an advisor is attached")
    }

    #[test]
    fn a_waiting_note_is_handed_over_once() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut agent = agent_with_an_advisor(dir.path());
        assert!(agent.take_advisor_note().is_none());

        session(&mut agent).note = Some(a_note());
        assert_eq!(agent.take_advisor_note(), Some(a_note().for_agent()));
        assert!(agent.take_advisor_note().is_none());
    }

    #[test]
    fn a_rewind_drops_the_waiting_note_and_what_was_reviewed_past_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut agent = agent_with_an_advisor(dir.path());
        session(&mut agent).note = Some(a_note());
        session(&mut agent).reviewed_upto = 6;

        // The conversation is cut back to before the steps the note is
        // about: the note has nothing left to be about, and those steps
        // count as not looked at when they are done again.
        agent.advisor_rewound(2);
        assert!(agent.take_advisor_note().is_none());
        assert_eq!(session(&mut agent).reviewed_upto, 2);

        // A cut that leaves everything reviewed in place moves nothing.
        agent.advisor_rewound(40);
        assert_eq!(session(&mut agent).reviewed_upto, 2);
    }

    #[test]
    fn review_ids_stay_unique_when_the_advisor_is_reattached() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut agent = agent_with_an_advisor(dir.path());
        agent.next_review_id = 7;
        let script = Script::new(vec![]);
        let advisor = Advisor::with_environment(
            BoundModel::new(script.client("advisor"), "advisor-model"),
            dir.path(),
            AdvisorLimits::default(),
            &ShaiConfig::default(),
            Vec::new(),
        )
        .expect("advisor");
        agent
            .set_advisor(advisor)
            .expect("the coder brain takes advisor notes");
        assert_eq!(agent.next_review_id, 7);
        assert!(agent.has_advisor());
    }
}
