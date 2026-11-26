// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

//! Configuration of the advisor (see [`crate::advisor`]).
//!
//! The advisor is off unless it is asked for, with `--advisor` or in the auth
//! config:
//!
//! ```jsonc
//! "roles": { "advisor": "anthropic/claude-haiku-4-5" },
//! "advisor": { "enabled": true, "max_calls": 10, "cooldown_turns": 2 }
//! ```
//!
//! It always runs on the model of the role named `advisor`. When it is asked
//! for but that role is missing or does not resolve, that is an error: the
//! advisor never falls back to the session's own model.

use super::config::ShaiConfig;
use super::roles::{BoundModel, RoleError};
use crate::advisor::AdvisorLimits;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Name of the role the advisor runs on.
pub const ADVISOR_ROLE: &str = "advisor";

/// Largest accepted `max_calls` and `cooldown_turns`.
const MAX_LIMIT: u32 = 10_000;

/// The `advisor` section of the auth config.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisorConfig {
    /// Run the advisor in every session.
    #[serde(default)]
    pub enabled: bool,
    /// Most reviews per session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_calls: Option<u32>,
    /// Completed steps to skip after each review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_turns: Option<u32>,
}

/// Why an advisor that was asked for cannot be set up.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AdvisorSetupError {
    /// The `advisor` section of the config does not have the expected shape,
    /// or the config has more than one.
    #[error("the \"advisor\" section of the config is invalid: expected a single {{\"enabled\": true|false, \"max_calls\": <number>, \"cooldown_turns\": <number>}}")]
    InvalidSection,

    /// A limit is outside the accepted range.
    #[error("advisor.{name} must be between 1 and {}", MAX_LIMIT)]
    LimitOutOfRange { name: &'static str },

    /// The advisor is on but there is no `advisor` role to run it on.
    #[error("the advisor is enabled but no \"{}\" role is configured; add it to \"roles\" in the config", ADVISOR_ROLE)]
    NoRole,

    /// The `advisor` role, or the config it lives in, cannot be used.
    #[error("cannot start the advisor: {0}")]
    Unresolved(#[source] RoleError),
}

/// Decide whether a new session gets an advisor, and with what.
///
/// `flag` is `--advisor`. `config` is the outcome of
/// [`ShaiConfig::load_for_roles`]: the user's own config, never the built-in
/// default.
///
/// Returns `Ok(None)` when the advisor was not asked for. When it was, the
/// result is either a model and limits ready to use, or an error. Nothing
/// here performs network I/O.
pub fn resolve_advisor(
    flag: bool,
    config: Result<&ShaiConfig, &RoleError>,
) -> Result<Option<(BoundModel, AdvisorLimits)>, AdvisorSetupError> {
    let config = match config {
        Ok(config) => config,
        // Without a flag, a config that cannot be loaded cannot have asked
        // for anything.
        Err(_) if !flag => return Ok(None),
        Err(error) => return Err(AdvisorSetupError::Unresolved(error.clone())),
    };

    // An unreadable section is an error even without the flag: it may be
    // what was meant to turn the advisor on, or to bound it.
    let section = config
        .advisor
        .get()
        .map_err(|_| AdvisorSetupError::InvalidSection)?
        .unwrap_or_default();
    if !flag && !section.enabled {
        return Ok(None);
    }

    let defaults = AdvisorLimits::default();
    let limits = AdvisorLimits {
        max_calls: limit("max_calls", section.max_calls, defaults.max_calls)?,
        cooldown_turns: limit(
            "cooldown_turns",
            section.cooldown_turns,
            defaults.cooldown_turns,
        )?,
    };

    let resolved = config
        .resolve_role(ADVISOR_ROLE)
        .map_err(AdvisorSetupError::Unresolved)?
        .ok_or(AdvisorSetupError::NoRole)?;
    let bound = resolved.bind().map_err(AdvisorSetupError::Unresolved)?;
    Ok(Some((bound, limits)))
}

/// A limit from the config, or its default. Both limits start at 1: a cap of
/// zero would be a second way to say "off", and a cooldown of zero would have
/// the advisor comment on every step.
fn limit(name: &'static str, value: Option<u32>, default: u32) -> Result<u32, AdvisorSetupError> {
    match value {
        None => Ok(default),
        Some(value) if (1..=MAX_LIMIT).contains(&value) => Ok(value),
        Some(_) => Err(AdvisorSetupError::LimitOutOfRange { name }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json_tail: &str) -> ShaiConfig {
        serde_json::from_str(&format!(
            r#"{{
                "providers": [
                    {{"provider": "openai", "env_vars": {{"OPENAI_API_KEY": "k"}}, "model": "gpt-4o", "tool_method": "FunctionCall"}}
                ],
                "selected_provider": 0
                {json_tail}
            }}"#
        ))
        .expect("config should load")
    }

    const ROLE: &str = r#", "roles": {"advisor": "openai/gpt-4o-mini"}"#;

    fn setup(
        flag: bool,
        config: &ShaiConfig,
    ) -> Result<Option<(String, AdvisorLimits)>, AdvisorSetupError> {
        resolve_advisor(flag, Ok(config))
            .map(|found| found.map(|(model, limits)| (model.label(), limits)))
    }

    #[test]
    fn off_by_default() {
        // No section, no flag: off, with or without an advisor role.
        assert_eq!(setup(false, &config("")), Ok(None));
        assert_eq!(setup(false, &config(ROLE)), Ok(None));
        for section in [
            r#", "advisor": {}"#,
            r#", "advisor": {"enabled": false}"#,
            r#", "advisor": {"max_calls": 3}"#,
            r#", "advisor": null"#,
        ] {
            assert_eq!(setup(false, &config(&format!("{ROLE}{section}"))), Ok(None));
        }
        // No usable config and no flag: nothing was asked for.
        assert!(matches!(
            resolve_advisor(false, Err(&RoleError::ConfigMissing)),
            Ok(None)
        ));
    }

    #[test]
    fn the_flag_or_the_config_turns_it_on_with_the_advisor_role() {
        let expected = Ok(Some((
            "openai/gpt-4o-mini".to_string(),
            AdvisorLimits::default(),
        )));
        assert_eq!(setup(true, &config(ROLE)), expected);
        let enabled = config(&format!(r#"{ROLE}, "advisor": {{"enabled": true}}"#));
        assert_eq!(setup(false, &enabled), expected);
        // The flag turns it on even where the config says off.
        let disabled = config(&format!(r#"{ROLE}, "advisor": {{"enabled": false}}"#));
        assert_eq!(setup(true, &disabled), expected);

        let defaults = AdvisorLimits::default();
        assert_eq!(defaults.max_calls, 10);
        assert_eq!(defaults.cooldown_turns, 2);
    }

    #[test]
    fn limits_can_be_set_in_the_config() {
        let cfg = config(&format!(
            r#"{ROLE}, "advisor": {{"enabled": true, "max_calls": 3, "cooldown_turns": 5}}"#
        ));
        let (_, limits) = setup(false, &cfg).unwrap().unwrap();
        assert_eq!(
            limits,
            AdvisorLimits {
                max_calls: 3,
                cooldown_turns: 5
            }
        );
        // They also apply when the flag is what turns the advisor on.
        let cfg = config(&format!(r#"{ROLE}, "advisor": {{"max_calls": 1}}"#));
        let (_, limits) = setup(true, &cfg).unwrap().unwrap();
        assert_eq!(limits.max_calls, 1);
        assert_eq!(limits.cooldown_turns, 2);
    }

    #[test]
    fn limits_out_of_range_are_refused() {
        for (section, name) in [
            (r#"{"enabled": true, "max_calls": 0}"#, "max_calls"),
            (r#"{"enabled": true, "max_calls": 10001}"#, "max_calls"),
            // A cooldown of zero would comment on every step.
            (
                r#"{"enabled": true, "cooldown_turns": 0}"#,
                "cooldown_turns",
            ),
            (
                r#"{"enabled": true, "cooldown_turns": 10001}"#,
                "cooldown_turns",
            ),
        ] {
            let cfg = config(&format!(r#"{ROLE}, "advisor": {section}"#));
            let error = setup(false, &cfg).unwrap_err();
            assert_eq!(
                error,
                AdvisorSetupError::LimitOutOfRange { name },
                "{section}"
            );
            assert!(error.to_string().contains(&format!("advisor.{name}")));
        }
    }

    #[test]
    fn enabled_without_a_usable_advisor_role_is_an_error() {
        // No role at all: never the session's own model instead.
        assert_eq!(setup(true, &config("")), Err(AdvisorSetupError::NoRole));
        let enabled = config(r#", "advisor": {"enabled": true}"#);
        assert_eq!(setup(false, &enabled), Err(AdvisorSetupError::NoRole));
        // Other roles do not stand in for it.
        let other = config(r#", "roles": {"cheap": "openai/gpt-4o-mini"}"#);
        assert_eq!(setup(true, &other), Err(AdvisorSetupError::NoRole));

        // A role that does not resolve.
        for roles in [
            r#", "roles": {"advisor": "anthropic/claude-haiku-4-5"}"#,
            r#", "roles": {"advisor": "gpt-4o-mini"}"#,
            r#", "roles": {"advisor": {"provider": "openai", "api_key": "k"}}"#,
        ] {
            let error = setup(true, &config(roles)).unwrap_err();
            assert!(
                matches!(error, AdvisorSetupError::Unresolved(_)),
                "{roles}: {error:?}"
            );
            assert!(error.to_string().starts_with("cannot start the advisor: "));
        }

        // The flag without a usable config: never the built-in default.
        assert_eq!(
            resolve_advisor(true, Err(&RoleError::ConfigMissing)).map(|_| ()),
            Err(AdvisorSetupError::Unresolved(RoleError::ConfigMissing))
        );
    }

    #[test]
    fn invalid_section_is_an_error_and_does_not_break_the_config() {
        for section in [
            r#""on""#,
            r#"true"#,
            r#"{"enabled": "yes"}"#,
            r#"{"enable": true}"#,
            r#"{"enabled": true, "max_calls": -1}"#,
            r#"{"enabled": true, "max_calls": "many"}"#,
            r#"[true, 10, 2]"#,
            // Written twice, as after a careless paste: neither copy is used.
            r#"{"enabled": true}, "advisor": {"enabled": true}"#,
            r#"{"enabled": false}, "advisor": {"enabled": true}"#,
        ] {
            let cfg = config(&format!(r#"{ROLE}, "advisor": {section}"#));
            // The primary provider still loads...
            assert_eq!(cfg.get_selected_provider().unwrap().provider, "openai");
            // ...and the advisor refuses to guess what was meant, with or
            // without the flag.
            for flag in [false, true] {
                assert_eq!(
                    setup(flag, &cfg),
                    Err(AdvisorSetupError::InvalidSection),
                    "{section}"
                );
            }
        }
    }

    #[test]
    fn section_survives_a_save_and_is_absent_when_unset() {
        let cfg = config(&format!(
            r#"{ROLE}, "advisor": {{"enabled": true, "max_calls": 3}}"#
        ));
        let saved = serde_json::to_string(&cfg).unwrap();
        assert!(
            saved.ends_with(r#""advisor":{"enabled": true, "max_calls": 3}}"#),
            "{saved}"
        );
        let reloaded: ShaiConfig = serde_json::from_str(&saved).unwrap();
        assert_eq!(reloaded.advisor, cfg.advisor);

        let saved = serde_json::to_string(&config("")).unwrap();
        assert!(!saved.contains("advisor"), "{saved}");
    }
}
