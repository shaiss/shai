// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

//! Snapshot of the user's process environment, taken before
//! [`super::config::ShaiConfig::set_env_vars`] exports a provider's values.
//!
//! Role and prewalk clients may fill a missing API key from this snapshot
//! only, and only for a provider with a fixed official endpoint. They never
//! read the process environment after that export.

use std::collections::HashMap;
use std::sync::Mutex;

/// Standard API-key variables of providers that have a fixed official
/// endpoint. The snapshot stores and returns only these names.
pub(in crate::config) const SNAPSHOTTED_KEYS: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "MISTRAL_API_KEY",
    "OPENROUTER_API_KEY",
];

static USER_ENV: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

fn lock_snapshot() -> std::sync::MutexGuard<'static, Option<HashMap<String, String>>> {
    USER_ENV
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn is_snapped_key(key: &str) -> bool {
    SNAPSHOTTED_KEYS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(key))
}

fn read_process_standard_keys() -> HashMap<String, String> {
    let mut vars = HashMap::new();
    for &key in SNAPSHOTTED_KEYS {
        if let Ok(value) = std::env::var(key) {
            if !value.trim().is_empty() {
                vars.insert(key.to_string(), value);
            }
        }
    }
    vars
}

/// Capture the current process values of the standard provider key
/// variables, unless a snapshot already exists.
///
/// Must be called before any [`super::config::ShaiConfig::set_env_vars`]
/// write, so later exports cannot appear in the snapshot.
pub(in crate::config) fn capture_user_env() {
    let mut slot = lock_snapshot();
    if slot.is_some() {
        return;
    }
    *slot = Some(read_process_standard_keys());
}

/// The snapshot's value for `key`, or `None` if it was unset, blank, or
/// is not a standard official-endpoint key. Captures the snapshot on
/// first use if nothing has called [`capture_user_env`] yet.
///
/// This never reads the live process environment for the returned value.
pub(in crate::config) fn user_env_var(key: &str) -> Option<String> {
    if !is_snapped_key(key) {
        return None;
    }
    capture_user_env();
    let slot = lock_snapshot();
    slot.as_ref().and_then(|vars| {
        vars.iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.clone())
    })
}

#[cfg(test)]
pub(in crate::config) fn reset_user_env_snapshot() {
    *lock_snapshot() = None;
}
