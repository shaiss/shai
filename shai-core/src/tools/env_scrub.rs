//! Keep secrets out of subprocesses the model can drive.
//!
//! `ShaiConfig::set_env_vars` exports the selected provider's key (for example
//! `OPENROUTER_API_KEY`) into the shai process env, and a model-driven child
//! (the bash tool, post-edit verification) would otherwise inherit it and could
//! print it with `env`. Callers remove these names on the spawned `Command`
//! with `env_remove`; the shai process env itself is left alone.

use std::ffi::OsString;

/// Provider key variables read by shai-llm. They all match the `_API_KEY`
/// suffix too; listed so the intent survives a rename of the suffix rule.
const PROVIDER_KEY_VARS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "MISTRAL_API_KEY",
    "OLLAMA_API_KEY",
    "OPENAI_API_KEY",
    "OPENAI_COMPATIBLE_API_KEY",
    "OPENROUTER_API_KEY",
    "OVH_API_KEY",
];

/// Name suffixes treated as secret-bearing (compared case-insensitively).
const SECRET_SUFFIXES: &[&str] = &["_API_KEY", "_TOKEN", "_SECRET"];

/// True if an env var with this name should not reach a model-driven child.
pub fn is_secret_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    PROVIDER_KEY_VARS.contains(&upper.as_str())
        || SECRET_SUFFIXES.iter().any(|s| upper.ends_with(s))
}

/// Names in the current process env that [`is_secret_env_name`] matches.
/// Pass each one to `Command::env_remove` before spawning.
pub fn secret_env_names() -> Vec<OsString> {
    std::env::vars_os()
        .map(|(name, _)| name)
        .filter(|name| is_secret_env_name(&name.to_string_lossy()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_provider_keys_and_secret_suffixes() {
        for name in [
            "OPENROUTER_API_KEY",
            "OVH_API_KEY",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "MISTRAL_API_KEY",
            "FOO_API_KEY",
            "GITHUB_TOKEN",
            "AWS_SECRET",
            "openrouter_api_key",
        ] {
            assert!(is_secret_env_name(name), "{name} should be scrubbed");
        }
    }

    #[test]
    fn keeps_ordinary_vars() {
        for name in [
            "PATH",
            "HOME",
            "OVH_BASE_URL",
            "OLLAMA_BASE_URL",
            "TOKENIZERS_PARALLELISM",
            "API_KEY_FILE",
        ] {
            assert!(!is_secret_env_name(name), "{name} should be kept");
        }
    }
}
