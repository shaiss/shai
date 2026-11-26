//! Keep secrets out of subprocesses the model can drive.
//!
//! `ShaiConfig::set_env_vars` exports the selected provider's key (for example
//! `OPENROUTER_API_KEY`) into the shai process env, and a model-driven child
//! (the bash tool, post-edit verification) would otherwise inherit it and could
//! print it with `env`. Callers remove these names on the spawned `Command`
//! with `env_remove`; the shai process env itself is left alone.

use regex::Regex;
use std::ffi::OsString;
use std::sync::OnceLock;

/// Provider key variables read by shai-llm. They all match the `_KEY`
/// suffix too; listed so the intent survives a change to the suffix rules.
const PROVIDER_KEY_VARS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "MISTRAL_API_KEY",
    "OLLAMA_API_KEY",
    "OPENAI_API_KEY",
    "OPENAI_COMPATIBLE_API_KEY",
    "OPENROUTER_API_KEY",
    "ORCAROUTER_API_KEY",
    "OVH_API_KEY",
];

/// Name suffixes treated as secret-bearing (compared case-insensitively).
/// `_KEY` also covers `_API_KEY`, `_ACCESS_KEY`, `_PRIVATE_KEY`.
const SECRET_SUFFIXES: &[&str] = &[
    "_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_PASSWD",
    "_CREDENTIALS",
    "_PAT",
];

/// `AWS_*` names that carry no secret and are kept.
const AWS_KEEP: &[&str] = &["AWS_REGION", "AWS_DEFAULT_REGION"];

/// True if an env var with this name should not reach a model-driven child.
pub fn is_secret_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if upper.starts_with("AWS_") && !AWS_KEEP.contains(&upper.as_str()) {
        return true;
    }
    PROVIDER_KEY_VARS.contains(&upper.as_str())
        || SECRET_SUFFIXES.iter().any(|s| upper.ends_with(s))
}

/// True if the value embeds URL credentials, `scheme://user:pass@host`
/// (DATABASE_URL-style). A URL without a password after the colon is kept.
pub fn is_secret_env_value(value: &str) -> bool {
    static URL_USERINFO: OnceLock<Regex> = OnceLock::new();
    URL_USERINFO
        .get_or_init(|| {
            Regex::new(r"[A-Za-z][A-Za-z0-9+.\-]*://[^/?#@\s:]*:[^/?#@\s]+@")
                .expect("valid userinfo regex")
        })
        .is_match(value)
}

/// Names in the current process env whose name or value looks secret.
/// Pass each one to `Command::env_remove` before spawning.
pub fn secret_env_names() -> Vec<OsString> {
    std::env::vars_os()
        .filter(|(name, value)| {
            is_secret_env_name(&name.to_string_lossy())
                || is_secret_env_value(&value.to_string_lossy())
        })
        .map(|(name, _)| name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_scrubbed(names: &[&str]) {
        for name in names {
            assert!(is_secret_env_name(name), "{name} should be scrubbed");
        }
    }

    #[test]
    fn scrubs_provider_keys() {
        assert_scrubbed(&[
            "OPENROUTER_API_KEY",
            "ORCAROUTER_API_KEY",
            "OVH_API_KEY",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "MISTRAL_API_KEY",
            "FOO_API_KEY",
            "openrouter_api_key",
        ]);
    }

    #[test]
    fn scrubs_token_and_secret_suffixes() {
        assert_scrubbed(&["GITHUB_TOKEN", "CLIENT_SECRET", "npm_token"]);
    }

    #[test]
    fn scrubs_key_suffix() {
        assert_scrubbed(&["STRIPE_KEY", "SSH_PRIVATE_KEY", "gpg_signing_key"]);
    }

    #[test]
    fn scrubs_password_suffixes() {
        assert_scrubbed(&["DB_PASSWORD", "PGPASS_PASSWORD", "smtp_password"]);
        assert_scrubbed(&["MYSQL_PASSWD", "ftp_passwd"]);
    }

    #[test]
    fn scrubs_credentials_suffix() {
        assert_scrubbed(&["GOOGLE_APPLICATION_CREDENTIALS", "docker_credentials"]);
    }

    #[test]
    fn scrubs_pat_suffix() {
        assert_scrubbed(&["GITHUB_PAT", "azure_devops_pat"]);
    }

    #[test]
    fn scrubs_aws_except_region() {
        assert_scrubbed(&[
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_PROFILE",
            "aws_access_key_id",
        ]);
        for name in ["AWS_REGION", "AWS_DEFAULT_REGION", "aws_region"] {
            assert!(!is_secret_env_name(name), "{name} should be kept");
        }
    }

    #[test]
    fn keeps_ordinary_names() {
        for name in [
            "PATH",
            "HOME",
            "OVH_BASE_URL",
            "OLLAMA_BASE_URL",
            "OPENAI_COMPATIBLE_BASE_URL",
            "TOKENIZERS_PARALLELISM",
            "API_KEY_FILE",
            "SHAI_KEY_EXIT",
            "KEYBOARD_LAYOUT",
            "PATH_INFO",
            "XDG_CONFIG_HOME",
            "AWSOME_FLAG",
        ] {
            assert!(!is_secret_env_name(name), "{name} should be kept");
        }
    }

    #[test]
    fn scrubs_url_userinfo_values() {
        for value in [
            "postgres://app:hunter2@db.internal:5432/app",
            "redis://:s3cret@cache:6379/0",
            "https://user:ghp_abc123@github.com/org/repo.git",
            "mysql+pymysql://root:pw@localhost/db?charset=utf8",
        ] {
            assert!(is_secret_env_value(value), "{value} should be scrubbed");
        }
    }

    #[test]
    fn keeps_plain_url_values() {
        for value in [
            "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1",
            "http://localhost:11434/v1",
            "https://user@example.com/path",
            "https://example.com/a:b@c",
            "https://example.com/?next=x:y@z",
            "ssh://git@github.com:22/org/repo",
            "/usr/local/bin:/usr/bin:/bin",
            "user:pass@host",
        ] {
            assert!(!is_secret_env_value(value), "{value} should be kept");
        }
    }
}
