use super::config::ShaiConfig;
use crate::tools::mcp::McpConfig;
use crate::tools::BashToolConfig;
use json_comments::StripComments;
use serde::{Deserialize, Serialize};
use shai_llm::ToolCallMethod;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProviderConfig {
    pub provider: String,
    pub env_vars: HashMap<String, String>,
    pub model: String,
    pub tool_method: ToolCallMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolConfig {
    pub config: McpConfig,
    #[serde(default = "default_enabled_tools")]
    pub enabled_tools: Vec<String>,
    #[serde(default)]
    pub excluded_tools: Vec<String>,
    /// Whether this MCP server is required to start successfully (default: false)
    /// If false, connection errors will be logged as warnings and agent will continue
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTools {
    #[serde(default)]
    pub builtin: Vec<String>,
    #[serde(default)]
    pub builtin_excluded: Vec<String>,
    #[serde(default)]
    pub mcp: HashMap<String, McpToolConfig>,
    /// Limits for the built-in bash tool (default / max timeout).
    #[serde(default)]
    pub bash: BashToolConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub name: String,
    pub description: String,
    #[serde(default = "default_llm_provider")]
    pub llm_provider: AgentProviderConfig,
    #[serde(default)]
    pub tools: AgentTools,
    #[serde(default = "default_system_prompt")]
    pub system_prompt: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    #[serde(default)]
    pub compaction: CompactionConfig,
    #[serde(default)]
    pub verification: VerificationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_output_chars")]
    pub max_output_chars: usize,
    #[serde(default = "default_max_tool_calls_per_turn")]
    pub max_tool_calls_per_turn: Option<usize>,
    #[serde(default)]
    pub max_cached_commands: usize,
    #[serde(default = "default_max_trace_chars")]
    pub max_trace_chars: usize,
    /// Maximum number of cached read results (per file path + line range)
    #[serde(default = "default_max_cached_reads")]
    pub max_cached_reads: usize,
    /// Default exclusion patterns for the find tool (substrings matched against file paths)
    #[serde(default = "default_find_exclude_patterns")]
    pub find_exclude_patterns: Vec<String>,
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_output_chars: 8000,
            max_tool_calls_per_turn: Some(100),
            max_cached_commands: 50,
            max_trace_chars: 85000,
            max_cached_reads: 100,
            find_exclude_patterns: default_find_exclude_patterns(),
        }
    }
}

fn default_max_cached_reads() -> usize {
    100
}

fn default_find_exclude_patterns() -> Vec<String> {
    vec![
        ".git".to_string(),
        "target".to_string(),
        "node_modules".to_string(),
        ".next".to_string(),
        "dist".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Whether post-edit verification is enabled (default: false)
    #[serde(default)]
    pub enabled: bool,
    /// Maximum time in seconds to wait for the verification command to complete
    #[serde(default = "default_verification_timeout_secs")]
    pub timeout_secs: u64,
    /// Mapping of language name to verification command.
    /// Defaults use stdlib-only tools. Users can override per-language.
    #[serde(default = "default_verification_commands")]
    pub commands: HashMap<String, Vec<String>>,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_secs: 30,
            commands: default_verification_commands(),
        }
    }
}

fn default_verification_timeout_secs() -> u64 {
    30
}

fn default_verification_commands() -> HashMap<String, Vec<String>> {
    let mut commands = HashMap::new();
    // Project-scoped verifiers: run once, no file arguments
    commands.insert("rust".to_string(), vec!["cargo".into(), "check".into()]);
    commands.insert(
        "go".to_string(),
        vec!["go".into(), "build".into(), "./...".into()],
    );
    // Per-file verifiers: `{files}` is replaced with each edited file and the
    // command runs once per file (several of these only check the first file
    // argument when given many)
    // Syntax-only check via `compile()`: unlike `python -m py_compile` it does
    // not write `__pycache__/*.pyc` artifacts next to the edited sources.
    commands.insert(
        "python".to_string(),
        vec![
            "python".into(),
            "-c".into(),
            "import sys; compile(open(sys.argv[1], encoding='utf-8').read(), sys.argv[1], 'exec')"
                .into(),
            "{files}".into(),
        ],
    );
    // Per-file check that understands TypeScript syntax (`node --check` only
    // parses JavaScript and rejects valid TS). Note: with file arguments tsc
    // ignores tsconfig.json; projects that want a project-scoped check can
    // override this with e.g. ["tsc", "-p", ".", "--noEmit"].
    commands.insert(
        "typescript".to_string(),
        vec!["tsc".into(), "--noEmit".into(), "{files}".into()],
    );
    commands.insert(
        "javascript".to_string(),
        vec!["node".into(), "--check".into(), "{files}".into()],
    );
    commands.insert(
        "perl".to_string(),
        vec!["perl".into(), "-c".into(), "{files}".into()],
    );
    commands.insert(
        "ruby".to_string(),
        vec!["ruby".into(), "-c".into(), "{files}".into()],
    );
    commands.insert(
        "bash".to_string(),
        vec!["bash".into(), "-n".into(), "{files}".into()],
    );
    commands.insert(
        "php".to_string(),
        vec!["php".into(), "-l".into(), "{files}".into()],
    );
    commands.insert(
        "lua".to_string(),
        vec!["luac".into(), "-p".into(), "{files}".into()],
    );
    commands
}

fn default_true() -> bool {
    true
}

fn default_max_output_chars() -> usize {
    8000
}

fn default_max_tool_calls_per_turn() -> Option<usize> {
    Some(100)
}

fn default_max_trace_chars() -> usize {
    85000
}

fn llm_provider_from_config(shai_config: &ShaiConfig) -> AgentProviderConfig {
    let provider_config = shai_config
        .get_selected_provider()
        .expect("No provider configured in default config");

    AgentProviderConfig {
        provider: provider_config.provider.clone(),
        env_vars: provider_config.env_vars.clone(),
        model: provider_config.model.clone(),
        tool_method: provider_config.tool_method,
    }
}

fn default_llm_provider() -> AgentProviderConfig {
    // Used when an agent file omits `llm_provider` and is deserialized
    // without going through [`AgentConfig::load`]. `load` refuses a broken
    // auth config before this is called.
    match ShaiConfig::primary() {
        Ok(config) => llm_provider_from_config(&config),
        Err(error) => {
            tracing::error!(
                "broken auth config while defaulting an agent's provider: {}",
                error
            );
            llm_provider_from_config(&ShaiConfig::default())
        }
    }
}

/// Fill in `llm_provider` from the auth config when the agent file omits it,
/// and enforce `anonymous_fallback` against both omitted and explicit
/// providers (refusing keyless `ovhcloud` under `deny` or an invalid policy).
pub(crate) fn agent_config_from_value(
    mut value: serde_json::Value,
    primary: Result<ShaiConfig, crate::config::roles::PrimaryConfigError>,
    path: Option<&Path>,
) -> Result<AgentConfig, Box<dyn std::error::Error>> {
    if !value.is_object() {
        return Err(unreadable_agent_config(path, json_kind(&value)).into());
    }
    let has_explicit_provider = value.get("llm_provider").is_some();
    if !has_explicit_provider {
        let config = ShaiConfig::primary_from(Ok(primary?))?;
        value["llm_provider"] = serde_json::to_value(llm_provider_from_config(&config))?;
        return Ok(serde_json::from_value(value)?);
    }
    let agent: AgentConfig = serde_json::from_value(value)?;
    ShaiConfig::enforce_provider_anonymous_fallback(
        &agent.llm_provider.provider,
        &agent.llm_provider.env_vars,
        primary.as_ref(),
    )?;
    Ok(agent)
}

fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn unreadable_agent_config(path: Option<&Path>, kind: &str) -> String {
    let reason = format!("expected an object, found {kind}");
    match path {
        Some(path) => format!(
            "the config file {} could not be loaded ({reason})",
            path.display()
        ),
        None => format!("the agent config could not be loaded ({reason})"),
    }
}

fn default_system_prompt() -> String {
    "{{CODER_BASE_PROMPT}}".to_string()
}

fn default_max_tokens() -> u32 {
    4096
}

fn default_temperature() -> f32 {
    0.0
}

fn default_enabled_tools() -> Vec<String> {
    vec!["*".to_string()]
}

impl Default for AgentTools {
    fn default() -> Self {
        Self {
            builtin: vec!["*".to_string()],
            builtin_excluded: Vec::new(),
            mcp: HashMap::new(),
            bash: BashToolConfig::default(),
        }
    }
}

impl AgentConfig {
    /// The agents directory, without creating it.
    fn agents_dir_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|_| {
                dirs::home_dir()
                    .map(|home| home.join(".config"))
                    .ok_or("Could not find home directory")
            })?;
        Ok(config_dir.join("shai").join("agents"))
    }

    /// Get the agents directory path, creating it if needed for a write.
    pub fn agents_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let agents_dir = Self::agents_dir_path()?;
        std::fs::create_dir_all(&agents_dir)?;
        Ok(agents_dir)
    }

    /// Get the path for a specific agent config file
    pub fn agent_config_path(agent_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(Self::agents_dir_path()?.join(format!("{}.config.json", agent_name)))
    }

    /// Get the legacy path for a specific agent config file
    fn legacy_agent_config_path(agent_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(Self::agents_dir_path()?.join(format!("{}.config", agent_name)))
    }

    /// Load an agent config from file
    pub fn load(agent_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::load_with_primary(agent_name, None)
    }

    /// [`AgentConfig::load`], filling an omitted provider from `primary`
    /// instead of reading the auth config again.
    pub fn load_with_primary(
        agent_name: &str,
        primary: Option<&ShaiConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::load_with_primary_result(agent_name, primary.map(Ok))
    }

    /// [`AgentConfig::load_with_primary`], accepting a pre-resolved `Result`
    /// (so a startup snapshot or missing-config refusal is reused without
    /// re-reading disk).
    pub fn load_with_primary_result(
        agent_name: &str,
        primary: Option<Result<&ShaiConfig, &crate::config::roles::PrimaryConfigError>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = Self::agent_config_path(agent_name)?;

        if config_path.exists() {
            let content_bytes = std::fs::read(&config_path)?;
            return Self::from_bytes_with_primary_result(&content_bytes, &config_path, primary);
        }

        let legacy_path = Self::legacy_agent_config_path(agent_name)?;
        if legacy_path.exists() {
            let content_bytes = std::fs::read(&legacy_path)?;
            return Self::from_bytes_with_primary_result(&content_bytes, &legacy_path, primary);
        }

        Err(format!("Agent config '{}' does not exist", agent_name).into())
    }

    #[cfg(test)]
    fn from_bytes(
        content_bytes: &[u8],
        path: &Path,
        primary: Option<&ShaiConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_bytes_with_primary_result(content_bytes, path, primary.map(Ok))
    }

    fn from_bytes_with_primary_result(
        content_bytes: &[u8],
        path: &Path,
        primary: Option<Result<&ShaiConfig, &crate::config::roles::PrimaryConfigError>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let content_stripped = StripComments::new(content_bytes);
        let value: serde_json::Value = serde_json::from_reader(content_stripped)?;
        let has_explicit_provider = value.get("llm_provider").is_some();
        let primary = match primary {
            Some(Ok(config)) => {
                if has_explicit_provider {
                    Ok(config.clone())
                } else {
                    ShaiConfig::primary_from(Ok(config.clone()))
                }
            }
            Some(Err(err)) => Err(err.clone()),
            None => {
                let raw = ShaiConfig::load_for_roles();
                if has_explicit_provider {
                    raw.map_err(crate::config::roles::PrimaryConfigError::from_role_error)
                } else {
                    ShaiConfig::primary_from(raw)
                }
            }
        };
        agent_config_from_value(value, primary, Some(path))
    }

    /// Save the agent config to file
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = Self::agent_config_path(&self.name)?;
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&config_path, content)?;
        Ok(())
    }

    /// List all available agents
    pub fn list_agents() -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let agents_dir = Self::agents_dir_path()?;
        let mut agents = Vec::new();

        if agents_dir.exists() {
            for entry in std::fs::read_dir(agents_dir)? {
                let entry = entry?;
                let path = entry.path();

                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(agent_name) = filename
                        .strip_suffix(".config.json")
                        .or_else(|| filename.strip_suffix(".config"))
                    {
                        agents.push(agent_name.to_string());
                    }
                }
            }
        }

        agents.sort();
        agents.dedup();
        Ok(agents)
    }

    /// True when the named agent's config file includes an `llm_provider`
    /// field. An omitted field falls back to the global auth config.
    pub fn has_explicit_llm_provider(agent_name: &str) -> bool {
        Self::explicit_llm_provider(agent_name).is_some()
    }

    /// The explicit `llm_provider` object from the named agent's file, if any.
    /// Does not fill an omitted field from the global auth config.
    fn explicit_llm_provider(agent_name: &str) -> Option<serde_json::Value> {
        let path = match Self::agent_config_path(agent_name) {
            Ok(path) if path.exists() => path,
            _ => match Self::legacy_agent_config_path(agent_name) {
                Ok(path) if path.exists() => path,
                _ => return None,
            },
        };
        let bytes = std::fs::read(&path).ok()?;
        let stripped = StripComments::new(&bytes[..]);
        let value = serde_json::from_reader::<_, serde_json::Value>(stripped).ok()?;
        value.get("llm_provider").cloned()
    }

    /// `Some(true)` when the agent's own provider would be anonymous OVH,
    /// `Some(false)` when it has a non-anonymous explicit provider, and
    /// `None` when the file omits `llm_provider` or cannot be read.
    pub fn explicit_provider_is_anonymous_ovh(agent_name: &str) -> Option<bool> {
        let provider = Self::explicit_llm_provider(agent_name)?;
        let name = provider.get("provider")?.as_str()?;
        let env_vars = provider
            .get("env_vars")
            .and_then(|value| serde_json::from_value::<HashMap<String, String>>(value.clone()).ok())
            .unwrap_or_default();
        Some(ShaiConfig::provider_is_anonymous_ovh(name, &env_vars))
    }

    /// Check if an agent config exists
    pub fn exists(agent_name: &str) -> bool {
        Self::agent_config_path(agent_name)
            .map(|p| p.exists())
            .unwrap_or(false)
            || Self::legacy_agent_config_path(agent_name)
                .map(|p| p.exists())
                .unwrap_or(false)
    }

    /// Delete an agent config
    pub fn delete(agent_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = Self::agent_config_path(agent_name)?;
        let legacy_path = Self::legacy_agent_config_path(agent_name)?;

        if config_path.exists() {
            std::fs::remove_file(config_path)?;
            return Ok(());
        }

        if legacy_path.exists() {
            std::fs::remove_file(legacy_path)?;
            return Ok(());
        }

        Err(format!("Agent config '{}' does not exist", agent_name).into())
    }

    /// Check if a builtin tool is enabled
    pub fn is_builtin_tool_enabled(&self, tool_name: &str) -> bool {
        self.tools.builtin.contains(&tool_name.to_string())
    }

    /// Check if a specific MCP tool is enabled
    pub fn is_mcp_tool_enabled(&self, mcp_name: &str, tool_name: &str) -> bool {
        self.tools
            .mcp
            .get(mcp_name)
            .map(|mcp_tool| mcp_tool.enabled_tools.contains(&tool_name.to_string()))
            .unwrap_or(false)
    }

    /// Get all enabled MCP tool names across all MCP configs
    pub fn get_all_enabled_mcp_tools(&self) -> Vec<String> {
        self.tools
            .mcp
            .values()
            .flat_map(|mcp_tool| &mcp_tool.enabled_tools)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod verification_default_tests {
    use super::default_verification_commands;

    #[test]
    fn python_default_does_not_emit_bytecode_artifacts() {
        let cmds = default_verification_commands();
        let python = cmds.get("python").expect("python default present");
        // py_compile writes __pycache__/*.pyc next to the edited sources; the
        // default must use the side-effect-free compile() syntax check instead.
        assert!(
            !python.iter().any(|a| a.contains("py_compile")),
            "python default must not use py_compile: {:?}",
            python
        );
        assert!(python.iter().any(|a| a == "{files}"));
    }

    #[test]
    fn typescript_default_understands_ts_syntax() {
        let cmds = default_verification_commands();
        let ts = cmds.get("typescript").expect("typescript default present");
        // `node --check` only parses JavaScript and rejects valid TypeScript;
        // the default must use a TS-aware checker.
        assert!(
            !(ts.first().map(|s| s == "node").unwrap_or(false)
                && ts.iter().any(|a| a == "--check")),
            "typescript default must not be `node --check`: {:?}",
            ts
        );
        assert_eq!(ts.first().map(|s| s.as_str()), Some("tsc"));
        assert!(ts.iter().any(|a| a == "--noEmit"));
        assert!(ts.iter().any(|a| a == "{files}"));
    }
}

#[cfg(test)]
mod broken_config_fallback_tests {
    use super::{agent_config_from_value, AgentConfig};
    use crate::config::config::ShaiConfig;
    use crate::config::roles::RoleError;
    use std::path::Path;

    fn agent_json(with_provider: bool) -> serde_json::Value {
        let provider = if with_provider {
            r#",
            "llm_provider": {
                "provider": "openai",
                "env_vars": {"OPENAI_API_KEY": "k"},
                "model": "gpt-4o",
                "tool_method": "FunctionCall"
            }"#
        } else {
            ""
        };
        serde_json::from_str(&format!(
            r#"{{
                "name": "reviewer",
                "description": "a named agent"
                {provider}
            }}"#
        ))
        .unwrap()
    }

    fn broken() -> Result<ShaiConfig, crate::config::roles::PrimaryConfigError> {
        ShaiConfig::primary_from_with_env(
            Err(RoleError::ConfigInvalid {
                path: "/home/me/.config/shai/auth.config.json".to_string(),
                reason: "JSON syntax error at line 3 column 7".to_string(),
            }),
            None,
        )
    }

    #[test]
    fn a_named_agent_without_its_own_provider_does_not_use_the_default_when_the_auth_config_is_broken(
    ) {
        let error = agent_config_from_value(agent_json(false), broken(), None)
            .map(|_| ())
            .expect_err("a broken auth config must not be replaced by the default");
        let message = error.to_string();
        assert!(message.contains("auth.config.json"), "{message}");
        assert!(message.contains("line 3 column 7"), "{message}");
    }

    #[test]
    fn a_named_agent_without_its_own_provider_uses_the_auth_config_or_the_default_if_it_is_missing()
    {
        let cfg: ShaiConfig = serde_json::from_str(
            r#"{"providers":[{"provider":"openai","env_vars":{"OPENAI_API_KEY":"k"},"model":"gpt-4o","tool_method":"FunctionCall"}],"selected_provider":0}"#,
        )
        .unwrap();
        let loaded = agent_config_from_value(agent_json(false), Ok(cfg), None).unwrap();
        assert_eq!(loaded.llm_provider.provider, "openai");
        assert_eq!(loaded.llm_provider.model, "gpt-4o");

        let loaded = agent_config_from_value(
            agent_json(false),
            ShaiConfig::primary_from_with_env(Err(RoleError::ConfigMissing), None),
            None,
        )
        .unwrap();
        assert_eq!(
            loaded.llm_provider.provider,
            ShaiConfig::default().providers[0].provider
        );

        let err = agent_config_from_value(
            agent_json(false),
            ShaiConfig::primary_from_with_env(Err(RoleError::ConfigMissing), Some("deny")),
            None,
        )
        .unwrap_err();
        assert!(
            err.downcast_ref::<crate::config::roles::PrimaryConfigError>()
                .is_some_and(|e| e.is_refused_start()),
            "expected PrimaryConfigError, got: {err}"
        );
    }

    #[test]
    fn a_named_agent_that_names_its_own_provider_loads_even_if_the_auth_config_is_broken() {
        let loaded = agent_config_from_value(agent_json(true), broken(), None).unwrap();
        assert_eq!(loaded.llm_provider.provider, "openai");
        assert_eq!(loaded.llm_provider.model, "gpt-4o");
    }

    #[test]
    fn a_non_object_agent_config_is_an_error_not_a_panic() {
        let path = Path::new("/home/me/.config/shai/agents/reviewer.config.json");
        for (json, kind) in [
            ("[]", "array"),
            ("\"str\"", "string"),
            ("123", "number"),
            ("null", "null"),
            ("true", "boolean"),
        ] {
            let value: serde_json::Value = serde_json::from_str(json).unwrap();
            let error = agent_config_from_value(value, Ok(ShaiConfig::default()), Some(path))
                .map(|_| ())
                .expect_err("non-object agent JSON must not panic or load");
            let message = error.to_string();
            assert!(
                message.contains("reviewer.config.json"),
                "{json}: {message}"
            );
            assert!(message.contains("could not be loaded"), "{json}: {message}");
            assert!(message.contains(kind), "{json}: {message}");
            assert!(message.contains("expected an object"), "{json}: {message}");
        }
    }

    #[test]
    fn load_with_primary_uses_the_startup_snapshot_when_auth_is_broken() {
        let _guard = crate::config::test_env::XDG_CONFIG_HOME_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::TempDir::new().unwrap();
        let shai = dir.path().join("shai");
        std::fs::create_dir_all(shai.join("agents")).unwrap();
        std::fs::write(shai.join("auth.config.json"), "{ this is not json").unwrap();
        std::fs::write(
            shai.join("agents").join("reviewer.config.json"),
            r#"{"name": "reviewer", "description": "needs the auth config"}"#,
        )
        .unwrap();
        let _home = crate::config::test_env::XdgConfigHomeGuard::set(dir.path());

        let load_error = AgentConfig::load("reviewer")
            .map(|_| ())
            .expect_err("a broken auth config must not load this agent");
        let message = load_error.to_string();
        assert!(message.contains("auth.config.json"), "{message}");

        let snapshot: ShaiConfig = serde_json::from_str(
            r#"{"providers":[{"provider":"openai","env_vars":{"OPENAI_API_KEY":"k"},"model":"snapshot-model","tool_method":"FunctionCall"}],"selected_provider":0}"#,
        )
        .unwrap();
        let loaded = AgentConfig::load_with_primary("reviewer", Some(&snapshot)).unwrap();
        assert_eq!(loaded.llm_provider.provider, "openai");
        assert_eq!(loaded.llm_provider.model, "snapshot-model");
    }

    #[test]
    fn explicit_provider_is_anonymous_ovh_uses_the_effective_key() {
        let _xdg = crate::config::test_env::XDG_CONFIG_HOME_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _env = crate::config::test_env::ENV_TEST_LOCK.blocking_lock();
        let previous = std::env::var_os("OVH_API_KEY");
        std::env::remove_var("OVH_API_KEY");
        let dir = tempfile::TempDir::new().unwrap();
        let agents = dir.path().join("shai").join("agents");
        std::fs::create_dir_all(&agents).unwrap();
        let _home = crate::config::test_env::XdgConfigHomeGuard::set(dir.path());

        std::fs::write(
            agents.join("none.config.json"),
            r#"{"name":"none","description":"x"}"#,
        )
        .unwrap();
        assert_eq!(
            AgentConfig::explicit_provider_is_anonymous_ovh("none"),
            None
        );
        assert!(!AgentConfig::has_explicit_llm_provider("none"));

        std::fs::write(
            agents.join("keyed.config.json"),
            r#"{"name":"keyed","description":"x","llm_provider":{"provider":"openai","env_vars":{"OPENAI_API_KEY":"k"},"model":"gpt-4o","tool_method":"FunctionCall"}}"#,
        )
        .unwrap();
        assert_eq!(
            AgentConfig::explicit_provider_is_anonymous_ovh("keyed"),
            Some(false)
        );
        assert!(AgentConfig::has_explicit_llm_provider("keyed"));

        std::fs::write(
            agents.join("anon.config.json"),
            r#"{"name":"anon","description":"x","llm_provider":{"provider":"ovhcloud","env_vars":{},"model":"qwen","tool_method":"FunctionCall"}}"#,
        )
        .unwrap();
        assert_eq!(
            AgentConfig::explicit_provider_is_anonymous_ovh("anon"),
            Some(true)
        );

        match previous {
            Some(value) => std::env::set_var("OVH_API_KEY", value),
            None => std::env::remove_var("OVH_API_KEY"),
        }
    }

    #[test]
    fn explicit_anonymous_ovh_agent_is_refused_under_deny_or_invalid_policy() {
        let _xdg = crate::config::test_env::XDG_CONFIG_HOME_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _env = crate::config::test_env::ENV_TEST_LOCK.blocking_lock();

        let prev_ovh = std::env::var_os("OVH_API_KEY");
        let prev_fb = std::env::var_os("SHAI_ANONYMOUS_FALLBACK");
        std::env::remove_var("OVH_API_KEY");
        std::env::remove_var("SHAI_ANONYMOUS_FALLBACK");

        let dir = tempfile::TempDir::new().unwrap();
        let shai_dir = dir.path().join("shai");
        let agents_dir = shai_dir.join("agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        let _home = crate::config::test_env::XdgConfigHomeGuard::set(dir.path());

        let anon_agent = r#"{"name":"anon","description":"x","llm_provider":{"provider":"ovhcloud","env_vars":{},"model":"qwen3-32b","tool_method":"FunctionCall"}}"#;
        let openai_agent = r#"{"name":"keyed","description":"x","llm_provider":{"provider":"openai","env_vars":{"OPENAI_API_KEY":"k"},"model":"gpt-4o","tool_method":"FunctionCall"}}"#;
        let anon_path = agents_dir.join("anon.config.json");
        let openai_path = agents_dir.join("keyed.config.json");
        std::fs::write(&anon_path, anon_agent).unwrap();
        std::fs::write(&openai_path, openai_agent).unwrap();

        // a) No auth file + SHAI_ANONYMOUS_FALLBACK=deny:
        // explicit keyless ovhcloud is refused (from_bytes & agent_config_from_value),
        // while explicit openai still loads.
        std::env::set_var("SHAI_ANONYMOUS_FALLBACK", "deny");
        let err = AgentConfig::from_bytes(anon_agent.as_bytes(), &anon_path, None)
            .map(|_| ())
            .expect_err("from_bytes must refuse explicit anonymous OVH under env deny");
        assert!(
            err.downcast_ref::<crate::config::roles::PrimaryConfigError>()
                .is_some_and(|e| e.is_refused_start()),
            "expected PrimaryConfigError, got: {err}"
        );
        let ok_openai = AgentConfig::from_bytes(openai_agent.as_bytes(), &openai_path, None)
            .expect("explicit openai must still load under missing auth + env deny");
        assert_eq!(ok_openai.llm_provider.provider, "openai");

        // b) Auth config has anonymous_fallback: deny (with env unset),
        // both when primary is openai and when primary is anonymous OVH.
        std::env::remove_var("SHAI_ANONYMOUS_FALLBACK");
        for auth in [
            r#"{"providers":[{"provider":"openai","env_vars":{"OPENAI_API_KEY":"k"},"model":"gpt-4o","tool_method":"FunctionCall"}],"selected_provider":0,"anonymous_fallback":"deny"}"#,
            r#"{"providers":[{"provider":"ovhcloud","env_vars":{},"model":"qwen3-32b","tool_method":"FunctionCall"}],"selected_provider":0,"anonymous_fallback":"deny"}"#,
        ] {
            std::fs::write(shai_dir.join("auth.config.json"), auth).unwrap();
            let err = AgentConfig::from_bytes(anon_agent.as_bytes(), &anon_path, None)
                .map(|_| ())
                .expect_err("from_bytes must refuse explicit anonymous OVH under config deny");
            assert!(
                err.downcast_ref::<crate::config::roles::PrimaryConfigError>()
                    .is_some_and(|e| e.is_refused_start()),
                "expected PrimaryConfigError for auth={auth}, got: {err}"
            );
            AgentConfig::from_bytes(openai_agent.as_bytes(), &openai_path, None)
                .expect("explicit openai must still load when auth has anonymous_fallback=deny");
        }

        // c) Invalid anonymous_fallback policy in env refuses.
        std::fs::remove_file(shai_dir.join("auth.config.json")).unwrap();
        std::env::set_var("SHAI_ANONYMOUS_FALLBACK", "bogus");
        let err = AgentConfig::from_bytes(anon_agent.as_bytes(), &anon_path, None)
            .map(|_| ())
            .expect_err("invalid policy must refuse explicit anonymous OVH");
        assert!(
            err.downcast_ref::<crate::config::roles::PrimaryConfigError>()
                .is_some_and(|e| e.is_refused_start()),
            "expected PrimaryConfigError, got: {err}"
        );

        match prev_ovh {
            Some(v) => std::env::set_var("OVH_API_KEY", v),
            None => std::env::remove_var("OVH_API_KEY"),
        }
        match prev_fb {
            Some(v) => std::env::set_var("SHAI_ANONYMOUS_FALLBACK", v),
            None => std::env::remove_var("SHAI_ANONYMOUS_FALLBACK"),
        }
    }
}
