use super::lenient::Lenient;
use super::prewalk::PrewalkConfig;
use super::roles::RolesConfig;
use crate::tools::mcp::McpConfig;
use json_comments::StripComments;
use reqwest::Url;
use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use shai_llm::{LlmClient, ToolCallMethod};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Mutex;
use std::{collections::HashMap, ffi::OsString, path::PathBuf};

/// Variables written by [`ShaiConfig::set_env_vars`], with the value each one had
/// before (`None` if it was unset), in the order they were written.
static APPLIED_ENV_VARS: Mutex<Vec<(String, Option<OsString>)>> = Mutex::new(Vec::new());

/// Undo `set_env_vars`, newest first, so a name written twice ends up with its
/// original value.
fn restore_env_vars(applied: &mut Vec<(String, Option<OsString>)>) {
    for (name, previous) in applied.drain(..).rev() {
        match previous {
            Some(value) => std::env::set_var(&name, value),
            None => std::env::remove_var(&name),
        }
    }
}

/// The process environment as [`ShaiConfig::set_env_vars`] last left it.
///
/// Used to put the live agent's variables back if a later
/// [`ShaiConfig::set_env_vars`] should not stick (for example, an `/auth`
/// reload that could not start).
pub struct AppliedEnvSnapshot {
    applied: Vec<(String, Option<OsString>)>,
    current: Vec<(String, Option<OsString>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub provider: String,
    pub env_vars: std::collections::HashMap<String, String>,
    pub model: String,
    pub tool_method: ToolCallMethod,
}

#[derive(Debug, Clone)]
pub struct ShaiConfig {
    pub providers: Vec<ProviderConfig>,
    pub selected_provider: usize,
    pub mcp_configs: HashMap<String, McpConfig>,
    /// Named secondary models, see [`crate::config::roles`].
    pub roles: RolesConfig,
    /// One-shot handoff to another model, see [`crate::config::prewalk`].
    pub prewalk: Lenient<PrewalkConfig>,
}

// Reading and writing are spelled out instead of derived for the sake of the
// optional sections (see `super::section`): a section the file gives twice
// has to survive loading and saving as it is, which a derived field cannot
// do. The other keys of the object are read as the derive read them:
// `providers` and `selected_provider` are required, `mcp_configs` is
// optional, none of the three may be repeated, and unknown keys are ignored.
// A config has to be a JSON object: the array of positional values that the
// derive also happened to accept is not read.
impl Serialize for ShaiConfig {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("providers", &self.providers)?;
        map.serialize_entry("selected_provider", &self.selected_provider)?;
        map.serialize_entry("mcp_configs", &self.mcp_configs)?;
        self.roles.section().write("roles", &mut map)?;
        self.prewalk.section().write("prewalk", &mut map)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for ShaiConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ConfigVisitor;

        /// Read the value of a key that may appear only once.
        fn once<'de, A: MapAccess<'de>, T: Deserialize<'de>>(
            slot: &mut Option<T>,
            field: &'static str,
            map: &mut A,
        ) -> Result<(), A::Error> {
            if slot.is_some() {
                return Err(de::Error::duplicate_field(field));
            }
            *slot = Some(map.next_value()?);
            Ok(())
        }

        impl<'de> Visitor<'de> for ConfigVisitor {
            type Value = ShaiConfig;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a config object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ShaiConfig, A::Error> {
                let mut providers = None;
                let mut selected_provider = None;
                let mut mcp_configs = None;
                let mut roles = RolesConfig::default();
                let mut prewalk = Lenient::unset();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "providers" => once(&mut providers, "providers", &mut map)?,
                        "selected_provider" => {
                            once(&mut selected_provider, "selected_provider", &mut map)?
                        }
                        "mcp_configs" => once(&mut mcp_configs, "mcp_configs", &mut map)?,
                        // Optional sections: every copy is kept as text.
                        "roles" => roles.section_mut().push(map.next_value()?),
                        "prewalk" => prewalk.section_mut().push(map.next_value()?),
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }

                Ok(ShaiConfig {
                    providers: providers.ok_or_else(|| de::Error::missing_field("providers"))?,
                    selected_provider: selected_provider
                        .ok_or_else(|| de::Error::missing_field("selected_provider"))?,
                    mcp_configs: mcp_configs.unwrap_or_default(),
                    roles,
                    prewalk,
                })
            }
        }

        deserializer.deserialize_map(ConfigVisitor)
    }
}

impl ShaiConfig {
    pub async fn pull_from_url(url: Url) -> Result<Self, Box<dyn std::error::Error>> {
        let response = reqwest::get(url).await?;
        let config_json = response.text().await?;
        Self::from_pulled_json(&config_json)
    }

    /// Parse a config that was downloaded rather than written by the user.
    ///
    /// Sections that send a session's data to additional models are opt-in,
    /// and only the user's own file may opt in: they are dropped here.
    fn from_pulled_json(config_json: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config: ShaiConfig = serde_json::from_str(config_json)?;
        config.roles = RolesConfig::default();
        config.prewalk = Lenient::unset();
        Ok(config)
    }

    pub fn add_provider(
        &mut self,
        provider: String,
        env_vars: std::collections::HashMap<String, String>,
        model: String,
    ) -> usize {
        let provider_config = ProviderConfig {
            provider,
            env_vars,
            model,
            tool_method: ToolCallMethod::FunctionCall,
        };

        self.providers.push(provider_config);
        self.providers.len() - 1
    }

    pub fn is_duplicate_config(
        &self,
        provider_name: &str,
        env_vars: &std::collections::HashMap<String, String>,
        model: &str,
    ) -> bool {
        self.providers.iter().any(|provider_config| {
            provider_config.provider == provider_name
                && provider_config.env_vars == *env_vars
                && provider_config.model.eq(model)
        })
    }

    pub fn get_selected_provider(&self) -> Option<&ProviderConfig> {
        self.providers.get(self.selected_provider)
    }

    pub fn get_selected_provider_mut(&mut self) -> Option<&mut ProviderConfig> {
        self.providers.get_mut(self.selected_provider)
    }

    pub fn set_selected_provider(&mut self, index: usize) -> Result<(), String> {
        if index < self.providers.len() {
            self.selected_provider = index;
            Ok(())
        } else {
            Err(format!(
                "Provider index {} out of bounds (have {} providers)",
                index,
                self.providers.len()
            ))
        }
    }

    pub fn config_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|_| {
                dirs::home_dir()
                    .map(|home| home.join(".config"))
                    .ok_or("Could not find home directory")
            })?;

        let shai_config_dir = config_dir.join("shai");
        std::fs::create_dir_all(&shai_config_dir)?;

        Ok(shai_config_dir.join("auth.config.json"))
    }

    pub(crate) fn legacy_config_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|_| {
                dirs::home_dir()
                    .map(|home| home.join(".config"))
                    .ok_or("Could not find home directory")
            })?;

        Ok(config_dir.join("shai").join("auth.config"))
    }

    pub fn load() -> Result<ShaiConfig, Box<dyn std::error::Error>> {
        Self::load_from_paths(&Self::config_path()?, &Self::legacy_config_path()?)
    }

    /// Load the config from `config_path`, or from `legacy_path` when the
    /// former does not exist. A missing file is an error, not a default.
    pub(crate) fn load_from_paths(
        config_path: &Path,
        legacy_path: &Path,
    ) -> Result<ShaiConfig, Box<dyn std::error::Error>> {
        for path in [config_path, legacy_path] {
            if path.exists() {
                let content_bytes = fs::read(path)?;
                let content_stripped = StripComments::new(&content_bytes[..]);
                let mut config: ShaiConfig = serde_json::from_reader(content_stripped)?;
                Self::validate_provider(&mut config);
                return Ok(config);
            }
        }

        Err("config file does not exist".into())
    }

    fn validate_provider(&mut self) {
        if self.providers.is_empty() || self.selected_provider >= self.providers.len() {
            self.selected_provider = 0;
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = Self::config_path()?;
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&config_path, content)?;

        // Set file permissions to 600 (user read/write only) on Unix systems
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&config_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&config_path, perms)?;
        }

        Ok(())
    }

    pub fn exists() -> bool {
        Self::config_path()
            .map(|path| path.exists())
            .unwrap_or(false)
    }

    /// Load the config, falling back to the default one.
    ///
    /// Returns a warning message only when a config file exists but could not
    /// be loaded; a missing file is the normal first-run case.
    pub fn load_or_default() -> (ShaiConfig, Option<String>) {
        match Self::load() {
            Ok(config) => (config, None),
            Err(e) => {
                let warning =
                    Self::exists().then(|| format!("Failed to load config, using default: {}", e));
                (ShaiConfig::default(), warning)
            }
        }
    }

    /// Set environment variables from the currently selected provider.
    ///
    /// Variables set by a previous call are first put back to what the process
    /// had before, so switching providers never leaves the old provider's values
    /// (e.g. an `OLLAMA_API_KEY`) behind for the env fallback to pick up.
    /// Variables the user exported themselves are left as they were.
    pub fn set_env_vars(&self) {
        let mut applied = APPLIED_ENV_VARS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        restore_env_vars(&mut applied);
        if let Some(provider_config) = self.get_selected_provider() {
            let mut set = |name: &str, value: &str| {
                applied.push((name.to_string(), std::env::var_os(name)));
                std::env::set_var(name, value);
            };
            for (name, value) in &provider_config.env_vars {
                set(name, value);
            }
            // Set model-specific environment variable if model is specified
            set("SHAI_MODEL", &provider_config.model);
            // Set provider-specific environment variable
            set("SHAI_PROVIDER", &provider_config.provider);
        }
    }

    /// Capture the provider variables currently exported to the process.
    pub fn snapshot_applied_env() -> AppliedEnvSnapshot {
        let applied = APPLIED_ENV_VARS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let current = applied
            .iter()
            .map(|(name, _)| (name.clone(), std::env::var_os(name)))
            .collect();
        AppliedEnvSnapshot { applied, current }
    }

    /// Restore the process environment to a previous [`Self::snapshot_applied_env`].
    ///
    /// Any variables written by a later [`Self::set_env_vars`] are undone first.
    pub fn restore_applied_env(snapshot: &AppliedEnvSnapshot) {
        let mut applied = APPLIED_ENV_VARS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        restore_env_vars(&mut applied);
        for (name, value) in &snapshot.current {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        *applied = snapshot.applied.clone();
    }

    pub fn remove_provider(&mut self, index: usize) -> Result<ProviderConfig, String> {
        if index >= self.providers.len() {
            return Err(format!(
                "Provider index {} out of bounds (have {} providers)",
                index,
                self.providers.len()
            ));
        }

        if self.providers.len() == 1 {
            return Err("Cannot remove the last provider".to_string());
        }

        let removed = self.providers.remove(index);

        // Adjust selected_provider if needed
        if self.selected_provider >= self.providers.len() {
            self.selected_provider = self.providers.len() - 1;
        } else if self.selected_provider > index {
            self.selected_provider -= 1;
        }

        Ok(removed)
    }

    pub fn list_providers(&self) -> Vec<(usize, &str, &str)> {
        self.providers
            .iter()
            .enumerate()
            .map(|(i, config)| (i, config.provider.as_str(), config.model.as_str()))
            .collect()
    }

    pub fn find_providers_by_type(&self, provider_type: &str) -> Vec<usize> {
        self.providers
            .iter()
            .enumerate()
            .filter_map(|(i, config)| {
                if config.provider == provider_type {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn add_mcp_config(&mut self, name: String, config: McpConfig) -> Option<McpConfig> {
        self.mcp_configs.insert(name, config)
    }

    pub fn remove_mcp_config(&mut self, name: &str) -> Option<McpConfig> {
        self.mcp_configs.remove(name)
    }

    pub fn get_mcp_config(&self, name: &str) -> Option<&McpConfig> {
        self.mcp_configs.get(name)
    }

    pub fn list_mcp_configs(&self) -> Vec<(String, String)> {
        self.mcp_configs
            .iter()
            .map(|(name, config)| {
                let description = match config {
                    McpConfig::Stdio { command, .. } => format!("stdio: {}", command),
                    McpConfig::Http { url, auth } => {
                        if auth.is_some() {
                            format!("http: {} (authenticated)", url)
                        } else {
                            format!("http: {}", url)
                        }
                    }
                    McpConfig::Sse { url } => format!("sse: {}", url),
                };
                (name.clone(), description)
            })
            .collect()
    }

    pub fn has_mcp_config(&self, name: &str) -> bool {
        self.mcp_configs.contains_key(name)
    }
}

impl Default for ShaiConfig {
    fn default() -> Self {
        Self {
            // default to ovhcloud qwen3 in anonymous mode
            providers: vec![ProviderConfig {
                provider: "ovhcloud".to_string(),
                env_vars: HashMap::from([(
                    String::from("OVH_BASE_URL"),
                    String::from(
                        "https://qwen-3-32b.endpoints.kepler.ai.cloud.ovh.net/api/openai_compat/v1",
                    ),
                )]),
                model: "Qwen3-32B".to_string(),
                tool_method: ToolCallMethod::FunctionCall,
            }],
            selected_provider: 0,
            mcp_configs: HashMap::new(),
            roles: RolesConfig::default(),
            prewalk: Lenient::unset(),
        }
    }
}

impl ShaiConfig {
    pub async fn get_llm() -> Result<(LlmClient, String), Box<dyn std::error::Error>> {
        let config = ShaiConfig::load().unwrap_or_else(|e| {
            tracing::warn!("Failed to load config, using default: {}", e);
            ShaiConfig::default()
        });
        config.get_llm_from_config().await
    }

    /// Build the LLM client and default model from this already-loaded config.
    /// Unlike [`ShaiConfig::get_llm`], this never loads the file again and never
    /// falls back to [`ShaiConfig::default`].
    ///
    /// This exports the selected provider's variables into the process
    /// environment, so child tools can see them. When a replacement is being
    /// built while a live agent is still running, use [`Self::llm_from_config`]
    /// instead and call [`Self::set_env_vars`] only after that agent is
    /// installed.
    pub async fn get_llm_from_config(
        &self,
    ) -> Result<(LlmClient, String), Box<dyn std::error::Error>> {
        self.set_env_vars();
        self.llm_from_config().await
    }

    /// Build the LLM client and configured model without writing provider
    /// variables into the process environment.
    ///
    /// Omitted settings are resolved against the original user environment
    /// (process env with [`Self::set_env_vars`] writes undone), then the
    /// selected provider's `env_vars` are applied. The live agent's exported
    /// overrides are therefore not inherited. The model is the one in the
    /// config, not `SHAI_MODEL`. Call [`Self::set_env_vars`] once this
    /// provider should actually be the one the process exports.
    pub async fn llm_from_config(&self) -> Result<(LlmClient, String), Box<dyn std::error::Error>> {
        let Some(provider_config) = self.get_selected_provider() else {
            return Err("No provider configured".into());
        };
        let env_vars = Self::env_vars_for_llm(provider_config);
        let llm = LlmClient::create_provider_from_map(&provider_config.provider, &env_vars)
            .map_err(|e| {
                format!(
                    "Failed to create {} client: {}",
                    provider_config.provider, e
                )
            })?;
        Ok((llm, provider_config.model.clone()))
    }

    /// Process environment with live-provider exports removed, then the
    /// selected provider's own `env_vars` overlaid.
    fn env_vars_for_llm(provider_config: &ProviderConfig) -> HashMap<String, String> {
        let mut env: HashMap<String, String> = std::env::vars().collect();
        {
            let applied = APPLIED_ENV_VARS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (name, previous) in applied.iter() {
                match previous {
                    Some(value) => match value.to_str() {
                        Some(value) => {
                            env.insert(name.clone(), value.to_string());
                        }
                        None => {
                            env.remove(name);
                        }
                    },
                    None => {
                        env.remove(name);
                    }
                }
            }
        }
        for (name, value) in &provider_config.env_vars {
            env.insert(name.clone(), value.clone());
        }
        env
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(provider: &str, env: &[(&str, &str)]) -> ShaiConfig {
        let mut config = ShaiConfig {
            providers: vec![],
            selected_provider: 0,
            mcp_configs: HashMap::new(),
            roles: RolesConfig::default(),
            prewalk: Lenient::unset(),
        };
        config.add_provider(
            provider.to_string(),
            env.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            "test-model".to_string(),
        );
        config
    }

    fn undo_set_env_vars() {
        let mut applied = APPLIED_ENV_VARS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        restore_env_vars(&mut applied);
    }

    #[test]
    fn config_keys_are_read_and_written_as_before_roles_existed() {
        for (json, expected) in [
            (r#"{"selected_provider": 0}"#, "missing field `providers`"),
            (r#"{"providers": []}"#, "missing field `selected_provider`"),
            (
                r#"{"providers": [], "providers": [], "selected_provider": 0}"#,
                "duplicate field `providers`",
            ),
            (
                r#"{"providers": [], "selected_provider": 0, "selected_provider": 1}"#,
                "duplicate field `selected_provider`",
            ),
            (
                r#"{"providers": [], "selected_provider": 0, "mcp_configs": {}, "mcp_configs": {}}"#,
                "duplicate field `mcp_configs`",
            ),
            (
                r#"{"providers": [], "selected_provider": "0"}"#,
                "invalid type",
            ),
            (
                r#"{"providers": [], "selected_provider": 0, "mcp_configs": null}"#,
                "invalid type",
            ),
        ] {
            let error = serde_json::from_str::<ShaiConfig>(json)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{json}: {error}");
        }

        // Unknown keys are ignored however often they appear, and
        // `mcp_configs` is optional.
        let config: ShaiConfig = serde_json::from_str(
            r#"{"future": 1, "providers": [], "future": {"a": [1, 2]}, "selected_provider": 3}"#,
        )
        .unwrap();
        assert!(config.providers.is_empty());
        assert_eq!(config.selected_provider, 3);
        assert!(config.mcp_configs.is_empty());

        // Without roles, the file that is written has the keys it always had.
        assert_eq!(
            serde_json::to_string(&config).unwrap(),
            r#"{"providers":[],"selected_provider":3,"mcp_configs":{}}"#
        );
        let null_roles: ShaiConfig =
            serde_json::from_str(r#"{"providers": [], "selected_provider": 3, "roles": null}"#)
                .unwrap();
        assert_eq!(
            serde_json::to_string(&null_roles).unwrap(),
            serde_json::to_string(&config).unwrap()
        );
    }

    #[test]
    fn pulled_config_cannot_turn_roles_on() {
        let pulled = ShaiConfig::from_pulled_json(
            r#"{
                "providers": [
                    {"provider": "ollama", "env_vars": {}, "model": "llama3", "tool_method": "FunctionCall"}
                ],
                "selected_provider": 0,
                "roles": {"planner": "ollama/other"},
                "prewalk": {"into": "planner"}
            }"#,
        )
        .unwrap();
        assert_eq!(pulled.providers.len(), 1);
        assert!(pulled.roles.is_unset());
        assert!(pulled.prewalk.is_unset());
        assert!(pulled.resolve_role("planner").unwrap().is_none());
    }

    #[tokio::test]
    async fn pull_from_url_drops_roles() {
        let mut server = mockito::Server::new_async().await;
        let served = server
            .mock("GET", "/starter.config")
            .with_status(200)
            .with_body(
                r#"{
                    "providers": [
                        {"provider": "ollama", "env_vars": {"OLLAMA_BASE_URL": "http://127.0.0.1:9/v1"}, "model": "llama3", "tool_method": "FunctionCall"}
                    ],
                    "selected_provider": 0,
                    "roles": {"planner": "ollama/other"}
                }"#,
            )
            .expect(1)
            .create_async()
            .await;

        let url = format!("{}/starter.config", server.url()).parse().unwrap();
        let pulled = ShaiConfig::pull_from_url(url).await.unwrap();
        served.assert_async().await;
        assert_eq!(pulled.providers.len(), 1);
        assert!(pulled.roles.is_unset());
        assert!(pulled.resolve_role("planner").unwrap().is_none());
    }

    // Serializes tests that read or write APPLIED_ENV_VARS / set_env_vars.
    // Unique variable names are not enough: undo_set_env_vars drains the
    // whole tracked list, which would drop another test's writes.
    static ENV_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn config_with_model(provider: &str, env: &[(&str, &str)], model: &str) -> ShaiConfig {
        let mut config = config_with(provider, env);
        if let Some(provider) = config.get_selected_provider_mut() {
            provider.model = model.to_string();
        }
        config
    }

    // One test owns these variable names so parallel tests cannot race on them.
    #[test]
    fn switching_provider_does_not_keep_previous_provider_vars() {
        let _guard = ENV_TEST_LOCK.blocking_lock();
        const KEY: &str = "SHAI_TEST_STALE_PROVIDER_API_KEY";
        const URL: &str = "SHAI_TEST_STALE_PROVIDER_BASE_URL";
        std::env::remove_var(KEY);
        std::env::set_var(URL, "http://exported.example.com/v1");

        let keyed = config_with(
            "ollama",
            &[(KEY, "secret-token"), (URL, "https://ollama.com/v1")],
        );
        keyed.set_env_vars();
        assert_eq!(std::env::var(KEY).as_deref(), Ok("secret-token"));
        assert_eq!(std::env::var(URL).as_deref(), Ok("https://ollama.com/v1"));
        assert_eq!(std::env::var("SHAI_PROVIDER").as_deref(), Ok("ollama"));

        // Switching to an anonymous config must not keep sending the old key,
        // and a value the user exported before is back in place.
        let anonymous = config_with("ollama", &[]);
        anonymous.set_env_vars();
        assert!(std::env::var_os(KEY).is_none(), "stale key left in env");
        assert_eq!(
            std::env::var(URL).as_deref(),
            Ok("http://exported.example.com/v1")
        );

        // Setting the same config twice is idempotent.
        keyed.set_env_vars();
        keyed.set_env_vars();
        assert_eq!(std::env::var(KEY).as_deref(), Ok("secret-token"));
        undo_set_env_vars();
        assert!(std::env::var_os(KEY).is_none());
        assert_eq!(
            std::env::var(URL).as_deref(),
            Ok("http://exported.example.com/v1")
        );
        std::env::remove_var(URL);
    }

    #[tokio::test]
    async fn llm_from_config_does_not_export_provider_env() {
        let _guard = ENV_TEST_LOCK.lock().await;
        const KEY: &str = "SHAI_TEST_LLM_FROM_CONFIG_ENV";
        std::env::remove_var(KEY);
        let config = config_with("not-a-real-provider", &[(KEY, "must-not-be-exported")]);
        let error = config
            .llm_from_config()
            .await
            .expect_err("an unknown provider must fail to build");
        assert!(error.to_string().contains("not-a-real-provider"), "{error}");
        assert!(
            std::env::var_os(KEY).is_none(),
            "llm_from_config must not write provider variables"
        );
    }

    #[test]
    fn restore_applied_env_puts_back_a_snapshot() {
        let _guard = ENV_TEST_LOCK.blocking_lock();
        const KEY: &str = "SHAI_TEST_ENV_SNAPSHOT_KEY";
        std::env::remove_var(KEY);

        let first = config_with("openai", &[(KEY, "live-agent-value")]);
        first.set_env_vars();
        let snapshot = ShaiConfig::snapshot_applied_env();
        assert_eq!(std::env::var(KEY).as_deref(), Ok("live-agent-value"));

        let second = config_with("openai", &[(KEY, "replacement-value")]);
        second.set_env_vars();
        assert_eq!(std::env::var(KEY).as_deref(), Ok("replacement-value"));

        ShaiConfig::restore_applied_env(&snapshot);
        assert_eq!(std::env::var(KEY).as_deref(), Ok("live-agent-value"));

        undo_set_env_vars();
        assert!(std::env::var_os(KEY).is_none());
    }

    #[tokio::test]
    async fn llm_from_config_uses_the_configured_model_not_shai_model() {
        let _guard = ENV_TEST_LOCK.lock().await;
        let previous_model = std::env::var("SHAI_MODEL").ok();
        std::env::remove_var("SHAI_MODEL");

        let first = config_with_model(
            "openai",
            &[("OPENAI_API_KEY", "first-key")],
            "configured-model",
        );
        let (_, model) = first
            .llm_from_config()
            .await
            .expect("openai client builds from the config key");
        assert_eq!(model, "configured-model");
        assert!(
            std::env::var_os("SHAI_MODEL").is_none(),
            "first start must not read or write SHAI_MODEL"
        );

        first.set_env_vars();
        assert_eq!(
            std::env::var("SHAI_MODEL").as_deref(),
            Ok("configured-model")
        );

        let replacement = config_with_model(
            "openai",
            &[("OPENAI_API_KEY", "replacement-key")],
            "replacement-model",
        );
        let (_, model) = replacement
            .llm_from_config()
            .await
            .expect("replacement client builds from its own key");
        assert_eq!(model, "replacement-model");
        assert_eq!(
            std::env::var("SHAI_MODEL").as_deref(),
            Ok("configured-model"),
            "llm_from_config must not export the replacement model"
        );

        undo_set_env_vars();
        match previous_model {
            Some(value) => std::env::set_var("SHAI_MODEL", value),
            None => std::env::remove_var("SHAI_MODEL"),
        }
    }

    #[tokio::test]
    async fn llm_from_config_does_not_inherit_a_live_provider_key() {
        let _guard = ENV_TEST_LOCK.lock().await;
        const KEY: &str = "OLLAMA_API_KEY";
        const URL: &str = "OLLAMA_BASE_URL";
        let previous_key = std::env::var(KEY).ok();
        let previous_url = std::env::var(URL).ok();
        std::env::remove_var(KEY);
        std::env::remove_var(URL);

        let live = config_with(
            "ollama",
            &[(KEY, "live-key"), (URL, "http://live.example/v1")],
        );
        live.set_env_vars();
        assert_eq!(std::env::var(KEY).as_deref(), Ok("live-key"));

        let replacement = config_with("ollama", &[(URL, "http://replacement.example/v1")]);
        let env = ShaiConfig::env_vars_for_llm(replacement.get_selected_provider().unwrap());
        assert_eq!(
            env.get(KEY),
            None,
            "a live-provider key the user did not export must not be inherited"
        );
        assert_eq!(
            env.get(URL).map(String::as_str),
            Some("http://replacement.example/v1")
        );
        replacement
            .llm_from_config()
            .await
            .expect("replacement ollama client builds from its own URL");

        // A value the user exported themselves is still used when the
        // replacement omits that setting.
        undo_set_env_vars();
        std::env::set_var(KEY, "user-key");
        live.set_env_vars();
        assert_eq!(std::env::var(KEY).as_deref(), Ok("live-key"));
        let env = ShaiConfig::env_vars_for_llm(replacement.get_selected_provider().unwrap());
        assert_eq!(env.get(KEY).map(String::as_str), Some("user-key"));

        undo_set_env_vars();
        match previous_key {
            Some(value) => std::env::set_var(KEY, value),
            None => std::env::remove_var(KEY),
        }
        match previous_url {
            Some(value) => std::env::set_var(URL, value),
            None => std::env::remove_var(URL),
        }
    }
}
