pub mod clifixer;
pub mod coder;
pub mod compacter;
pub mod gerund;
pub mod searcher;

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::sync::Once;

    use shai_llm::client::LlmClient;

    /// Mutex to serialize tests that call `std::env::set_current_dir`.
    /// Since the working directory is process-wide, parallel tests would
    /// otherwise interfere with each other.
    pub static DIR_TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    static INIT_LOGGING: Once = Once::new();

    /// Env var that opts in to tests that call a real LLM provider.
    pub const LIVE_LLM_TESTS_ENV: &str = "SHAI_LIVE_LLM_TESTS";

    /// True only when the gate value is exactly "1".
    pub fn live_llm_gate(value: Option<&str>) -> bool {
        value == Some("1")
    }

    /// Returns true (after printing a one-line reason) when live LLM tests are
    /// not enabled, so the caller can `return` early. Without this gate these
    /// tests would fall back to the built-in provider config and try to reach
    /// a real endpoint during a plain `cargo test`.
    pub fn skip_unless_live_llm(test_name: &str) -> bool {
        let value = std::env::var(LIVE_LLM_TESTS_ENV).ok();
        if live_llm_gate(value.as_deref()) {
            return false;
        }
        println!(
            "skipping {}: live LLM test, set {}=1 to run",
            test_name, LIVE_LLM_TESTS_ENV
        );
        true
    }

    #[test]
    fn live_llm_gate_requires_exactly_one() {
        assert!(live_llm_gate(Some("1")));
        assert!(!live_llm_gate(None));
        assert!(!live_llm_gate(Some("")));
        assert!(!live_llm_gate(Some("0")));
        assert!(!live_llm_gate(Some("true")));
    }

    /// Initialize logging for tests. Safe to call multiple times.
    pub fn init_test_logging() {
        INIT_LOGGING.call_once(|| {
            let _ = crate::logging::LoggingConfig::from_env().init();
        });
    }

    /// Helper to get an LLM client + model from ShaiConfig.
    /// Falls back to environment variables if no config file exists.
    pub async fn get_llm() -> Result<(std::sync::Arc<LlmClient>, String), Box<dyn std::error::Error>>
    {
        let (client, model) = crate::config::config::ShaiConfig::get_llm().await?;
        Ok((std::sync::Arc::new(client), model))
    }

    /// Try to get an LLM client from available environment variables, fallback to Ollama
    pub fn get_test_llm_client() -> LlmClient {
        if let Some(client) = LlmClient::from_env_ovhcloud() {
            return client;
        }
        if let Some(client) = LlmClient::from_env_openai() {
            return client;
        }
        if let Some(client) = LlmClient::from_env_anthropic() {
            return client;
        }
        if let Some(client) = LlmClient::from_env_openrouter() {
            return client;
        }
        if let Some(client) = LlmClient::from_env_openai_compatible() {
            return client;
        }
        if let Some(client) = LlmClient::from_env_mistral() {
            return client;
        }

        // Fallback to Ollama (always returns Some)
        LlmClient::from_env_ollama().expect("Ollama should always be available as fallback")
    }

    /// Get the default model for a provider, with fallbacks
    pub async fn get_test_model_for_provider(client: &LlmClient) -> String {
        client
            .default_model()
            .await
            .unwrap_or_else(|_| match client.provider_name() {
                "openai" => "gpt-3.5-turbo".to_string(),
                "anthropic" => "claude-3-haiku-20240307".to_string(),
                "openrouter" => "openai/gpt-3.5-turbo".to_string(),
                "ovhcloud" => "gpt-3.5-turbo".to_string(),
                "mistral" => "mistral-tiny".to_string(),
                "ollama" => "llama2".to_string(),
                _ => "gpt-3.5-turbo".to_string(),
            })
    }
}
