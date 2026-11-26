use crate::chat::{ChatClient, NoHooks};
use crate::provider::{EnvVar, LlmError, LlmProvider, LlmStream, ProviderInfo};
use async_trait::async_trait;
use futures::StreamExt;
use openai_dive::v1::resources::{
    chat::{ChatCompletionParameters, ChatCompletionResponse},
    model::ListModelResponse,
};
use reqwest;

const ORCAROUTER_API_BASE: &str = "https://api.orcarouter.ai/v1";

/// True for OrcaRouter's free router and any model id ending in `-free`.
///
/// Compared case-insensitively after trimming. `orcarouter/auto` is not
/// treated as free here; it is a paid-or-mixed router, not a free-model id.
pub(crate) fn is_free_model_id(id: &str) -> bool {
    let id = id.trim().to_ascii_lowercase();
    id == "orcarouter/free" || id.ends_with("-free")
}

fn exclude_free_models(mut models: ListModelResponse) -> ListModelResponse {
    models.data.retain(|model| !is_free_model_id(&model.id));
    models
}

pub struct OrcaRouterProvider {
    /// Uses shai's ChatClient (not openai_dive's) so router-style
    /// finish_reason values such as "error" are handled instead of failing
    /// to parse.
    client: ChatClient,
    api_key: String,
    base_url: String,
    http_client: reqwest::Client,
}

impl OrcaRouterProvider {
    pub fn new(api_key: String) -> Self {
        let client = ChatClient::new(api_key.clone(), ORCAROUTER_API_BASE.to_string());
        Self {
            client,
            api_key,
            base_url: ORCAROUTER_API_BASE.to_string(),
            http_client: reqwest::Client::new(),
        }
    }

    /// Create an OrcaRouter provider from environment variables.
    /// Returns None if `ORCAROUTER_API_KEY` is not set.
    pub fn from_env() -> Option<Self> {
        std::env::var("ORCAROUTER_API_KEY").ok().map(Self::new)
    }

    async fn list_models(&self) -> Result<ListModelResponse, LlmError> {
        let url = format!("{}/models", self.base_url);

        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| Box::new(e) as LlmError)?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Box::new(std::io::Error::other(format!(
                "OrcaRouter API error {}: {}",
                status, text
            ))) as LlmError);
        }

        let models: ListModelResponse =
            response.json().await.map_err(|e| Box::new(e) as LlmError)?;
        Ok(exclude_free_models(models))
    }
}

#[async_trait]
impl LlmProvider for OrcaRouterProvider {
    async fn models(&self) -> Result<ListModelResponse, LlmError> {
        self.list_models().await
    }

    async fn default_model(&self) -> Result<String, LlmError> {
        let models = self.models().await?;
        models
            .data
            .first()
            .map(|m| m.id.clone())
            .ok_or_else(|| "no model available".into())
    }

    async fn chat(
        &self,
        request: ChatCompletionParameters,
    ) -> Result<ChatCompletionResponse, LlmError> {
        let response = self
            .client
            .chat_completion(&request, &NoHooks)
            .await
            .map_err(|e| Box::new(e) as LlmError)?;
        Ok(response)
    }

    async fn chat_stream(
        &self,
        mut request: ChatCompletionParameters,
    ) -> Result<LlmStream, LlmError> {
        request.stream = Some(true);

        let stream = self
            .client
            .chat_completion_stream(&request, NoHooks)
            .await
            .map_err(|e| Box::new(e) as LlmError)?;

        let converted_stream = stream.map(|result| result.map_err(|e| Box::new(e) as LlmError));

        Ok(Box::new(Box::pin(converted_stream)))
    }

    fn supports_functions(&self, model: String) -> bool {
        let _ = model;
        true
    }

    fn supports_structured_output(&self, model: String) -> bool {
        let _ = model;
        true
    }

    fn name(&self) -> &'static str {
        "orcarouter"
    }

    fn info() -> ProviderInfo {
        ProviderInfo {
            name: "orcarouter",
            display_name: "OrcaRouter (Multiple AI Providers)",
            env_vars: vec![EnvVar::required("ORCAROUTER_API_KEY", "OrcaRouter API key")],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openai_dive::v1::resources::chat::{
        ChatCompletionParametersBuilder, ChatMessage, ChatMessageContent,
    };
    use openai_dive::v1::resources::model::Model;

    fn model(id: &str) -> Model {
        Model {
            id: id.to_string(),
            created: Some(1),
            object: "model".to_string(),
            owned_by: "test".to_string(),
        }
    }

    fn list(ids: &[&str]) -> ListModelResponse {
        ListModelResponse {
            object: "list".to_string(),
            data: ids.iter().copied().map(model).collect(),
        }
    }

    fn ids_of(models: &ListModelResponse) -> Vec<&str> {
        models.data.iter().map(|m| m.id.as_str()).collect()
    }

    #[test]
    fn is_free_model_id_matches_the_free_router_and_free_suffix() {
        assert!(is_free_model_id("orcarouter/free"));
        assert!(is_free_model_id(" ORCAROUTER/FREE "));
        assert!(is_free_model_id("deepseek/deepseek-v4.1-flash-free"));
        assert!(is_free_model_id("glm-5.3-flash-free"));
        assert!(is_free_model_id("Qwen/Qwen3-Free"));
        assert!(!is_free_model_id("orcarouter/auto"));
        assert!(!is_free_model_id("openai/gpt-4o-mini"));
        assert!(!is_free_model_id("anthropic/claude-sonnet-4.6"));
        assert!(!is_free_model_id("free"));
        assert!(!is_free_model_id("orcarouter/free-tier"));
    }

    #[test]
    fn exclude_free_models_drops_free_ids_and_keeps_the_rest() {
        let filtered = exclude_free_models(list(&[
            "orcarouter/free",
            "deepseek/hy3-free",
            "anthropic/claude-sonnet-4.6",
            "orcarouter/auto",
            "openai/gpt-4o-mini",
        ]));
        assert_eq!(
            ids_of(&filtered),
            [
                "anthropic/claude-sonnet-4.6",
                "orcarouter/auto",
                "openai/gpt-4o-mini"
            ]
        );
    }

    #[test]
    fn declared_key_is_orcarouter_api_key_not_orca_key() {
        let info = OrcaRouterProvider::info();
        assert_eq!(info.name, "orcarouter");
        assert_eq!(info.env_vars.len(), 1);
        assert_eq!(info.env_vars[0].name, "ORCAROUTER_API_KEY");
        assert!(info.env_vars[0].required);
        assert!(info.env_vars.iter().all(|var| var.name != "ORCA_KEY"));
    }

    fn models_body(ids: &[&str]) -> String {
        let data: Vec<String> = ids
            .iter()
            .map(|id| format!(r#"{{"id":"{id}","object":"model","created":1,"owned_by":"test"}}"#))
            .collect();
        format!(r#"{{"object":"list","data":[{}]}}"#, data.join(","))
    }

    async fn provider_against(server: &mockito::Server) -> OrcaRouterProvider {
        let mut provider = OrcaRouterProvider::new("test-key".to_string());
        provider.base_url = server.url();
        provider.client = ChatClient::new("test-key".to_string(), server.url());
        provider
    }

    #[tokio::test]
    async fn models_omits_free_ids_from_the_catalog() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/models")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(models_body(&[
                "orcarouter/free",
                "deepseek/deepseek-v4.1-flash-free",
                "anthropic/claude-sonnet-4.6",
                "orcarouter/auto",
            ]))
            .create_async()
            .await;

        let provider = provider_against(&server).await;
        let models = provider.models().await.expect("models");
        assert_eq!(
            ids_of(&models),
            ["anthropic/claude-sonnet-4.6", "orcarouter/auto"]
        );
    }

    #[tokio::test]
    async fn default_model_skips_leading_free_ids() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/models")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(models_body(&[
                "orcarouter/free",
                "glm-5.3-flash-free",
                "openai/gpt-4o-mini",
                "anthropic/claude-sonnet-4.6",
            ]))
            .create_async()
            .await;

        let provider = provider_against(&server).await;
        let default = provider.default_model().await.expect("default model");
        assert_eq!(default, "openai/gpt-4o-mini");
        assert!(!is_free_model_id(&default));
    }

    #[tokio::test]
    async fn default_model_errors_when_only_free_models_are_listed() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/models")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(models_body(&["orcarouter/free", "hy3-free"]))
            .create_async()
            .await;

        let provider = provider_against(&server).await;
        let error = provider
            .default_model()
            .await
            .expect_err("only free models should not yield a default")
            .to_string();
        assert!(error.contains("no model available"), "{error}");
    }

    #[tokio::test]
    async fn chat_reports_finish_reason_error_instead_of_parse_failure() {
        let body = r#"{"id":"gen-1","object":"chat.completion","created":1700000000,"model":"openai/gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":""},"finish_reason":"error","error":{"code":"server_error","message":"Provider disconnected unexpectedly"}}]}"#;
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/chat/completions")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let provider = provider_against(&server).await;
        let request = ChatCompletionParametersBuilder::default()
            .model("openai/gpt-4o-mini")
            .messages(vec![ChatMessage::User {
                content: ChatMessageContent::Text("hello".into()),
                name: None,
            }])
            .build()
            .unwrap();
        let message = provider
            .chat(request)
            .await
            .expect_err("finish_reason error should be an error")
            .to_string();
        assert!(
            message.contains("Provider disconnected unexpectedly"),
            "{}",
            message
        );
        assert!(!message.contains("unknown variant"), "{}", message);
    }
}
