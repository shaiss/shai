use super::api::OpenRouterModelsResponse;
use crate::chat::{ChatClient, NoHooks};
use crate::provider::{EnvVar, LlmError, LlmProvider, LlmStream, ProviderInfo};
use async_trait::async_trait;
use futures::StreamExt;
use openai_dive::v1::resources::{
    chat::{ChatCompletionChunkResponse, ChatCompletionParameters, ChatCompletionResponse},
    model::ListModelResponse,
};
use reqwest;

const OPENROUTER_API_BASE: &str = "https://openrouter.ai/api/v1";

pub struct OpenRouterProvider {
    /// Uses shai's ChatClient (not openai_dive's) so OpenRouter-specific
    /// finish_reason values such as "error" are handled instead of failing to parse.
    client: ChatClient,
    api_key: String,
    base_url: String,
    http_client: reqwest::Client,
}

impl OpenRouterProvider {
    pub fn new(api_key: String) -> Self {
        let client = ChatClient::new(api_key.clone(), OPENROUTER_API_BASE.to_string());
        Self {
            client,
            api_key,
            base_url: OPENROUTER_API_BASE.to_string(),
            http_client: reqwest::Client::new(),
        }
    }

    /// Create OpenRouter provider from environment variables
    /// Returns None if required environment variables are not set
    pub fn from_env() -> Option<Self> {
        std::env::var("OPENROUTER_API_KEY").ok().map(Self::new)
    }

    /// Get OpenRouter models using their native API format
    pub async fn openrouter_models(&self) -> Result<OpenRouterModelsResponse, LlmError> {
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
                "OpenRouter API error {}: {}",
                status, text
            ))) as LlmError);
        }

        let openrouter_response: OpenRouterModelsResponse =
            response.json().await.map_err(|e| Box::new(e) as LlmError)?;

        Ok(openrouter_response)
    }
}

#[async_trait]
impl LlmProvider for OpenRouterProvider {
    async fn models(&self) -> Result<ListModelResponse, LlmError> {
        let openrouter_response = self.openrouter_models().await?;
        Ok(openrouter_response.to_openai_models_response())
    }

    async fn default_model(&self) -> Result<String, LlmError> {
        let models = self.models().await?;

        let keywords = ["free"];
        models
            .data
            .iter()
            .find(|m| keywords.iter().any(|kw| m.id.to_lowercase().contains(kw)))
            .or_else(|| models.data.first())
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
        // Ensure streaming is enabled
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
        true
    }

    fn supports_structured_output(&self, model: String) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "openrouter"
    }

    fn info() -> ProviderInfo {
        ProviderInfo {
            name: "openrouter",
            display_name: "OpenRouter (Multiple AI Providers)",
            env_vars: vec![EnvVar::required("OPENROUTER_API_KEY", "OpenRouter API key")],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openai_dive::v1::resources::chat::{
        ChatCompletionParametersBuilder, ChatMessage, ChatMessageContent,
    };

    #[tokio::test]
    async fn chat_reports_finish_reason_error_instead_of_parse_failure() {
        let body = r#"{"id":"gen-1","object":"chat.completion","created":1700000000,"model":"openai/gpt-oss-120b","choices":[{"index":0,"message":{"role":"assistant","content":""},"finish_reason":"error","error":{"code":"server_error","message":"Provider disconnected unexpectedly"}}]}"#;
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/chat/completions")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let mut provider = OpenRouterProvider::new("test-key".to_string());
        provider.client = ChatClient::new("test-key".to_string(), server.url());

        let request = ChatCompletionParametersBuilder::default()
            .model("openai/gpt-oss-120b")
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
