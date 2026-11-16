/// Blatant COPY / PASTE from openai_dive to add hooks for json manipulation
///
// Flexible chat client with JSON manipulation hooks
use async_trait::async_trait;
use futures::{Stream, StreamExt};
use openai_dive::v1::{
    error::APIError,
    resources::{
        chat::{ChatCompletionChunkResponse, ChatCompletionParameters, ChatCompletionResponse},
        shared::FinishReason,
    },
};
use reqwest::{Method, RequestBuilder};
use reqwest_eventsource::{Event, EventSource, RequestBuilderExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::pin::Pin;

use crate::error::{retry_after_from_headers, RateLimitedError};

/// Error type for [`ChatClient`].
///
/// Wraps the upstream [`APIError`] while adding a [`RateLimitedError`] variant
/// that preserves the `Retry-After` hint, which `APIError` discards.
#[derive(Debug)]
pub enum ChatError {
    Api(APIError),
    RateLimited(RateLimitedError),
}

impl ChatError {
    /// Return the `Retry-After` delay if this error carries one.
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        match self {
            ChatError::RateLimited(e) => e.retry_after,
            ChatError::Api(_) => None,
        }
    }
}

impl From<APIError> for ChatError {
    fn from(e: APIError) -> Self {
        ChatError::Api(e)
    }
}

impl fmt::Display for ChatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChatError::Api(e) => write!(f, "{}", e),
            ChatError::RateLimited(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ChatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ChatError::Api(e) => Some(e),
            ChatError::RateLimited(e) => Some(e),
        }
    }
}

/// Normalize `finish_reason` values that openai_dive's [`FinishReason`] cannot
/// deserialize, so one unexpected value does not fail the whole response with
/// "unknown variant".
///
/// - `"error"` (sent by OpenRouter when the upstream provider fails mid-generation)
///   is turned into an [`APIError::ServerError`] carrying the provider's error
///   code and message when present. It stays retryable.
/// - Any other unknown value is mapped to [`FinishReason::Other`] and logged.
pub(crate) fn normalize_finish_reasons(json: &mut Value) -> Result<(), APIError> {
    let top_level_error = json.get("error").filter(|e| !e.is_null()).cloned();
    let has_choices = json
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|c| !c.is_empty());
    if !has_choices {
        // OpenRouter: a 200 body (or SSE event) with only `error` and no choices.
        return match top_level_error {
            Some(error) => Err(provider_error("provider returned an error", &error)),
            None => Ok(()),
        };
    }
    let Some(choices) = json.get_mut("choices").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    for choice in choices {
        let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) else {
            continue;
        };
        if reason == "error" {
            let prefix = "provider returned finish_reason \"error\"";
            return Err(match choice.get("error").or(top_level_error.as_ref()) {
                Some(error) => provider_error(prefix, error),
                None => APIError::ServerError(format!("{}: no error details in response", prefix)),
            });
        }
        if serde_json::from_value::<FinishReason>(Value::String(reason.to_string())).is_err() {
            tracing::warn!(
                target: "shai_llm::chat",
                "unknown finish_reason {:?}, treating it as \"OTHER\"",
                reason
            );
            choice["finish_reason"] = Value::String("OTHER".to_string());
        }
    }
    Ok(())
}

/// Map a provider error object to an [`APIError`], using its numeric `code`
/// (OpenRouter mirrors the HTTP status there) so deterministic client errors
/// are not retried.
fn provider_error(prefix: &str, error: &Value) -> APIError {
    let message = format!("{}: {}", prefix, describe_provider_error(error));
    match error.get("code").and_then(Value::as_u64) {
        Some(400 | 413 | 422) => APIError::InvalidRequestError(message),
        Some(401) => APIError::AuthenticationError(message),
        Some(402 | 403) => APIError::PermissionError(message),
        Some(404) => APIError::NotFoundError(message),
        _ => APIError::ServerError(message),
    }
}

/// Render a provider error object (`{"code": .., "message": ..}`) or plain value.
fn describe_provider_error(error: &Value) -> String {
    let message = error.get("message").and_then(Value::as_str);
    let code = error.get("code").map(|c| match c {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    });
    match (code, message) {
        (Some(code), Some(message)) => format!("{} ({})", message, code),
        (None, Some(message)) => message.to_string(),
        _ => error.to_string(),
    }
}

/// Trait for JSON manipulation hooks
#[async_trait]
pub trait JsonHooks: Send + Sync {
    /// Called before sending JSON to the API
    async fn before_send(&self, json: Value) -> Result<Value, APIError> {
        Ok(json) // Default: no modification
    }

    /// Called after receiving JSON from the API (non-streaming)
    async fn after_receive(&self, json: Value) -> Result<Value, APIError> {
        Ok(json) // Default: no modification
    }

    /// Called after receiving JSON from the API (streaming chunks)
    async fn after_receive_stream(&self, json: Value) -> Result<Value, APIError> {
        // Default: use the same logic as after_receive
        self.after_receive(json).await
    }
}

/// Default implementation with no hooks
pub struct NoHooks;

#[async_trait]
impl JsonHooks for NoHooks {}

/// Flexible chat client
#[derive(Clone, Debug)]
pub struct ChatClient {
    pub http_client: reqwest::Client,
    pub base_url: String,
    pub api_key: String,
    pub headers: Option<HashMap<String, String>>,
    pub organization: Option<String>,
    pub project: Option<String>,
}

impl ChatClient {
    /// Create a new chat client
    pub fn new(api_key: String, base_url: String) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            base_url,
            api_key,
            headers: None,
            organization: None,
            project: None,
        }
    }

    /// Build a request with authentication headers
    fn build_request(&self, method: Method, path: &str, content_type: &str) -> RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self
            .http_client
            .request(method, &url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .bearer_auth(&self.api_key);

        if let Some(headers) = &self.headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        if let Some(organization) = &self.organization {
            request = request.header("OpenAI-Organization", organization);
        }

        if let Some(project) = &self.project {
            request = request.header("OpenAI-Project", project);
        }

        request
    }

    /// Map an HTTP status to the corresponding [`ChatError`].
    ///
    /// `retry_after` must be read from the response headers before the body
    /// is consumed.
    fn error_from_status(
        status: reqwest::StatusCode,
        retry_after: Option<std::time::Duration>,
        error_text: String,
    ) -> ChatError {
        match status.as_u16() {
            400 => ChatError::Api(APIError::InvalidRequestError(error_text)),
            401 => ChatError::Api(APIError::AuthenticationError(error_text)),
            403 => ChatError::Api(APIError::PermissionError(error_text)),
            404 => ChatError::Api(APIError::NotFoundError(error_text)),
            429 | 503 => ChatError::RateLimited(RateLimitedError::new(
                status.as_u16(),
                retry_after,
                error_text,
            )),
            _ => ChatError::Api(APIError::UnknownError(status.as_u16(), error_text)),
        }
    }

    /// Check status code and handle errors.
    ///
    /// Rate-limiting responses (429/503) are surfaced as [`ChatError::RateLimited`]
    /// so the caller can honor the `Retry-After` header. The header must be read
    /// before the body is consumed.
    async fn check_status_code(
        result: Result<reqwest::Response, reqwest::Error>,
    ) -> Result<reqwest::Response, ChatError> {
        match result {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(response)
                } else {
                    let status = response.status();
                    let retry_after = retry_after_from_headers(response.headers());
                    let error_text = response.text().await.unwrap_or_default();
                    Err(Self::error_from_status(status, retry_after, error_text))
                }
            }
            Err(error) => Err(ChatError::Api(APIError::ParseError(error.to_string()))),
        }
    }

    /// Chat completion with JSON hooks
    pub async fn chat_completion<H: JsonHooks>(
        &self,
        parameters: &ChatCompletionParameters,
        hooks: &H,
    ) -> Result<ChatCompletionResponse, ChatError> {
        // Serialize to JSON and apply before_send hook
        let mut json =
            serde_json::to_value(parameters).map_err(|e| APIError::ParseError(e.to_string()))?;
        json = hooks.before_send(json).await?;

        // Send request
        let result = self
            .build_request(Method::POST, "/chat/completions", "application/json")
            .json(&json)
            .send()
            .await;

        let response = Self::check_status_code(result).await?;

        // Get response text and apply after_receive hook
        let response_text = response
            .text()
            .await
            .map_err(|error| APIError::ParseError(error.to_string()))?;

        let mut response_json: Value = serde_json::from_str(&response_text)
            .map_err(|e| APIError::ParseError(e.to_string()))?;

        response_json = hooks.after_receive(response_json).await?;
        normalize_finish_reasons(&mut response_json)?;

        // Deserialize the modified JSON
        let completion_response: ChatCompletionResponse = serde_json::from_value(response_json)
            .map_err(|e| APIError::ParseError(e.to_string()))?;

        Ok(completion_response)
    }

    /// Chat completion streaming with JSON hooks
    pub async fn chat_completion_stream<H: JsonHooks + 'static>(
        &self,
        parameters: &ChatCompletionParameters,
        hooks: H,
    ) -> Result<
        Pin<Box<dyn Stream<Item = Result<ChatCompletionChunkResponse, APIError>> + Send>>,
        ChatError,
    > {
        // Serialize to JSON and apply before_send hook
        let mut json =
            serde_json::to_value(parameters).map_err(|e| APIError::ParseError(e.to_string()))?;
        json = hooks.before_send(json).await?;

        // Create event source for streaming
        let mut event_source = self
            .build_request(Method::POST, "/chat/completions", "application/json")
            .json(&json)
            .eventsource()
            .map_err(|e| APIError::ParseError(e.to_string()))?;

        // Wait for the connection to be established before returning the
        // stream. A healthy connection emits `Event::Open` first; HTTP errors
        // (non-200 status, wrong content type) would otherwise only surface
        // as stream items, after the caller's retry loop has already accepted
        // the stream. Surfacing them here lets `LlmClient::chat_stream` retry
        // and honor `Retry-After` exactly like the non-streaming path.
        match event_source.next().await {
            Some(Ok(Event::Open)) => {}
            Some(Err(reqwest_eventsource::Error::InvalidStatusCode(status, response))) => {
                let retry_after = retry_after_from_headers(response.headers());
                let error_text = response.text().await.unwrap_or_default();
                return Err(Self::error_from_status(status, retry_after, error_text));
            }
            Some(Err(reqwest_eventsource::Error::InvalidContentType(content_type, response))) => {
                let error_text = response.text().await.unwrap_or_default();
                return Err(ChatError::Api(APIError::StreamError(format!(
                    "unexpected content-type {:?}: {}",
                    content_type, error_text
                ))));
            }
            Some(Err(e)) => return Err(ChatError::Api(APIError::StreamError(e.to_string()))),
            Some(Ok(_)) => {
                return Err(ChatError::Api(APIError::StreamError(
                    "unexpected event before stream open".to_string(),
                )));
            }
            None => {
                return Err(ChatError::Api(APIError::StreamError(
                    "event stream closed before opening".to_string(),
                )));
            }
        }

        // Return stream that processes events
        let stream = async_stream::stream! {
            let mut event_source = event_source;
            while let Some(event) = event_source.next().await {
                match event {
                    Ok(Event::Open) => {}
                    Ok(Event::Message(message)) => {
                        if message.data == "[DONE]" {
                            break;
                        }

                        // Parse the event data
                        match serde_json::from_str::<Value>(&message.data) {
                            Ok(json) => {
                                // Apply after_receive_stream hook
                                match hooks.after_receive_stream(json).await {
                                    Ok(mut modified_json) => {
                                        if let Err(e) = normalize_finish_reasons(&mut modified_json) {
                                            yield Err(e);
                                            break;
                                        }
                                        // Deserialize the modified JSON
                                        match serde_json::from_value::<ChatCompletionChunkResponse>(modified_json) {
                                            Ok(chunk) => yield Ok(chunk),
                                            Err(e) => yield Err(APIError::ParseError(e.to_string())),
                                        }
                                    }
                                    Err(e) => yield Err(e),
                                }
                            }
                            Err(e) => yield Err(APIError::ParseError(e.to_string())),
                        }
                    }
                    Err(e) => yield Err(APIError::StreamError(e.to_string())),
                }
            }
        };

        Ok(Box::pin(stream))
    }
}

// Note: types are already imported above, no need to re-export

#[cfg(test)]
mod tests {
    use super::*;
    use openai_dive::v1::resources::chat::{
        ChatCompletionParametersBuilder, ChatMessage, ChatMessageContent,
    };

    fn sample_params() -> ChatCompletionParameters {
        ChatCompletionParametersBuilder::default()
            .model("test-model".to_string())
            .messages(vec![ChatMessage::User {
                content: ChatMessageContent::Text("hello".into()),
                name: None,
            }])
            .build()
            .expect("valid chat parameters")
    }

    #[tokio::test]
    async fn rate_limit_surfaces_retry_after() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/chat/completions")
            .with_status(429)
            .with_header("retry-after", "2")
            .with_body(r#"{"error":"rate limited"}"#)
            .create_async()
            .await;

        let client = ChatClient::new("test-key".into(), server.url());
        let err = client
            .chat_completion(&sample_params(), &NoHooks)
            .await
            .expect_err("expected a rate-limit error");

        match err {
            ChatError::RateLimited(rate_limited) => {
                assert_eq!(rate_limited.status, 429);
                assert_eq!(
                    rate_limited.retry_after,
                    Some(std::time::Duration::from_secs(2))
                );
            }
            other => panic!("expected ChatError::RateLimited, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn service_unavailable_surfaces_retry_after() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/chat/completions")
            .with_status(503)
            .with_header("retry-after", "5")
            .with_body("unavailable")
            .create_async()
            .await;

        let client = ChatClient::new("test-key".into(), server.url());
        let err = client
            .chat_completion(&sample_params(), &NoHooks)
            .await
            .expect_err("expected a 503 error");

        assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn auth_error_stays_api_variant() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/chat/completions")
            .with_status(401)
            .with_body("unauthorized")
            .create_async()
            .await;

        let client = ChatClient::new("bad-key".into(), server.url());
        let err = client
            .chat_completion(&sample_params(), &NoHooks)
            .await
            .expect_err("expected an auth error");

        assert!(matches!(
            err,
            ChatError::Api(APIError::AuthenticationError(_))
        ));
        assert_eq!(err.retry_after(), None);
    }

    #[tokio::test]
    async fn stream_rate_limit_surfaces_retry_after() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/chat/completions")
            .with_status(429)
            .with_header("retry-after", "2")
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"rate limited"}"#)
            .create_async()
            .await;

        let client = ChatClient::new("test-key".into(), server.url());
        let err = match client
            .chat_completion_stream(&sample_params(), NoHooks)
            .await
        {
            Err(err) => err,
            Ok(_) => panic!("expected a rate-limit error before the stream is returned"),
        };

        match err {
            ChatError::RateLimited(rate_limited) => {
                assert_eq!(rate_limited.status, 429);
                assert_eq!(
                    rate_limited.retry_after,
                    Some(std::time::Duration::from_secs(2))
                );
            }
            other => panic!("expected ChatError::RateLimited, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn stream_auth_error_surfaces_before_stream() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/chat/completions")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body("unauthorized")
            .create_async()
            .await;

        let client = ChatClient::new("bad-key".into(), server.url());
        let err = match client
            .chat_completion_stream(&sample_params(), NoHooks)
            .await
        {
            Err(err) => err,
            Ok(_) => panic!("expected an auth error before the stream is returned"),
        };

        assert!(matches!(
            err,
            ChatError::Api(APIError::AuthenticationError(_))
        ));
    }

    const OPENROUTER_ERROR_CHUNK: &str = r#"{"id":"gen-1","object":"chat.completion.chunk","created":1700000000,"model":"openai/gpt-oss-120b","error":{"code":"server_error","message":"Provider disconnected unexpectedly"},"choices":[{"index":0,"delta":{"content":""},"finish_reason":"error"}]}"#;

    #[test]
    fn finish_reason_error_is_a_provider_error() {
        let mut json: Value = serde_json::from_str(OPENROUTER_ERROR_CHUNK).unwrap();
        let err = normalize_finish_reasons(&mut json).expect_err("error finish reason");
        match err {
            APIError::ServerError(message) => {
                assert!(message.contains("finish_reason \"error\""), "{}", message);
                assert!(message.contains("Provider disconnected unexpectedly"));
                assert!(message.contains("server_error"));
            }
            other => panic!("expected APIError::ServerError, got {:?}", other),
        }
    }

    #[test]
    fn finish_reason_error_prefers_choice_error_and_handles_missing_details() {
        let mut json = serde_json::json!({
            "choices": [{"index": 0, "finish_reason": "error",
                         "error": {"code": 502, "message": "upstream timeout"}}]
        });
        let message = normalize_finish_reasons(&mut json).unwrap_err().to_string();
        assert!(message.contains("upstream timeout (502)"), "{}", message);

        let mut bare = serde_json::json!({"choices": [{"index": 0, "finish_reason": "error"}]});
        let message = normalize_finish_reasons(&mut bare).unwrap_err().to_string();
        assert!(message.contains("no error details"), "{}", message);
    }

    #[test]
    fn unknown_finish_reason_deserializes_as_other() {
        let body = r#"{"id":"gen-2","object":"chat.completion","created":1700000000,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"done"},"finish_reason":"some_new_reason"}]}"#;
        // Without normalization openai_dive rejects the value.
        assert!(serde_json::from_str::<ChatCompletionResponse>(body).is_err());

        let mut json: Value = serde_json::from_str(body).unwrap();
        normalize_finish_reasons(&mut json).expect("unknown reason is not an error");
        let response: ChatCompletionResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.choices[0].finish_reason, Some(FinishReason::Other));
    }

    #[test]
    fn known_and_null_finish_reasons_are_unchanged() {
        let mut json = serde_json::json!({
            "choices": [
                {"index": 0, "finish_reason": "stop"},
                {"index": 1, "finish_reason": "tool_calls"},
                {"index": 2, "finish_reason": null}
            ]
        });
        let before = json.clone();
        normalize_finish_reasons(&mut json).unwrap();
        assert_eq!(json, before);
    }

    #[tokio::test]
    async fn chat_completion_surfaces_finish_reason_error() {
        let body = r#"{"id":"gen-3","object":"chat.completion","created":1700000000,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":""},"finish_reason":"error","error":{"code":"server_error","message":"boom"}}]}"#;
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/chat/completions")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let client = ChatClient::new("test-key".into(), server.url());
        let err = client
            .chat_completion(&sample_params(), &NoHooks)
            .await
            .expect_err("finish_reason error should fail the call");
        match err {
            ChatError::Api(APIError::ServerError(message)) => {
                assert!(message.contains("boom (server_error)"), "{}", message)
            }
            other => panic!("expected ServerError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn stream_finish_reason_error_yields_provider_error() {
        let ok_chunk = r#"{"id":"gen-1","object":"chat.completion.chunk","created":1700000000,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":"partial"},"finish_reason":null}]}"#;
        let body = format!(
            "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
            ok_chunk, OPENROUTER_ERROR_CHUNK
        );
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/chat/completions")
            .with_status(200)
            .with_header("content-type", "text/event-stream")
            .with_body(body)
            .create_async()
            .await;

        let client = ChatClient::new("test-key".into(), server.url());
        let mut stream = client
            .chat_completion_stream(&sample_params(), NoHooks)
            .await
            .expect("stream should open");

        let first = stream.next().await.expect("first item");
        assert!(first.is_ok(), "partial chunk should parse: {:?}", first);
        match stream.next().await.expect("second item") {
            Err(APIError::ServerError(message)) => {
                assert!(message.contains("Provider disconnected unexpectedly"))
            }
            other => panic!("expected ServerError, got {:?}", other),
        }
        assert!(stream.next().await.is_none(), "stream ends after the error");
    }

    #[tokio::test]
    async fn stream_success_yields_chunks() {
        let chunk_json = r#"{"id":"chatcmpl-test","object":"chat.completion.chunk","created":1700000000,"model":"test-model","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":null}]}"#;
        let body = format!("data: {}\n\ndata: [DONE]\n\n", chunk_json);

        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/chat/completions")
            .with_status(200)
            .with_header("content-type", "text/event-stream")
            .with_body(body)
            .create_async()
            .await;

        let client = ChatClient::new("test-key".into(), server.url());
        let mut stream = client
            .chat_completion_stream(&sample_params(), NoHooks)
            .await
            .expect("stream should open on a 200 response");

        let mut chunks = Vec::new();
        while let Some(item) = stream.next().await {
            chunks.push(item.expect("chunk should parse"));
        }

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].id.as_deref(), Some("chatcmpl-test"));
        assert_eq!(chunks[0].choices.len(), 1);
    }

    #[tokio::test]
    async fn chat_completion_surfaces_error_only_200_body() {
        // OpenRouter: a provider failure after headers is a 200 whose body
        // holds only `error` and no `choices`.
        let body = r#"{"id":"gen-9","error":{"code":502,"message":"Provider returned error"}}"#;
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/chat/completions")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let client = ChatClient::new("test-key".into(), server.url());
        let err = client
            .chat_completion(&sample_params(), &NoHooks)
            .await
            .expect_err("error-only body should fail the call");
        match err {
            ChatError::Api(APIError::ServerError(message)) => {
                assert!(message.contains("Provider returned error"), "{}", message)
            }
            other => panic!("expected ServerError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn stream_error_only_event_keeps_provider_message() {
        let body = "data: {\"error\":{\"code\":429,\"message\":\"Rate limit exceeded\"}}\n\ndata: [DONE]\n\n";
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/chat/completions")
            .with_status(200)
            .with_header("content-type", "text/event-stream")
            .with_body(body)
            .create_async()
            .await;

        let client = ChatClient::new("test-key".into(), server.url());
        let mut stream = client
            .chat_completion_stream(&sample_params(), NoHooks)
            .await
            .expect("stream should open");
        match stream.next().await.expect("first item") {
            Err(APIError::ServerError(message)) => {
                assert!(message.contains("Rate limit exceeded"), "{}", message)
            }
            other => panic!("expected ServerError, got {:?}", other),
        }
    }

    #[test]
    fn finish_reason_error_with_client_error_code_is_not_retryable() {
        let mut json = serde_json::json!({
            "error": {"code": 400, "message": "context_length_exceeded"},
            "choices": [{"index": 0, "finish_reason": "error"}]
        });
        let err = normalize_finish_reasons(&mut json).unwrap_err();
        assert!(matches!(err, APIError::InvalidRequestError(_)), "{:?}", err);

        let mut json = serde_json::json!({
            "choices": [{"index": 0, "finish_reason": "error",
                         "error": {"code": 402, "message": "insufficient credits"}}]
        });
        let err = normalize_finish_reasons(&mut json).unwrap_err();
        assert!(matches!(err, APIError::PermissionError(_)), "{:?}", err);
    }
}
