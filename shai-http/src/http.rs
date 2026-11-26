use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::apis;
use crate::session::{SessionManager, SessionManagerConfig};

/// Configuration for the HTTP server
#[derive(Clone)]
pub struct ServerConfig {
    /// Server bind address (e.g., "127.0.0.1:8080")
    pub address: String,
    /// Session manager configuration
    pub session_manager: SessionManagerConfig,
}

impl ServerConfig {
    /// Create a new server config with the given address and default session manager config
    pub fn new(address: String) -> Self {
        Self {
            address,
            session_manager: SessionManagerConfig::default(),
        }
    }

    /// Set whether sessions are ephemeral by default
    pub fn with_ephemeral(mut self, ephemeral: bool) -> Self {
        self.session_manager.ephemeral = ephemeral;
        self
    }

    /// Grant every tool (writes, bash, network) to every session.
    /// Off by default: sessions then run read-only tools only.
    pub fn with_allow_all_tools(mut self, allow_all_tools: bool) -> Self {
        self.session_manager.allow_all_tools = allow_all_tools;
        self
    }

    /// Set the maximum number of concurrent sessions
    pub fn with_max_sessions(mut self, max_sessions: Option<usize>) -> Self {
        self.session_manager.max_sessions = max_sessions;
        self
    }

    /// Use this already-loaded auth config for every default HTTP session.
    pub fn with_primary_config(mut self, primary: shai_core::config::config::ShaiConfig) -> Self {
        self.session_manager.primary = Some(std::sync::Arc::new(primary));
        self
    }

    /// Set the default agent name used when requests omit an agent or pass `"default"`.
    pub fn with_default_agent(mut self, default_agent: Option<String>) -> Self {
        self.session_manager.default_agent = default_agent;
        self
    }
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("address", &self.address)
            .field("session_manager", &self.session_manager)
            .finish()
    }
}

/// Server state holding the session manager
#[derive(Clone)]
pub struct ServerState {
    pub session_manager: Arc<SessionManager>,
}

/// Start the HTTP server with SSE streaming
pub async fn start_server(config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Create session manager
    let session_manager = SessionManager::new(config.session_manager.clone());

    println!("✓ Session manager initialized");
    if let Some(max) = config.session_manager.max_sessions {
        println!("  Max sessions: \x1b[1m{}\x1b[0m", max);
    } else {
        println!("  Max sessions: \x1b[1munlimited\x1b[0m");
    }
    println!(
        "  Default agent: \x1b[1m{}\x1b[0m",
        config
            .session_manager
            .default_agent
            .as_deref()
            .unwrap_or("default")
    );
    println!(
        "  Default mode: \x1b[1m{}\x1b[0m",
        if config.session_manager.ephemeral {
            "ephemeral"
        } else {
            "persistent"
        }
    );
    println!(
        "  Tools: \x1b[1m{}\x1b[0m",
        if config.session_manager.allow_all_tools {
            "all (--yes)"
        } else {
            "read-only (pass --yes to allow writes, bash and network)"
        }
    );
    println!();

    let state = ServerState {
        session_manager: Arc::new(session_manager),
    };

    let app = Router::new()
        // Simple API
        .route(
            "/v1/multimodal",
            post(apis::simple::handle_multimodal_query_stream),
        )
        .route(
            "/v1/multimodal/{session_id}",
            post(apis::simple::handle_multimodal_query_stream_with_session),
        )
        // OpenAI-compatible Response API
        .route("/v1/responses", post(apis::openai::handle_response))
        .route(
            "/v1/responses/{response_id}",
            get(apis::openai::handle_get_response),
        )
        .route(
            "/v1/responses/{response_id}/cancel",
            post(apis::openai::handle_cancel_response),
        )
        // OpenAI-compatible Chat Completion API
        .route(
            "/v1/chat/completions",
            post(apis::openai::handle_chat_completion),
        )
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.address).await?;

    // Print server info
    println!("Server starting on \x1b[1mhttp://{}\x1b[0m", config.address);
    println!("\nAvailable endpoints:");
    println!("  \x1b[1mPOST /v1/chat/completions\x1b[0m            - OpenAI Chat Completions API (ephemeral)");
    println!("  \x1b[1mPOST /v1/responses\x1b[0m                    - OpenAI Responses API (stateful/stateless)");
    println!("  \x1b[1mGET  /v1/responses/:id\x1b[0m                - Get response by ID");
    println!("  \x1b[1mPOST /v1/responses/:id/cancel\x1b[0m        - Cancel a response");
    println!(
        "  \x1b[1mPOST /v1/multimodal\x1b[0m                   - Simple multimodal API (streaming)"
    );
    println!("  \x1b[1mPOST /v1/multimodal/:session_id\x1b[0m      - Simple multimodal API (with session)");

    // List available agents
    use shai_core::config::agent::AgentConfig;
    match AgentConfig::list_agents() {
        Ok(agents) if !agents.is_empty() => {
            println!("\nAvailable agents: \x1b[2m{}\x1b[0m", agents.join(", "));
        }
        _ => {}
    }

    println!("\nPress Ctrl+C to stop\n");

    info!("HTTP server listening on {}", config.address);

    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ServerConfig;
    use shai_core::config::config::ShaiConfig;

    #[test]
    fn debug_does_not_contain_the_auth_config_key() {
        let snapshot: ShaiConfig = serde_json::from_str(
            r#"{"providers":[{"provider":"openai","env_vars":{"OPENAI_API_KEY":"sk-test-do-not-leak"},"model":"gpt-4o","tool_method":"FunctionCall"}],"selected_provider":0}"#,
        )
        .unwrap();
        let config = ServerConfig::new("127.0.0.1:0".into()).with_primary_config(snapshot);
        let debug = format!("{config:?}");
        assert!(
            !debug.contains("sk-test-do-not-leak"),
            "Debug leaked the key: {debug}"
        );
    }

    #[test]
    fn with_default_agent_sets_session_manager_default_agent() {
        let config =
            ServerConfig::new("127.0.0.1:0".into()).with_default_agent(Some("reviewer".into()));
        assert_eq!(
            config.session_manager.default_agent.as_deref(),
            Some("reviewer")
        );
    }
}
