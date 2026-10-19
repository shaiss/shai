use super::bash::BashTool;
use super::structs::{resolve_timeout_secs, BashToolConfig, BashToolParams};
use crate::tools::{Tool, ToolCapability};
use serde_json::json;
use shai_llm::ToolDescription;
use std::collections::HashMap;
use std::time::Instant;

fn error_text(result: &crate::tools::types::ToolResult) -> String {
    match result {
        crate::tools::types::ToolResult::Error { error, .. } => error.clone(),
        other => format!("{:?}", other),
    }
}

#[test]
fn test_bash_tool_permissions() {
    let tool = BashTool::new();
    let perms = tool.capabilities();
    assert!(perms.contains(&ToolCapability::Read));
    assert!(perms.contains(&ToolCapability::Write));
    assert!(perms.contains(&ToolCapability::Network));
    assert_eq!(perms.len(), 3);
}

#[tokio::test]
async fn test_bash_tool_creation() {
    let tool = BashTool::new();
    assert_eq!(&tool.name(), "bash");
    assert!(!tool.description().is_empty());
}

#[tokio::test]
async fn test_bash_tool_execution() {
    let tool = BashTool::new();
    let params = BashToolParams {
        command: "echo hello".to_string(),
        // Explicit 0 so this unit test is not subject to the 300s default
        // (still finishes instantly either way).
        timeout: Some(0),
        working_dir: None,
        env: HashMap::new(),
    };

    let result = Tool::execute(&tool, params, None).await;
    assert!(result.is_success());
    if let crate::tools::types::ToolResult::Success { output, metadata } = result {
        assert!(output.contains("hello"));
        let metadata = metadata.unwrap();
        assert_eq!(metadata["exit_code"], json!(0));
        assert_eq!(metadata["success"], json!(true));
        assert_eq!(metadata["timeout"], json!("none"));
    } else {
        panic!("Expected success result");
    }
}

#[tokio::test]
async fn test_timeout_keeps_partial_stdout() {
    let tool = BashTool::new();
    let params = BashToolParams {
        // Print something, flush, then sleep past the 1s timeout.
        command: "echo PARTIAL_MARKER; sleep 5".to_string(),
        timeout: Some(1),
        working_dir: None,
        env: HashMap::new(),
    };

    let started = Instant::now();
    let result = Tool::execute(&tool, params, None).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed.as_secs() < 4,
        "should have timed out well before sleep 5 finished, took {:?}",
        elapsed
    );
    assert!(
        result.is_error(),
        "expected timeout error, got {:?}",
        result
    );
    let err = error_text(&result);
    assert!(
        err.contains("killed after 1 seconds") || err.contains("killed after 1 second"),
        "missing kill message: {}",
        err
    );
    assert!(
        err.contains("PARTIAL_MARKER"),
        "partial stdout was lost: {}",
        err
    );
    assert!(
        err.contains("re-run with a larger `timeout`") || err.contains("timeout: 0"),
        "missing hint: {}",
        err
    );
    assert!(
        !err.to_lowercase().contains("nohup"),
        "must not suggest nohup (issue #7 / review on #4): {}",
        err
    );
}

#[tokio::test]
async fn test_omitted_timeout_uses_default_from_config() {
    // Tiny default so the test is fast; omit params.timeout.
    let tool = BashTool::with_config(BashToolConfig {
        default_timeout_secs: 1,
        max_timeout_secs: 1800,
    });
    let params = BashToolParams {
        command: "echo BEFORE; sleep 5".to_string(),
        timeout: None,
        working_dir: None,
        env: HashMap::new(),
    };
    let result = Tool::execute(&tool, params, None).await;
    assert!(result.is_error());
    let err = error_text(&result);
    assert!(err.contains("killed after 1"), "{}", err);
    assert!(err.contains("BEFORE"), "partial output lost: {}", err);
}

#[tokio::test]
async fn test_timeout_zero_disables_limit() {
    let tool = BashTool::with_config(BashToolConfig {
        default_timeout_secs: 1,
        max_timeout_secs: 1800,
    });
    let params = BashToolParams {
        // Would hit the 1s default if 0 did not opt out.
        command: "sleep 2; echo SURVIVED".to_string(),
        timeout: Some(0),
        working_dir: None,
        env: HashMap::new(),
    };
    let result = Tool::execute(&tool, params, None).await;
    assert!(
        result.is_success(),
        "timeout 0 should disable limit: {:?}",
        result
    );
    if let crate::tools::types::ToolResult::Success { output, metadata } = result {
        assert!(output.contains("SURVIVED"));
        assert_eq!(metadata.unwrap()["timeout"], json!("none"));
    }
}

#[tokio::test]
async fn test_max_timeout_caps_huge_value() {
    let tool = BashTool::with_config(BashToolConfig {
        default_timeout_secs: 300,
        max_timeout_secs: 1,
    });
    let params = BashToolParams {
        command: "echo CAPPED; sleep 5".to_string(),
        timeout: Some(99999),
        working_dir: None,
        env: HashMap::new(),
    };
    let started = Instant::now();
    let result = Tool::execute(&tool, params, None).await;
    assert!(started.elapsed().as_secs() < 4);
    assert!(result.is_error());
    let err = error_text(&result);
    assert!(err.contains("killed after 1"), "{}", err);
    assert!(err.contains("CAPPED"), "{}", err);
    // Effective timeout recorded in metadata
    if let crate::tools::types::ToolResult::Error { metadata, .. } = result {
        assert_eq!(metadata.unwrap()["timeout"], json!(1));
    }
}

#[test]
fn test_resolve_timeout_helpers_exported() {
    let cfg = BashToolConfig::default();
    assert_eq!(resolve_timeout_secs(None, &cfg), Some(300));
    assert_eq!(resolve_timeout_secs(Some(0), &cfg), None);
}

#[tokio::test]
async fn test_utf8_multibyte_not_corrupted_across_pipe_reads() {
    let tool = BashTool::new();
    // ~20KB of a 2-byte UTF-8 character so output spans multiple 8KB reads.
    let params = BashToolParams {
        command: r#"python3 -c "import sys; sys.stdout.buffer.write(b'\xc3\xa9'*12000); sys.stdout.buffer.flush()""#.to_string(),
        timeout: Some(10),
        working_dir: None,
        env: HashMap::new(),
    };
    let result = Tool::execute(&tool, params, None).await;
    assert!(result.is_success(), "{:?}", result);
    if let crate::tools::types::ToolResult::Success { output, .. } = result {
        assert!(
            !output.contains('\u{FFFD}'),
            "replacement char present: corrupted UTF-8"
        );
        assert_eq!(output.chars().count(), 12000);
        assert!(
            output.chars().all(|c| c == 'é'),
            "unexpected char in output"
        );
    }
}
