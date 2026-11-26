// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

//! `shai serve <agent>` must validate the named agent before binding.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn shai_serve_exits_2_when_named_agent_is_missing() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_home = dir.path().join("config");
    std::fs::create_dir_all(config_home.join("shai")).unwrap();
    std::fs::write(
        config_home.join("shai").join("auth.config.json"),
        r#"{"providers":[{"provider":"openai","env_vars":{"OPENAI_API_KEY":"k"},"model":"gpt-4o","tool_method":"FunctionCall"}],"selected_provider":0}"#,
    )
    .unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_shai"));
    command
        .args([
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "missing-agent",
        ])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir.path().join("home"))
        .env("XDG_CONFIG_HOME", &config_home)
        .env("NO_COLOR", "1")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("the shai binary should start");
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(3) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("shai serve missing-agent did not exit; agent argument was ignored");
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("missing-agent"),
        "expected error mentioning missing-agent, got stderr={stderr}"
    );
}

#[test]
fn shai_serve_starts_with_valid_named_agent() {
    use std::io::{BufRead, BufReader};

    let dir = tempfile::TempDir::new().unwrap();
    let config_home = dir.path().join("config");
    let shai_dir = config_home.join("shai");
    let agents_dir = shai_dir.join("agents");
    std::fs::create_dir_all(&agents_dir).unwrap();
    std::fs::write(
        shai_dir.join("auth.config.json"),
        r#"{"providers":[{"provider":"openai","env_vars":{"OPENAI_API_KEY":"k"},"model":"gpt-4o","tool_method":"FunctionCall"}],"selected_provider":0}"#,
    )
    .unwrap();
    std::fs::write(
        agents_dir.join("reviewer.config.json"),
        r#"{"name":"reviewer","description":"test reviewer agent"}"#,
    )
    .unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_shai"));
    command
        .args(["serve", "--host", "127.0.0.1", "--port", "0", "reviewer"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir.path().join("home"))
        .env("XDG_CONFIG_HOME", &config_home)
        .env("NO_COLOR", "1")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("the shai binary should start");
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let started = Instant::now();
    let mut seen_default_agent = false;
    let mut seen_listening = false;
    let mut collected = String::new();
    let mut line = String::new();

    while started.elapsed() < Duration::from_secs(5) {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                collected.push_str(&line);
                if line.contains("Default agent:") && line.contains("reviewer") {
                    seen_default_agent = true;
                }
                if line.contains("Server starting on") {
                    seen_listening = true;
                    break;
                }
            }
            Err(err) => panic!("failed reading serve stdout: {err}"),
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        seen_default_agent && seen_listening,
        "expected Default agent: reviewer and Server starting on; stdout={collected}"
    );
}
