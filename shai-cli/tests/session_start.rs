// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

//! What the `shai` binary does when a session option cannot be honoured.
//!
//! Every case here ends before a session starts, so no model is contacted,
//! and every case but the one that says so has a config file, so no starter
//! config is downloaded. Should one of them try, it gets nowhere: the child
//! is given a proxy that nothing listens on.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// One provider that is never contacted.
const PROVIDER: &str = r#""providers": [{"provider": "ollama", "env_vars": {"OLLAMA_BASE_URL": "http://127.0.0.1:9/v1"}, "model": "local-a", "tool_method": "FunctionCall"}], "selected_provider": 0"#;

/// The file a starter config is saved to, whether it was downloaded or made
/// up when the download failed.
const STARTER_CONFIG_FILE: &str = "auth.config.json";

/// The proxy every request of the child would go through: a port of this
/// machine where nothing listens, so that a connection is refused at once.
const DEAD_PROXY: &str = "http://127.0.0.1:9";

struct Outcome {
    status: i32,
    stdout: String,
    stderr: String,
}

/// Run `shai` in an environment that holds nothing of the machine it runs
/// on, with `config_home` as the place its config is looked for and `dir` to
/// keep the rest in.
fn run(dir: &Path, config_home: &Path, args: &[&str]) -> Outcome {
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_shai"));
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir.join("home"))
        .env("XDG_CONFIG_HOME", config_home)
        .env("NO_COLOR", "1");
    // No request leaves the machine, whatever a regression makes of it.
    for proxy in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
        command
            .env(proxy, DEAD_PROXY)
            .env(proxy.to_lowercase(), DEAD_PROXY);
    }
    let mut child = command
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the shai binary should start");

    // None of these invocations may get as far as a session.
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("shai {args:?} did not exit");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    Outcome {
        status: output.status.code().expect("an exit status"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Run `shai` with `config` as its only config file, and check that it is
/// still its only config file afterwards, as it was written.
fn shai(config_file: &str, config: &str, args: &[&str]) -> Outcome {
    let dir = tempfile::TempDir::new().unwrap();
    let config_dir = dir.path().join("config").join("shai");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join(config_file), config).unwrap();

    let outcome = run(dir.path(), &dir.path().join("config"), args);

    // Nothing was fetched or made up over the config file or next to it:
    // the config directory holds exactly what it held before, the one file
    // as it was written.
    let left: Vec<(String, String)> = std::fs::read_dir(&config_dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
            (entry.file_name().to_string_lossy().into_owned(), text)
        })
        .collect();
    assert_eq!(
        left,
        [(config_file.to_string(), config.to_string())],
        "shai {args:?} must leave the config directory as it was"
    );
    outcome
}

/// A config with the role `cheap`, followed by `tail`.
fn config(tail: &str) -> String {
    format!(r#"{{{PROVIDER}, "roles": {{"cheap": "ollama/local-b"}}{tail}}}"#)
}

/// A config with the role `advisor`, followed by `tail`.
fn config_with_advisor_role(tail: &str) -> String {
    format!(r#"{{{PROVIDER}, "roles": {{"advisor": "ollama/local-c"}}{tail}}}"#)
}

#[test]
fn a_starter_config_lands_where_these_tests_look_for_one() {
    // The one case without a config file. What it is told to fetch a
    // starter config from is not an address, so no request is made and the
    // built-in config is saved in its place.
    let dir = tempfile::TempDir::new().unwrap();
    let config_home = dir.path().join("config");
    let outcome = run(
        dir.path(),
        &config_home,
        &[
            "--default-shai-config-url",
            "not an address",
            "--list-tools",
        ],
    );
    assert_eq!(outcome.status, 0, "{}", outcome.stderr);
    assert!(
        config_home.join("shai").join(STARTER_CONFIG_FILE).exists(),
        "the check made after every other case watches this file"
    );
}

#[test]
fn a_target_that_does_not_resolve_stops_the_session_with_status_2() {
    for (args, expected) in [
        (
            &["-p", "hello", "--prewalk-into", "planner"][..],
            "cannot arm prewalk from --prewalk-into: role \"planner\" is not configured",
        ),
        (
            &["-p", "hello", "--prewalk-into", "anthropic/claude-x"][..],
            "names a provider that is not configured",
        ),
        (
            &["--prewalk-into", "planner", "agent", "reviewer"][..],
            "cannot arm prewalk from --prewalk-into",
        ),
    ] {
        let outcome = shai("auth.config.json", &config(""), args);
        assert_eq!(outcome.status, 2, "{args:?}: {}", outcome.stderr);
        assert!(
            outcome.stderr.contains(expected),
            "{args:?}: {}",
            outcome.stderr
        );
        assert!(outcome.stdout.is_empty(), "{args:?}: {}", outcome.stdout);
    }

    // The same from the config, where the value is named and not repeated.
    let outcome = shai(
        "auth.config.json",
        &config(r#", "prewalk": {"into": "sk-live-SECRETSECRET"}"#),
        &["-p", "hello"],
    );
    assert_eq!(outcome.status, 2, "{}", outcome.stderr);
    assert!(
        outcome
            .stderr
            .contains("cannot arm prewalk from the config: \"prewalk.into\""),
        "{}",
        outcome.stderr
    );
    assert!(!outcome.stderr.contains("SECRET"), "{}", outcome.stderr);
}

#[test]
fn a_prewalk_section_that_is_invalid_or_written_twice_stops_the_session() {
    for tail in [
        r#", "prewalk": "cheap""#,
        r#", "prewalk": {"in_to": "cheap"}"#,
        r#", "prewalk": {"into": "cheap"}, "prewalk": {"into": "cheap"}"#,
    ] {
        let outcome = shai("auth.config.json", &config(tail), &["-p", "hello"]);
        assert_eq!(outcome.status, 2, "{tail}: {}", outcome.stderr);
        assert!(
            outcome
                .stderr
                .contains("the \"prewalk\" section of the config is invalid"),
            "{tail}: {}",
            outcome.stderr
        );
        // The rest of the file still loads: no parse warning.
        assert!(
            !outcome.stderr.contains("Warning"),
            "{tail}: {}",
            outcome.stderr
        );
    }
}

#[test]
fn a_config_file_that_cannot_be_read_stops_the_session_and_nothing_else() {
    // A value in the wrong place, which the parser would quote.
    let broken = r#"{"providers": [], "selected_provider": "sk-live-SECRETSECRET"}"#;
    for file in ["auth.config.json", "auth.config"] {
        let outcome = shai(file, broken, &["-p", "hello"]);
        assert_eq!(outcome.status, 2, "{file}: {}", outcome.stderr);
        assert!(
            outcome.stderr.contains("could not be loaded") && outcome.stderr.contains(file),
            "{file}: {}",
            outcome.stderr
        );
        // Where it is broken, not what it holds.
        assert!(
            outcome.stderr.contains("line 1 column"),
            "{}",
            outcome.stderr
        );
        assert!(!outcome.stderr.contains("SECRET"), "{}", outcome.stderr);
        assert!(outcome.stdout.is_empty(), "{}", outcome.stdout);

        // Commands that start no session are not held up by it.
        let outcome = shai(file, broken, &["--list-tools"]);
        assert_eq!(outcome.status, 0, "{file}: {}", outcome.stderr);
        assert!(outcome.stderr.contains("todo_write"), "{}", outcome.stderr);
        assert!(!outcome.stderr.contains("SECRET"), "{}", outcome.stderr);
    }
}

#[test]
fn the_flag_is_refused_where_no_session_starts() {
    for args in [
        &["--prewalk-into", "cheap", "--list-tools"][..],
        &["--prewalk-into", "cheap", "--version"],
        &["--prewalk-into", "cheap", "agent", "list"],
        &["--prewalk-into", "cheap", "auth"],
        &["--prewalk-into", "cheap", "list", "agent"],
        &["--prewalk-into", "cheap", "import"],
    ] {
        let outcome = shai("auth.config.json", &config(""), args);
        assert_eq!(outcome.status, 2, "{args:?}: {}", outcome.stderr);
        assert!(
            outcome
                .stderr
                .contains("--prewalk-into only applies to commands that start an agent session"),
            "{args:?}: {}",
            outcome.stderr
        );
        assert!(outcome.stdout.is_empty(), "{args:?}: {}", outcome.stdout);
    }

    // Without the flag, and with a config section that is fine, they run.
    let outcome = shai(
        "auth.config.json",
        &config(r#", "prewalk": {"into": "cheap"}"#),
        &["--version"],
    );
    assert_eq!(outcome.status, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.contains("shai version"),
        "{}",
        outcome.stdout
    );
}

#[test]
fn an_advisor_that_cannot_be_set_up_stops_the_session_with_status_2() {
    for (config, args, expected) in [
        // Asked for, and there is no role for it to run on.
        (
            config(""),
            &["-p", "hello", "--advisor"][..],
            "no \"advisor\" role is configured",
        ),
        (
            config(r#", "advisor": {"enabled": true}"#),
            &["-p", "hello"][..],
            "no \"advisor\" role is configured",
        ),
        // A section that cannot be read stops the session whether or not it
        // would have turned the advisor on.
        (
            config_with_advisor_role(
                r#", "advisor": {"enabled": false}, "advisor": {"enabled": true}"#,
            ),
            &["-p", "hello"][..],
            "the \"advisor\" section of the config is invalid",
        ),
        (
            config_with_advisor_role(r#", "advisor": "on""#),
            &["-p", "hello"][..],
            "the \"advisor\" section of the config is invalid",
        ),
        (
            config_with_advisor_role(r#", "advisor": {"enabled": true, "max_calls": 0}"#),
            &["-p", "hello"][..],
            "advisor.max_calls must be between 1 and 10000",
        ),
    ] {
        let outcome = shai("auth.config.json", &config, args);
        assert_eq!(outcome.status, 2, "{args:?}: {}", outcome.stderr);
        assert!(
            outcome.stderr.contains(expected),
            "{args:?}: {}",
            outcome.stderr
        );
        assert!(outcome.stdout.is_empty(), "{args:?}: {}", outcome.stdout);
    }

    // The flag where no session starts.
    for args in [
        &["--advisor", "--list-tools"][..],
        &["--advisor", "auth"],
        &["--advisor", "agent", "list"],
    ] {
        let outcome = shai("auth.config.json", &config_with_advisor_role(""), args);
        assert_eq!(outcome.status, 2, "{args:?}: {}", outcome.stderr);
        assert!(
            outcome
                .stderr
                .contains("--advisor only applies to commands that start an agent session"),
            "{args:?}: {}",
            outcome.stderr
        );
    }
}
