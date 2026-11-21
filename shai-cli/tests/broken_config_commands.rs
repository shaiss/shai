// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

//! A broken auth config must not start `shai serve` or the shell assistant
//! on the built-in default model.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Outcome {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

fn shai_with_broken_config(args: &[&str], extra_env: &[(&str, &str)]) -> Outcome {
    let dir = tempfile::TempDir::new().unwrap();
    let config_home = dir.path().join("config");
    std::fs::create_dir_all(config_home.join("shai")).unwrap();
    std::fs::write(
        config_home.join("shai").join("auth.config.json"),
        "{ this is not json",
    )
    .unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_shai"));
    command
        .args(args)
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
    for (key, value) in extra_env {
        command.env(key, value);
    }

    let mut child = command.spawn().expect("the shai binary should start");
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(15) {
            let _ = child.kill();
            panic!(
                "shai {args:?} did not exit; a broken config must not start a session or a server"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    Outcome {
        status: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn assert_exits_2_on_broken_config(outcome: Outcome) {
    assert_eq!(
        outcome.status,
        Some(2),
        "stdout={} stderr={}",
        outcome.stdout,
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("could not be loaded")
            && outcome.stderr.contains("auth.config.json"),
        "stderr={}",
        outcome.stderr
    );
    assert!(
        !outcome.stderr.contains("this is not json"),
        "stderr={}",
        outcome.stderr
    );
}

#[test]
fn shai_serve_exits_2_when_the_config_file_is_broken() {
    assert_exits_2_on_broken_config(shai_with_broken_config(
        &["serve", "--host", "127.0.0.1", "--port", "59999"],
        &[],
    ));
}

#[cfg(unix)]
#[test]
fn shai_postcmd_exits_2_when_the_config_file_is_broken() {
    assert_exits_2_on_broken_config(shai_with_broken_config(
        &["postcmd", "1", "false"],
        &[("SHAI_SESSION_ID", "broken-config-test")],
    ));
}
