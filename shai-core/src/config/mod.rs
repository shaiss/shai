pub mod agent;
pub mod config;
pub mod lenient;
pub mod prewalk;
pub mod roles;
pub(crate) mod section;
pub mod tui;

/// Serializes unit tests that mutate process-wide `XDG_CONFIG_HOME` / `HOME`.
/// Integration tests (`tests/*.rs`) are a separate process and do not share it.
#[cfg(test)]
pub(crate) mod test_env {
    use std::path::Path;
    use std::sync::Mutex;

    pub static XDG_CONFIG_HOME_LOCK: Mutex<()> = Mutex::new(());

    /// Serializes tests that read or mutate process-wide `HOME` (prompt/skill
    /// discovery under `~/.config/shai/...`).
    pub static HOME_LOCK: Mutex<()> = Mutex::new(());

    /// Serializes tests that read or write `set_env_vars` / APPLIED_ENV_VARS.
    pub static ENV_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Restores the previous `XDG_CONFIG_HOME` when dropped, including when
    /// a test panics. Keep this guard inside the lock scope so restoration
    /// finishes before another test can acquire the lock.
    pub struct XdgConfigHomeGuard {
        previous: Option<String>,
    }

    impl XdgConfigHomeGuard {
        pub fn set(home: impl AsRef<Path>) -> Self {
            let previous = std::env::var("XDG_CONFIG_HOME").ok();
            std::env::set_var("XDG_CONFIG_HOME", home.as_ref());
            Self { previous }
        }
    }

    impl Drop for XdgConfigHomeGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    /// Restores the previous `HOME` when dropped, including when a test panics.
    pub struct HomeGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl HomeGuard {
        pub fn set(home: impl AsRef<Path>) -> Self {
            let previous = std::env::var_os("HOME");
            std::env::set_var("HOME", home.as_ref());
            Self { previous }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }
}
