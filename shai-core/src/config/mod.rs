pub mod agent;
pub mod config;
pub mod lenient;
pub mod prewalk;
pub mod roles;
pub(crate) mod section;
pub mod tui;

/// Serializes unit tests that mutate process-wide `XDG_CONFIG_HOME`.
/// Integration tests (`tests/*.rs`) are a separate process and do not share it.
#[cfg(test)]
pub(crate) mod test_env {
    use std::sync::Mutex;

    pub static XDG_CONFIG_HOME_LOCK: Mutex<()> = Mutex::new(());
}
