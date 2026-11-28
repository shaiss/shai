// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Metadata extracted from a prompt file's frontmatter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptInfo {
    /// Prompt name (from frontmatter `name` or file stem)
    pub name: String,
    /// Short description (from frontmatter `description`)
    pub description: String,
    /// Full path to the prompt file
    pub path: PathBuf,
}

/// Parse a prompt file content to extract name and description from frontmatter.
///
/// Frontmatter format:
/// ```text
/// ---
/// name: My Prompt
/// description: A short description
/// ---
/// # Rest of the file...
/// ```
fn parse_prompt_frontmatter(content: &str) -> Option<(String, String)> {
    crate::tools::frontmatter::parse_frontmatter(content)
}

/// Strip the frontmatter block from a prompt file content, returning only the body.
pub fn strip_frontmatter(content: &str) -> String {
    let trimmed = content.trim_start();
    if !trimmed.starts_with("---") {
        return content.to_string();
    }

    let rest = &trimmed[3..];
    let end = match rest.find("\n---") {
        Some(idx) => idx,
        None => return content.to_string(),
    };

    let body_start = end + 4; // skip "\n---"
    let body = &rest[body_start..];
    body.trim_start_matches('\n').to_string()
}

/// Discover all prompts in a given directory.
/// Each `.md` file is considered a prompt.
fn discover_prompts_in_dir(dir: &Path) -> Vec<PromptInfo> {
    let mut prompts = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return prompts,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        if path.extension().is_some_and(|ext| ext == "md") {
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let (name, description) = match parse_prompt_frontmatter(&content) {
                Some(parsed) => parsed,
                None => {
                    // Fall back to file stem if no frontmatter
                    let file_stem = path
                        .file_stem()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    (file_stem, String::new())
                }
            };

            prompts.push(PromptInfo {
                name,
                description,
                path: path.clone(),
            });
        }
    }

    prompts
}

/// Discover all prompts from both global (`~/.config/shai/prompts/`) and
/// project-local (`.shai/prompts/`) directories.
///
/// Project-local prompts take precedence (they shadow global prompts with the same name).
pub fn discover_prompts() -> Vec<PromptInfo> {
    let mut prompts = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    // Project-local prompts first (higher priority)
    let git_root = crate::runners::coder::env::find_git_root();
    if let Some(root) = git_root {
        let project_prompts_dir = root.join(".shai").join("prompts");
        for prompt in discover_prompts_in_dir(&project_prompts_dir) {
            seen_names.insert(prompt.name.clone());
            prompts.push(prompt);
        }
    }

    // Global prompts
    let home = std::env::var("HOME").ok();
    if let Some(home) = home {
        let global_prompts_dir = PathBuf::from(home)
            .join(".config")
            .join("shai")
            .join("prompts");
        for prompt in discover_prompts_in_dir(&global_prompts_dir) {
            if !seen_names.contains(&prompt.name) {
                seen_names.insert(prompt.name.clone());
                prompts.push(prompt);
            }
        }
    }

    prompts
}

/// Load the body of a prompt file, stripping the frontmatter.
pub fn load_prompt_body(path: &Path) -> Result<String, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    Ok(strip_frontmatter(&content))
}

/// Get the path to the active prompts persistence file.
fn active_prompts_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("shai")
            .join("active_prompts.json"),
    )
}

/// Save the list of active prompt names to disk so they persist across restarts.
pub fn save_active_prompts(names: &[String]) -> Result<(), std::io::Error> {
    let path = active_prompts_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine home directory",
        )
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(names)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(&path, content)?;
    Ok(())
}

/// Load the list of active prompt names from disk.
pub fn load_active_prompts_from_disk() -> Vec<String> {
    let path = match active_prompts_path() {
        Some(p) => p,
        None => return Vec::new(),
    };
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Load the bodies of active prompts by name.
/// Returns a vector of (name, body) pairs.
pub fn load_active_prompts(names: &[String]) -> Vec<(String, String)> {
    let prompts = discover_prompts();
    let mut result = Vec::new();

    for name in names {
        if let Some(prompt) = prompts.iter().find(|p| &p.name == name) {
            match load_prompt_body(&prompt.path) {
                Ok(body) => result.push((name.clone(), body)),
                Err(_) => continue,
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_strip_frontmatter() {
        let content = "---\nname: test\ndescription: test\n---\n\n# Body\n\nContent here.";
        let body = strip_frontmatter(content);
        assert!(body.starts_with("# Body"));
    }

    #[test]
    fn test_strip_frontmatter_no_frontmatter() {
        let content = "# Just a heading\n\nNo frontmatter here.";
        let body = strip_frontmatter(content);
        assert_eq!(body, content);
    }

    #[test]
    fn test_discover_prompts_in_dir() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create a prompt file with frontmatter
        fs::write(
            temp_path.join("my-prompt.md"),
            "---\nname: my-prompt\ndescription: A test prompt\n---\n# My Prompt\n",
        )
        .unwrap();

        // Create another prompt without frontmatter
        fs::write(
            temp_path.join("another.md"),
            "# Another Prompt\n\nNo frontmatter.",
        )
        .unwrap();

        // Create a non-md file
        fs::write(temp_path.join("not-a-prompt.txt"), "Not a prompt").unwrap();

        let prompts = discover_prompts_in_dir(temp_path);
        assert_eq!(prompts.len(), 2);

        let names: Vec<&str> = prompts.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"my-prompt"));
        assert!(names.contains(&"another"));
    }

    #[test]
    fn test_load_prompt_body() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let file_path = temp_path.join("test.md");
        fs::write(
            &file_path,
            "---\nname: test\ndescription: test\n---\n# Body\n\nContent here.",
        )
        .unwrap();

        let body = load_prompt_body(&file_path).unwrap();
        assert!(body.starts_with("# Body"));
        assert!(body.contains("Content here."));
    }

    #[test]
    fn test_load_active_prompts() {
        // load_active_prompts resolves names through discover_prompts(), which
        // reads ~/.config/shai/prompts (and project .shai/prompts). Point HOME
        // at a temp tree so the test does not depend on the developer's config.
        // HOME is process-wide: take HOME_LOCK and restore via HomeGuard so
        // parallel skill/prompt discovery tests cannot race.
        let _lock = crate::config::test_env::HOME_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_home = TempDir::new().unwrap();
        let prompts_dir = temp_home
            .path()
            .join(".config")
            .join("shai")
            .join("prompts");
        fs::create_dir_all(&prompts_dir).unwrap();
        // Unique name: project-local prompts still win over HOME, so avoid
        // colliding with a real `.shai/prompts/caveman.md` in the checkout.
        let name = "ci_gate_unique_prompt_fixture";
        fs::write(
            prompts_dir.join(format!("{name}.md")),
            format!("---\nname: {name}\ndescription: CI fixture\n---\nBe concise."),
        )
        .unwrap();

        let _home = crate::config::test_env::HomeGuard::set(temp_home.path());
        let loaded = load_active_prompts(&[name.to_string()]);

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, name);
        assert!(loaded[0].1.contains("Be concise."));
    }
}
