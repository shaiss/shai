use super::super::{FsOperationLog, FsOperationType};
use super::structs::{ReadFileSpec, ReadToolParams};
use crate::tools::fs::hash::compute_line_hash;
use crate::tools::fs::symbol::{extract_symbols, format_outline, LanguageRegistry};
use crate::tools::{tool, ToolResult};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::sync::Arc;

const DEFAULT_READ_LIMIT: u32 = 2000;
const MAX_LINE_LENGTH: usize = 2000;
const MAX_BYTES: usize = 50 * 1024;
const MAX_LINE_SUFFIX: &str = "... (line truncated to 2000 chars)";
const BINARY_SAMPLE_SIZE: usize = 4096;

/// Bounds for the "did you mean" search run when a read path does not exist.
const SUGGEST_MAX_DEPTH: usize = 6;
const SUGGEST_MAX_ENTRIES: usize = 20_000;
const SUGGEST_MAX_RESULTS: usize = 5;
const SUGGEST_SKIP_DIRS: &[&str] = &[".git", "node_modules", "target"];

const BINARY_EXTENSIONS: &[&str] = &[
    ".zip", ".tar", ".gz", ".exe", ".dll", ".so", ".class", ".jar", ".war", ".7z", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".bin", ".dat", ".obj", ".o", ".lib",
    ".wasm", ".pyc", ".pyo", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tiff",
    ".pdf", ".mp3", ".mp4", ".avi", ".mov",
];

#[derive(Clone)]
pub struct ReadTool {
    operation_log: Arc<FsOperationLog>,
    language_registry: Arc<LanguageRegistry>,
}

impl ReadTool {
    pub fn new(operation_log: Arc<FsOperationLog>) -> Self {
        let language_registry = Arc::new(LanguageRegistry::new().unwrap_or_else(|e| {
            tracing::error!("Failed to initialize language registry: {}", e);
            panic!("Failed to initialize language registry: {}", e)
        }));
        Self {
            operation_log,
            language_registry,
        }
    }

    pub fn with_language_registry(
        operation_log: Arc<FsOperationLog>,
        language_registry: Arc<LanguageRegistry>,
    ) -> Self {
        Self {
            operation_log,
            language_registry,
        }
    }

    fn is_binary_file(path: &str) -> bool {
        if let Some(ext) = Path::new(path).extension().and_then(|e| e.to_str()) {
            let ext_lower = format!(".{}", ext.to_lowercase());
            if BINARY_EXTENSIONS.contains(&ext_lower.as_str()) {
                return true;
            }
        }

        let file = match fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut reader = io::BufReader::new(file);
        let mut buf = vec![0u8; BINARY_SAMPLE_SIZE];
        let n = reader.read(&mut buf).unwrap_or(0);
        if n == 0 {
            return false;
        }

        let sample = &buf[..n];
        let mut non_printable = 0;
        for &b in sample {
            if b == 0 {
                return true;
            }
            if b < 9 || (b > 13 && b < 32) {
                non_printable += 1;
            }
        }
        (non_printable as f64 / n as f64) > 0.3
    }

    /// Find files under `root` whose name equals the file name of `missing`.
    /// Used to recover from a path the model has forgotten (ovh/shai issue 101: it
    /// listed `.github/workflows/`, then read the bare `codecov-upload.yml`).
    /// Bounded in depth and entries so a huge tree cannot stall a failed read.
    fn suggest_paths(root: &Path, missing: &Path) -> Vec<String> {
        Self::suggest_paths_bounded(root, missing, SUGGEST_MAX_ENTRIES)
    }

    fn suggest_paths_bounded(root: &Path, missing: &Path, max_entries: usize) -> Vec<String> {
        let Some(wanted) = missing.file_name() else {
            return Vec::new();
        };
        let mut found = Vec::new();
        let mut visited = 0usize;
        let mut queue = std::collections::VecDeque::new();
        queue.push_back((root.to_path_buf(), 0usize));
        while let Some((dir, depth)) = queue.pop_front() {
            if visited >= max_entries {
                break;
            }
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            // Never hold more than the remaining entry budget in memory, so a
            // single huge directory cannot defeat SUGGEST_MAX_ENTRIES.
            let mut entries: Vec<_> = entries
                .flatten()
                .take(max_entries.saturating_sub(visited))
                .collect();
            entries.sort_by_key(|e| e.file_name());
            for entry in entries {
                visited += 1;
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                let path = entry.path();
                if file_type.is_dir() {
                    let name = entry.file_name();
                    let skip = SUGGEST_SKIP_DIRS.iter().any(|d| name == *d);
                    if !skip && depth < SUGGEST_MAX_DEPTH {
                        queue.push_back((path, depth + 1));
                    }
                } else if file_type.is_file() && entry.file_name() == wanted {
                    let shown = path.strip_prefix(".").unwrap_or(&path);
                    found.push(shown.to_string_lossy().to_string());
                    if found.len() >= SUGGEST_MAX_RESULTS {
                        return found;
                    }
                }
            }
        }
        found
    }

    fn missing_file_message(path: &Path) -> String {
        let suggestions = Self::suggest_paths(Path::new("."), path);
        if suggestions.is_empty() {
            "[Error: File does not exist]".to_string()
        } else {
            format!(
                "[Error: File does not exist. A file with that name exists at: {}. Use the full path.]",
                suggestions.join(", ")
            )
        }
    }

    fn read_file_content(&self, params: &ReadFileSpec) -> io::Result<String> {
        // If outline mode is requested, try to produce a symbol outline
        if params.outline {
            if let Some(config) = self.language_registry.config_for_path(&params.path) {
                let content = fs::read_to_string(&params.path)?;
                let symbols = extract_symbols(&content, config);
                return Ok(format_outline(&symbols, &params.path));
            }
            // Fall through to normal read if language is unsupported
        }

        let offset = params.offset.unwrap_or(1).max(1) as usize;
        let limit = params.limit.unwrap_or(DEFAULT_READ_LIMIT) as usize;

        let file = fs::File::open(&params.path)?;
        let reader = BufReader::new(file);

        // (line number, original content, display content)
        let mut lines: Vec<(u32, String, String)> = Vec::new();
        let mut total_lines = 0usize;
        let mut bytes_written = 0usize;

        for (i, line_result) in reader.lines().enumerate() {
            let line_num = i as u32 + 1;
            total_lines = line_num as usize;

            if line_num < offset as u32 {
                continue;
            }
            if lines.len() >= limit {
                break;
            }

            let line = line_result?;
            let display = if line.len() > MAX_LINE_LENGTH {
                format!(
                    "{}{}",
                    line.chars().take(MAX_LINE_LENGTH).collect::<String>(),
                    MAX_LINE_SUFFIX
                )
            } else {
                line.clone()
            };

            let line_size = display.len();
            if bytes_written + line_size > MAX_BYTES && !lines.is_empty() {
                break;
            }

            lines.push((line_num, line, display));
            bytes_written += line_size;
        }

        // Handle degenerate cases before computing the last shown line number
        if lines.is_empty() {
            return Ok(if total_lines == 0 {
                "(End of file - 0 lines)".to_string()
            } else if limit == 0 {
                "(No lines displayed: limit is 0)".to_string()
            } else {
                format!(
                    "(No lines displayed: offset {} is past end of file, {} lines total)",
                    offset, total_lines
                )
            });
        }

        // Build output with line numbers and hashes
        let mut output = lines
            .iter()
            .map(|(line_num, original, display)| {
                // Hash the full original line so hash-anchored edits work
                // even when the displayed text is truncated
                let hash = compute_line_hash(original);
                format!("{:4}: {} {}", line_num, hash, display)
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Add truncation footer
        let last_line = offset + lines.len() - 1;
        let truncated = lines.len() == limit || (lines.len() as u32) < total_lines as u32;
        if truncated {
            if lines.len() == limit {
                output.push_str(&format!(
                    "\n\n(Showing lines {}-{} of {}. Use offset={} to continue.)",
                    offset,
                    last_line,
                    total_lines,
                    last_line + 1
                ));
            } else {
                output.push_str(&format!(
                    "\n\n(Output capped at {}KB. Showing lines {}-{} of {}. Use offset={} to continue.)",
                    MAX_BYTES / 1024,
                    offset,
                    last_line,
                    total_lines,
                    last_line + 1
                ));
            }
        } else {
            output.push_str(&format!("\n\n(End of file - {} lines)", total_lines));
        }

        Ok(output)
    }
}

#[tool(name = "read", description = r#"Reads one or more files in a single call. Output always includes line numbers and hashes for precise editing.

**Usage:**
- Pass an array of file specs in the `files` parameter.
- Each spec requires a `path` and optionally `offset` (1-indexed start line) and `limit` (max lines to read, default 2000).
- Set `outline: true` to return a compact symbol outline instead of full file content. Useful for understanding file structure before reading specific sections.
- Lines longer than 2000 characters are truncated.
- Output is capped at 50KB per file; use `offset` to paginate through larger files.

**Best Practices:**
- When exploring an unfamiliar codebase, use `outline: true` on the first read to understand file structure.
- Use full reads (without `outline`) when you need exact content for editing.
- When investigating a task, read multiple potentially relevant files in a single call to build context.

**IMPORTANT:** This is the preferred tool for inspecting file contents. Do not use `bash` with `cat`, `less`, `head`, `tail`, or `bat` --- use this tool instead.

**Examples:**
Read a single file:
```json
{"files": [{"path": "src/main.rs"}]}
```
Read with offset and limit:
```json
{"files": [{"path": "src/main.rs", "offset": 50, "limit": 100}]}
```
Read multiple files:
```json
{"files": [{"path": "src/main.rs"}, {"path": "src/lib.rs"}]}
```
Get symbol outline:
```json
{"files": [{"path": "src/main.rs", "outline": true}]}
```
"#, capabilities = [Read])]
impl ReadTool {
    async fn execute(&self, params: ReadToolParams) -> ToolResult {
        if params.files.is_empty() {
            return ToolResult::error("At least one file path is required".to_string());
        }

        let mut outputs = Vec::new();
        let mut total_lines = 0usize;
        let mut file_count = 0usize;

        for file_spec in &params.files {
            let path = Path::new(&file_spec.path);

            if !path.exists() {
                outputs.push(format!(
                    "=== {} ===\n{}",
                    file_spec.path,
                    Self::missing_file_message(path)
                ));
                continue;
            }
            if !path.is_file() {
                outputs.push(format!(
                    "=== {} ===\n[Error: Path is not a file]",
                    file_spec.path
                ));
                continue;
            }

            // Check for binary files
            if Self::is_binary_file(&file_spec.path) {
                outputs.push(format!(
                    "=== {} ===\n[Error: Cannot read binary file]",
                    file_spec.path
                ));
                continue;
            }

            match self.read_file_content(file_spec) {
                Ok(content) => {
                    total_lines += content.lines().count();
                    file_count += 1;
                    self.operation_log
                        .log_operation(FsOperationType::Read, file_spec.path.clone())
                        .await;
                    outputs.push(format!("=== {} ===\n{}", file_spec.path, content));
                }
                Err(e) => {
                    outputs.push(format!("=== {} ===\n[Error: {}]", file_spec.path, e));
                }
            }
        }

        // Nothing was read: report a tool error, so a failed read is not cached
        // as a success and the model sees that the call did not work.
        if file_count == 0 {
            return ToolResult::error(outputs.join("\n\n"));
        }

        let mut meta = HashMap::new();
        meta.insert("file_count".to_string(), json!(file_count));
        meta.insert("total_lines".to_string(), json!(total_lines));

        ToolResult::Success {
            output: outputs.join("\n\n"),
            metadata: Some(meta),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shai_llm::ToolDescription;

    #[test]
    fn test_read_schema_required_fields() {
        let operation_log = Arc::new(FsOperationLog::new());
        let tool = ReadTool::new(operation_log);
        let schema = tool.parameters_schema();

        // The "files" field should be present in properties
        let files_prop = &schema["properties"]["files"];
        assert_eq!(files_prop["type"].as_str().unwrap_or(""), "array");
    }

    fn spec(path: &std::path::Path, offset: Option<u32>, limit: Option<u32>) -> ReadFileSpec {
        ReadFileSpec {
            path: path.to_string_lossy().to_string(),
            offset,
            limit,
            outline: false,
        }
    }

    #[test]
    fn test_read_hashes_original_line_not_truncated_display() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("long.txt");
        let long_line = "x".repeat(MAX_LINE_LENGTH + 500);
        fs::write(&path, format!("{}\nshort line\n", long_line)).unwrap();

        let tool = ReadTool::new(Arc::new(FsOperationLog::new()));
        let out = tool.read_file_content(&spec(&path, None, None)).unwrap();

        // Hash must match the full original line, not the truncated display
        let original_hash = compute_line_hash(&long_line);
        let display = format!(
            "{}{}",
            long_line.chars().take(MAX_LINE_LENGTH).collect::<String>(),
            MAX_LINE_SUFFIX
        );
        assert_ne!(original_hash, compute_line_hash(&display));
        assert!(out.contains(&original_hash));
        assert!(out.contains(&display));
    }

    #[test]
    fn test_read_empty_file_and_out_of_range() {
        let dir = tempfile::TempDir::new().unwrap();
        let tool = ReadTool::new(Arc::new(FsOperationLog::new()));

        let empty = dir.path().join("empty.txt");
        fs::write(&empty, "").unwrap();
        let out = tool.read_file_content(&spec(&empty, None, None)).unwrap();
        assert!(out.contains("End of file - 0 lines"));

        let small = dir.path().join("small.txt");
        fs::write(&small, "a\nb\n").unwrap();
        let out = tool
            .read_file_content(&spec(&small, Some(100), None))
            .unwrap();
        assert!(out.contains("offset 100 is past end of file"));

        let out = tool
            .read_file_content(&spec(&small, None, Some(0)))
            .unwrap();
        assert!(out.contains("limit is 0"));
    }

    #[test]
    fn test_suggest_paths_finds_forgotten_directory() {
        // ovh/shai issue 101: model listed .github/workflows, then read the bare name.
        let dir = tempfile::TempDir::new().unwrap();
        let wf = dir.path().join(".github").join("workflows");
        fs::create_dir_all(&wf).unwrap();
        fs::write(wf.join("codecov-upload.yml"), "name: codecov\n").unwrap();
        fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
        fs::write(dir.path().join("node_modules/pkg/codecov-upload.yml"), "x").unwrap();

        let found = ReadTool::suggest_paths(dir.path(), Path::new("codecov-upload.yml"));
        assert_eq!(found.len(), 1, "node_modules must be skipped: {found:?}");
        assert!(
            found[0].ends_with(".github/workflows/codecov-upload.yml"),
            "{found:?}"
        );
    }

    #[test]
    fn test_suggest_paths_is_bounded_and_empty_when_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        for i in 0..(SUGGEST_MAX_RESULTS + 3) {
            let d = dir.path().join(format!("d{i}"));
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("dup.txt"), "x").unwrap();
        }
        let found = ReadTool::suggest_paths(dir.path(), Path::new("dup.txt"));
        assert_eq!(found.len(), SUGGEST_MAX_RESULTS);
        assert!(ReadTool::suggest_paths(dir.path(), Path::new("nope.txt")).is_empty());
        assert!(ReadTool::suggest_paths(dir.path(), Path::new("/")).is_empty());
    }

    #[test]
    fn test_suggest_paths_enforces_entry_budget_inside_one_directory() {
        // The match sorts after 50 decoys; a budget of 10 must stop before reaching it.
        let dir = tempfile::TempDir::new().unwrap();
        for i in 0..50 {
            fs::write(dir.path().join(format!("a{i:02}.txt")), "x").unwrap();
        }
        fs::write(dir.path().join("zz-target.txt"), "x").unwrap();
        let tight = ReadTool::suggest_paths_bounded(dir.path(), Path::new("zz-target.txt"), 10);
        assert!(tight.is_empty(), "budget ignored: {tight:?}");
        let roomy = ReadTool::suggest_paths_bounded(dir.path(), Path::new("zz-target.txt"), 1000);
        assert_eq!(roomy.len(), 1);
    }

    #[tokio::test]
    async fn test_read_all_missing_is_tool_error_not_success() {
        // A read that read nothing must not look successful (and so must not be cached).
        let tool = ReadTool::new(Arc::new(FsOperationLog::new()));
        let result = tool
            .execute(ReadToolParams {
                files: vec![ReadFileSpec {
                    path: "/nonexistent-dir-101/codecov-upload.yml".to_string(),
                    offset: None,
                    limit: None,
                    outline: false,
                }],
            })
            .await;
        match result {
            ToolResult::Error { error, .. } => assert!(error.contains("does not exist")),
            other => panic!("expected tool error, got {other:?}"),
        }
    }
}
