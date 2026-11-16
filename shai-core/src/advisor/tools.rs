// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

//! The advisor's tools: a fixed, read-only set.
//!
//! The set is the [`AdvisorTool`] enum. It is not built from configuration,
//! not derived from the session's toolbox, and cannot be extended at run
//! time: a tool the advisor can call is a variant here, and a name that is
//! not a variant is refused before anything runs. None of the variants can
//! write, execute a command or reach the network, and all of them read
//! through [`ConfinedFs`], which keeps them inside the working directory.
//!
//! What a tool returns has been through the [`Redactor`]. A file is redacted
//! whole before lines are picked from it, cut or searched, so that no window
//! on it can show half of a secret, and a search cannot be used to probe one.
//! A path is redacted by itself before it is matched or shown, for the same
//! reasons, and so that it is never read together with the text that follows
//! it on a line.

use super::confine::{listed, shown_name, ConfineError, ConfinedFs};
use super::redact::Redactor;
use regex::RegexBuilder;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Names of the tools the advisor may call. This is the whole list.
pub const ADVISOR_TOOL_ALLOWLIST: [&str; 4] = ["read", "ls", "find", "grep"];

/// Most lines one `read` returns.
const MAX_READ_LINES: usize = 400;
/// Most bytes one `read` or `grep` loads from a single file.
const MAX_FILE_BYTES: usize = 256 * 1024;
/// Longest line shown before it is cut.
const MAX_LINE_CHARS: usize = 300;
/// Most entries `ls` lists.
const MAX_LS_ENTRIES: usize = 200;
/// Most entries `ls` reads from a directory before it stops.
const MAX_LS_SCAN: usize = 5_000;
/// Most results `find` or `grep` return.
const MAX_MATCHES: usize = 100;
/// Most directory entries one `find` or `grep` walk reads, whether it then
/// visits them or leaves them out. It is also the most one directory can
/// make the walk hold in memory and sort.
const MAX_WALK_ENTRIES: usize = 20_000;
/// Longest one `find` or `grep` walk may run. The walk happens on a blocking
/// thread that cannot be cancelled, so it has to stop by itself. The time is
/// looked at for every entry read and before every file visited; one visit
/// is bounded by [`MAX_FILE_BYTES`].
const MAX_WALK_TIME: Duration = Duration::from_secs(10);
/// Directories a walk does not descend into: build output and dependencies.
const SKIPPED_WALK_DIRS: &[&str] = &[
    "target",
    "node_modules",
    "dist",
    "build",
    ".next",
    "vendor",
    ".venv",
    "venv",
    ".tox",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".gradle",
    ".cache",
];

/// One of the advisor's tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdvisorTool {
    Read,
    Ls,
    Find,
    Grep,
}

impl AdvisorTool {
    /// Every tool, in the order of [`ADVISOR_TOOL_ALLOWLIST`].
    pub(crate) const ALL: [AdvisorTool; 4] = [
        AdvisorTool::Read,
        AdvisorTool::Ls,
        AdvisorTool::Find,
        AdvisorTool::Grep,
    ];

    /// The tool called `name`, or `None` for any name off the allowlist.
    /// The match is exact: no aliases, no prefix stripping.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            AdvisorTool::Read => "read",
            AdvisorTool::Ls => "ls",
            AdvisorTool::Find => "find",
            AdvisorTool::Grep => "grep",
        }
    }

    pub(crate) fn description(self) -> &'static str {
        match self {
            AdvisorTool::Read => {
                "Read a text file in the working directory. Returns numbered lines."
            }
            AdvisorTool::Ls => "List the entries of a directory in the working directory.",
            AdvisorTool::Find => {
                "Find files in the working directory whose path matches a regular expression."
            }
            AdvisorTool::Grep => {
                "Search file contents in the working directory with a regular expression."
            }
        }
    }

    /// JSON schema of the tool's arguments.
    pub(crate) fn parameters(self) -> Value {
        match self {
            AdvisorTool::Read => json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File to read, relative to the working directory"},
                    "offset": {"type": "integer", "description": "First line to return, starting at 1 (default 1)"},
                    "limit": {"type": "integer", "description": "Number of lines to return (default and maximum 400)"}
                },
                "required": ["path"]
            }),
            AdvisorTool::Ls => json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory to list, relative to the working directory (default: the working directory)"}
                }
            }),
            AdvisorTool::Find => json!({
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regular expression matched against each file's relative path"},
                    "path": {"type": "string", "description": "Directory to search (default: the working directory)"}
                },
                "required": ["pattern"]
            }),
            AdvisorTool::Grep => json!({
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regular expression matched against each line"},
                    "path": {"type": "string", "description": "File or directory to search (default: the working directory)"},
                    "ignore_case": {"type": "boolean", "description": "Match case-insensitively (default false)"}
                },
                "required": ["pattern"]
            }),
        }
    }

    /// Run the tool. Errors are returned as text for the model, like results.
    /// Either way the text has been redacted.
    pub(crate) fn run(self, fs: &ConfinedFs, redactor: &Redactor, args: &Value) -> String {
        let result = match self {
            AdvisorTool::Read => read(fs, redactor, args),
            AdvisorTool::Ls => ls(fs, redactor, args),
            AdvisorTool::Find => find(fs, redactor, args),
            AdvisorTool::Grep => grep(fs, redactor, args),
        };
        result.unwrap_or_else(|failure| failure.shown(redactor))
    }
}

/// Why a tool has no result to return.
#[derive(Debug)]
struct Failure {
    /// The path the failure is about, when it is about one.
    path: Option<String>,
    reason: String,
}

impl Failure {
    fn about(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            path: Some(path.into()),
            reason: reason.into(),
        }
    }

    /// The line the advisor is given. The path and the reason are redacted
    /// apart: read together, `token.rs: not a text file` would look like a
    /// field called token and its value.
    fn shown(&self, redactor: &Redactor) -> String {
        let reason = redactor.redact(&self.reason);
        match &self.path {
            Some(path) => format!("error: {}: {reason}", redactor.redact(path)),
            None => format!("error: {reason}"),
        }
    }
}

impl From<ConfineError> for Failure {
    fn from(error: ConfineError) -> Self {
        Self::about(error.path(), error.reason())
    }
}

/// A failure that is about no path: a bad argument, a bad pattern.
impl From<String> for Failure {
    fn from(reason: String) -> Self {
        Self { path: None, reason }
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn required_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    str_arg(args, key).ok_or_else(|| format!("missing string argument \"{key}\""))
}

fn usize_arg(args: &Value, key: &str) -> Option<usize> {
    args.get(key).and_then(Value::as_u64).map(|n| n as usize)
}

fn clip_line(line: &str) -> String {
    if line.chars().count() > MAX_LINE_CHARS {
        let cut: String = line.chars().take(MAX_LINE_CHARS).collect();
        format!("{cut}…")
    } else {
        line.to_string()
    }
}

/// The text of a file, or `None` when it is not UTF-8 text.
fn text_of(bytes: &[u8]) -> Option<&str> {
    if bytes.contains(&0) {
        return None;
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(text),
        // A multi-byte character cut by the size limit: keep what is valid.
        Err(error) if error.error_len().is_none() => {
            std::str::from_utf8(&bytes[..error.valid_up_to()]).ok()
        }
        Err(_) => None,
    }
}

fn read(fs: &ConfinedFs, redactor: &Redactor, args: &Value) -> Result<String, Failure> {
    let path = required_str(args, "path")?;
    let offset = usize_arg(args, "offset").unwrap_or(1).max(1);
    let limit = usize_arg(args, "limit")
        .unwrap_or(MAX_READ_LINES)
        .clamp(1, MAX_READ_LINES);

    let (bytes, truncated) = fs.read(path, MAX_FILE_BYTES)?;
    let text = text_of(&bytes).ok_or_else(|| Failure::about(path, "not a text file"))?;
    // The whole file, before any line is picked or cut. A file that was too
    // large to read in full may end inside a secret.
    let text = if truncated {
        redactor.redact_truncated(text)
    } else {
        redactor.redact(text)
    };

    let mut out = String::new();
    let mut shown = 0;
    let mut total = 0;
    for (index, line) in text.lines().enumerate() {
        total = index + 1;
        if total < offset || shown >= limit {
            continue;
        }
        out.push_str(&format!("{:>5}  {}\n", total, clip_line(line)));
        shown += 1;
    }
    if shown == 0 {
        return Ok(format!(
            "{}: no lines at offset {offset} ({total} lines)",
            redactor.redact(path)
        ));
    }
    if truncated {
        out.push_str("[file truncated: too large to read in full]\n");
    } else if offset + shown <= total {
        out.push_str(&format!("[{} more lines]\n", total + 1 - offset - shown));
    }
    Ok(out)
}

fn ls(fs: &ConfinedFs, redactor: &Redactor, args: &Value) -> Result<String, Failure> {
    let dir = fs.resolve_dir(str_arg(args, "path").unwrap_or("."))?;

    let mut entries: Vec<String> = Vec::new();
    let mut listing =
        std::fs::read_dir(&dir).map_err(|e| Failure::about(fs.display(&dir), e.to_string()))?;
    let mut partial = false;
    // Entries the advisor may not look at are left out, by the same rule as
    // `read`, `find` and `grep` use, and only counted.
    let mut hidden = 0;
    for (scanned, entry) in listing.by_ref().enumerate() {
        // A directory can hold any number of entries: stop reading at some.
        if scanned >= MAX_LS_SCAN {
            partial = true;
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // A link is judged by its own name here: it is never followed.
        if !fs.may_visit(&entry.path(), false, file_type.is_dir()) {
            hidden += 1;
            continue;
        }
        // Each name by itself, before the list is put in order: where an
        // entry comes in the list then says nothing about what was removed
        // from its name.
        let name = listed(redactor.redact(&shown_name(&entry.file_name().to_string_lossy())));
        // Names only: nothing here is opened or followed.
        if file_type.is_dir() {
            entries.push(format!("{name}/"));
        } else if file_type.is_symlink() {
            entries.push(format!("{name}@"));
        } else {
            entries.push(name);
        }
    }
    entries.sort();

    let total = entries.len();
    entries.truncate(MAX_LS_ENTRIES);
    let mut out = entries.join("\n");
    if partial {
        out.push_str(&format!(
            "\n[the directory holds more than {MAX_LS_SCAN} entries: this is a part of them]"
        ));
    } else if total > MAX_LS_ENTRIES {
        out.push_str(&format!("\n[{} more entries]", total - MAX_LS_ENTRIES));
    }
    if hidden > 0 {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!(
            "[{hidden} not shown: they may hold credentials or internal state]"
        ));
    }
    if out.is_empty() {
        out.push_str("(empty directory)");
    }
    Ok(out)
}

/// How a walk ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Walk {
    /// Every file was visited.
    Complete,
    /// The visitor had what it wanted and asked to stop.
    Stopped,
    /// The walk ran into its own limits before the tree was covered.
    CutShort,
}

/// What a walk did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Walked {
    end: Walk,
    /// Files and directories the walk came across and left out because the
    /// advisor may not look at them. Links and build output are not counted.
    refused: usize,
    /// Directories, and files for `grep`, that could not be read: the walk
    /// did not cover what is in them.
    unreadable: usize,
}

/// Visit the regular files under `start`, in a stable order, staying inside
/// the confined tree. `visit` returns false to stop the walk.
fn walk_files(fs: &ConfinedFs, start: &Path, visit: impl FnMut(&Path) -> bool) -> Walked {
    walk_within(MAX_WALK_ENTRIES, MAX_WALK_TIME, fs, start, visit)
}

/// [`walk_files`] with its limits given: the number of directory entries it
/// may read and the time it may take.
fn walk_within(
    max_entries: usize,
    max_time: Duration,
    fs: &ConfinedFs,
    start: &Path,
    mut visit: impl FnMut(&Path) -> bool,
) -> Walked {
    let started = Instant::now();
    let mut read = 0;
    let mut refused = 0;
    let mut unreadable = 0;
    // The directories the walk is in, outermost first: for each, the entries
    // it kept that are still to be handled, in the order of their names.
    let mut open: Vec<std::vec::IntoIter<(PathBuf, bool)>> = Vec::new();
    let mut enter = Some(start.to_path_buf());
    let end = 'walk: loop {
        if let Some(dir) = enter.take() {
            let mut kept = Vec::new();
            // A directory that cannot be read is passed over, and counted:
            // "no match" must not read as "not there" for what is in it.
            let listing = match std::fs::read_dir(&dir) {
                Ok(listing) => Some(listing),
                Err(_) => {
                    unreadable += 1;
                    None
                }
            };
            for entry in listing.into_iter().flatten() {
                // Every entry read counts towards the limits, whatever it is
                // and whether it is kept or left out: a directory of a
                // million files that are all left out is as long to go
                // through as one whose files are searched. The limits are
                // looked at here, as entries are read, so that a walk never
                // holds or sorts more entries than it may read.
                read += 1;
                if read > max_entries || started.elapsed() >= max_time {
                    break 'walk Walk::CutShort;
                }
                let Ok(entry) = entry else {
                    continue;
                };
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                // Links are never followed.
                if file_type.is_symlink() {
                    continue;
                }
                let is_dir = file_type.is_dir();
                if is_dir
                    && SKIPPED_WALK_DIRS.contains(&entry.file_name().to_string_lossy().as_ref())
                {
                    continue;
                }
                let path = entry.path();
                if !fs.may_visit(&path, false, is_dir) {
                    refused += 1;
                    continue;
                }
                if is_dir || file_type.is_file() {
                    kept.push((path, is_dir));
                }
            }
            kept.sort_by(|(a, _), (b, _)| a.file_name().cmp(&b.file_name()));
            open.push(kept.into_iter());
        }
        let Some(entries) = open.last_mut() else {
            break 'walk Walk::Complete;
        };
        match entries.next() {
            None => {
                open.pop();
            }
            Some((dir, true)) => enter = Some(dir),
            Some((file, false)) => {
                if started.elapsed() >= max_time {
                    break 'walk Walk::CutShort;
                }
                if !visit(&file) {
                    break 'walk Walk::Stopped;
                }
            }
        }
    };
    Walked {
        end,
        refused,
        unreadable,
    }
}

/// What to add to the results of a search that did not cover everything.
fn walk_note(walked: Walked) -> String {
    let mut note = match walked.end {
        Walk::Complete => "",
        Walk::Stopped => "\n[more results not shown]",
        Walk::CutShort => "\n[the search stopped before it had looked everywhere: narrow the path]",
    }
    .to_string();
    // Without this line, "no match" would read as "it is not there".
    match walked.refused {
        0 => {}
        1 => note
            .push_str("\n[1 entry was skipped because it may hold credentials or internal state]"),
        refused => note.push_str(&format!(
            "\n[{refused} entries were skipped because they may hold credentials or internal state]"
        )),
    }
    match walked.unreadable {
        0 => {}
        1 => note.push_str("\n[1 entry could not be read: the search did not cover it]"),
        unreadable => note.push_str(&format!(
            "\n[{unreadable} entries could not be read: the search did not cover them]"
        )),
    }
    note
}

fn compile(pattern: &str, ignore_case: bool) -> Result<regex::Regex, String> {
    RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .size_limit(1 << 20)
        .build()
        .map_err(|e| format!("invalid regular expression: {e}"))
}

fn find(fs: &ConfinedFs, redactor: &Redactor, args: &Value) -> Result<String, Failure> {
    let regex = compile(required_str(args, "pattern")?, true)?;
    let start = fs.resolve_dir(str_arg(args, "path").unwrap_or("."))?;

    let mut matches = Vec::new();
    let walked = walk_files(fs, &start, |path| {
        // The pattern is matched against the path as the advisor may see
        // it: whether a path comes back never tells it anything about a
        // part of the path that is not shown.
        let shown = listed(redactor.redact(&fs.display(path)));
        if regex.is_match(&shown) {
            matches.push(shown);
        }
        matches.len() < MAX_MATCHES
    });

    let mut out = if matches.is_empty() {
        "no file matches".to_string()
    } else {
        matches.join("\n")
    };
    out.push_str(&walk_note(walked));
    Ok(out)
}

fn grep(fs: &ConfinedFs, redactor: &Redactor, args: &Value) -> Result<String, Failure> {
    let ignore_case = args
        .get("ignore_case")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let regex = compile(required_str(args, "pattern")?, ignore_case)?;
    let start = fs.resolve(str_arg(args, "path").unwrap_or("."))?;

    let mut matches: Vec<String> = Vec::new();
    let mut partly_searched = 0;
    let mut unreadable_files = 0;
    let mut search = |path: &Path| {
        let Ok((bytes, truncated)) = fs.read_resolved(path, MAX_FILE_BYTES) else {
            unreadable_files += 1;
            return true;
        };
        let Some(text) = text_of(&bytes) else {
            return true;
        };
        if truncated {
            partly_searched += 1;
        }
        // The pattern is matched against what the advisor may see, not
        // against what the file holds: a match never tells it anything about
        // a secret that the matching line would not show.
        let text = if truncated {
            redactor.redact_truncated(text)
        } else {
            redactor.redact(text)
        };
        // The path by itself, and only once a line of the file is shown. Put
        // in front of a line first and redacted with it, `token.rs:12:` would
        // be read as a field called token and its value.
        let mut shown_path = None;
        for (index, line) in text.lines().enumerate() {
            if regex.is_match(line) {
                matches.push(format!(
                    "{}:{}: {}",
                    shown_path.get_or_insert_with(|| listed(redactor.redact(&fs.display(path)))),
                    index + 1,
                    clip_line(line.trim_end())
                ));
                if matches.len() >= MAX_MATCHES {
                    return false;
                }
            }
        }
        true
    };

    let walked = if start.is_dir() {
        walk_files(fs, &start, &mut search)
    } else {
        let end = if search(&start) {
            Walk::Complete
        } else {
            Walk::Stopped
        };
        Walked {
            end,
            refused: 0,
            unreadable: 0,
        }
    };
    let walked = Walked {
        unreadable: walked.unreadable + unreadable_files,
        ..walked
    };

    let mut out = if matches.is_empty() {
        "no match".to_string()
    } else {
        matches.join("\n")
    };
    out.push_str(&walk_note(walked));
    if partly_searched > 0 {
        out.push_str(&format!(
            "\n[{partly_searched} large file(s) were searched only in part]"
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn project() -> (TempDir, ConfinedFs) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("work");
        fs::create_dir_all(root.join("src/nested")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::write(
            root.join("src/main.rs"),
            "fn main() {\n    let answer = 42;\n}\n",
        )
        .unwrap();
        fs::write(
            root.join("src/nested/lib.rs"),
            "pub fn answer() -> u32 {\n    42\n}\n",
        )
        .unwrap();
        fs::write(root.join("README.md"), "# Demo\nThe ANSWER is here.\n").unwrap();
        fs::write(root.join(".env"), "API_TOKEN=answer-token-123456\n").unwrap();
        fs::write(
            root.join(".git/config"),
            "[remote]\nurl = https://answer@host\n",
        )
        .unwrap();
        fs::write(root.join("target/debug/out.txt"), "answer\n").unwrap();
        fs::write(tmp.path().join("outside.txt"), "the answer outside\n").unwrap();
        let fs = ConfinedFs::new(&root).unwrap();
        (tmp, fs)
    }

    /// What a search over the whole of [`project`] ends with: it came across
    /// `.env` and `.git`. `target` is build output and is not counted.
    const TWO_SKIPPED: &str =
        "\n[2 entries were skipped because they may hold credentials or internal state]";

    #[test]
    fn the_allowlist_is_exactly_four_read_only_tools() {
        assert_eq!(ADVISOR_TOOL_ALLOWLIST, ["read", "ls", "find", "grep"]);
        let names: Vec<&str> = AdvisorTool::ALL.iter().map(|tool| tool.name()).collect();
        assert_eq!(names, ADVISOR_TOOL_ALLOWLIST);
        for name in ADVISOR_TOOL_ALLOWLIST {
            assert_eq!(AdvisorTool::from_name(name).unwrap().name(), name);
        }
    }

    #[test]
    fn no_other_name_resolves_to_a_tool() {
        // Every built-in tool of the main agent that is not on the allowlist,
        // and the spellings a model might try to get at one.
        let mut refused: Vec<String> = crate::tools::TOOL_NAMES
            .iter()
            .filter(|name| !ADVISOR_TOOL_ALLOWLIST.contains(name))
            .map(|name| name.to_string())
            .collect();
        for name in [
            "bash",
            "write",
            "edit",
            "fetch",
            "todo_write",
            "memory_write",
        ] {
            assert!(
                refused.contains(&name.to_string()),
                "{name} should be a built-in tool"
            );
        }
        refused.extend(
            [
                "",
                "Read",
                "READ",
                "read ",
                " read",
                "functions.read",
                "read<|channel|>",
                "search",
                "cat",
                "shell",
                "exec",
                "multiedit",
                "skill",
                "mcp",
                "read\0bash",
            ]
            .map(String::from),
        );
        for name in refused {
            assert!(
                AdvisorTool::from_name(&name).is_none(),
                "{name:?} must not resolve"
            );
        }
    }

    #[test]
    fn every_tool_describes_itself_with_an_object_schema() {
        for tool in AdvisorTool::ALL {
            assert!(!tool.description().is_empty());
            let schema = tool.parameters();
            assert_eq!(schema["type"], "object", "{}", tool.name());
            assert!(schema["properties"].is_object(), "{}", tool.name());
        }
    }

    #[test]
    fn read_returns_numbered_lines_within_bounds() {
        let (_tmp, fs) = project();
        let out = AdvisorTool::Read.run(&fs, &Redactor::default(), &json!({"path": "src/main.rs"}));
        assert_eq!(
            out,
            "    1  fn main() {\n    2      let answer = 42;\n    3  }\n"
        );

        let out = AdvisorTool::Read.run(
            &fs,
            &Redactor::default(),
            &json!({"path": "src/main.rs", "offset": 2, "limit": 1}),
        );
        assert_eq!(out, "    2      let answer = 42;\n[1 more lines]\n");

        for (args, expected) in [
            (json!({}), "missing string argument"),
            (json!({"path": 5}), "missing string argument"),
            (json!({"path": "nope.rs"}), "no such file"),
            (json!({"path": "src"}), "error:"),
            (
                json!({"path": "../outside.txt"}),
                "outside the working directory",
            ),
            (json!({"path": ".env"}), "access refused"),
            (json!({"path": ".git/config"}), "access refused"),
        ] {
            let out = AdvisorTool::Read.run(&fs, &Redactor::default(), &args);
            assert!(out.starts_with("error:"), "{args}: {out}");
            assert!(out.contains(expected), "{args}: {out}");
            assert!(!out.contains("answer"), "{args}: {out}");
        }
    }

    #[test]
    fn read_refuses_binary_files_and_truncates_long_ones() {
        let (tmp, fs) = project();
        let root = tmp.path().join("work");
        std::fs::write(root.join("blob.bin"), [0u8, 159, 146, 150]).unwrap();
        let out = AdvisorTool::Read.run(&fs, &Redactor::default(), &json!({"path": "blob.bin"}));
        assert!(out.contains("not a text file"), "{out}");

        let long: String = (0..1000).map(|i| format!("line {i}\n")).collect();
        std::fs::write(root.join("long.txt"), long).unwrap();
        let out = AdvisorTool::Read.run(&fs, &Redactor::default(), &json!({"path": "long.txt"}));
        assert_eq!(out.lines().count(), MAX_READ_LINES + 1);
        assert!(
            out.ends_with("[600 more lines]\n"),
            "{}",
            &out[out.len() - 40..]
        );

        std::fs::write(root.join("wide.txt"), "y".repeat(5000)).unwrap();
        let out = AdvisorTool::Read.run(&fs, &Redactor::default(), &json!({"path": "wide.txt"}));
        assert!(out.chars().count() < MAX_LINE_CHARS + 20, "{}", out.len());
    }

    #[test]
    fn ls_lists_names_and_does_not_enter_sensitive_directories() {
        let (_tmp, fs) = project();
        let out = AdvisorTool::Ls.run(&fs, &Redactor::default(), &json!({}));
        // `.env` and `.git` are left out by the same rule as `read` applies,
        // and only counted.
        assert_eq!(
            out,
            "README.md\nsrc/\ntarget/\n[2 not shown: they may hold credentials or internal state]"
        );
        let out = AdvisorTool::Ls.run(&fs, &Redactor::default(), &json!({"path": "src"}));
        assert_eq!(out, "main.rs\nnested/");

        for path in [".git", "..", "/", "src/main.rs", "nope"] {
            let out = AdvisorTool::Ls.run(&fs, &Redactor::default(), &json!({"path": path}));
            assert!(out.starts_with("error:"), "{path}: {out}");
        }
    }

    #[test]
    fn ls_leaves_out_sensitive_names_of_any_kind_and_counts_them() {
        let (tmp, fs) = project();
        let root = tmp.path().join("work");
        fs::create_dir_all(root.join("conf/.npmrc")).unwrap();
        fs::write(root.join("conf/settings.toml"), "a = 1\n").unwrap();
        fs::write(root.join("conf/id_rsa"), "key\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("settings.toml", root.join("conf/prod.env")).unwrap();
        let out = AdvisorTool::Ls.run(&fs, &Redactor::default(), &json!({"path": "conf"}));
        let hidden = if cfg!(unix) { 3 } else { 2 };
        assert_eq!(
            out,
            format!(
                "settings.toml\n[{hidden} not shown: they may hold credentials or internal state]"
            )
        );

        // A directory holding only such names says so, and is not "empty".
        fs::create_dir_all(root.join("only")).unwrap();
        fs::write(root.join("only/.env.local"), "X=1\n").unwrap();
        let out = AdvisorTool::Ls.run(&fs, &Redactor::default(), &json!({"path": "only"}));
        assert_eq!(
            out,
            "[1 not shown: they may hold credentials or internal state]"
        );
    }

    #[test]
    fn a_directory_named_like_a_secret_file_is_never_entered() {
        let (tmp, fs) = project();
        let root = tmp.path().join("work");
        // `.env`, `.npmrc` and `prod.env` as directories, with secrets in them.
        fs::remove_file(root.join(".env")).unwrap();
        for dir in [".env", "app/.npmrc", "deploy/prod.env"] {
            fs::create_dir_all(root.join(dir)).unwrap();
            fs::write(root.join(dir).join("values.rs"), "answer-token-123456\n").unwrap();
        }
        let redactor = Redactor::default();
        for path in [
            ".env",
            ".env/values.rs",
            "app/.npmrc",
            "app/.npmrc/values.rs",
            "deploy/prod.env/values.rs",
        ] {
            for tool in [AdvisorTool::Read, AdvisorTool::Ls, AdvisorTool::Grep] {
                let args = json!({"path": path, "pattern": "answer"});
                let out = tool.run(&fs, &redactor, &args);
                assert!(
                    out.contains("access refused"),
                    "{} {path}: {out}",
                    tool.name()
                );
                assert!(
                    !out.contains("answer-token"),
                    "{} {path}: {out}",
                    tool.name()
                );
            }
        }

        // Walks skip them, and say they skipped something.
        let out = AdvisorTool::Grep.run(&fs, &redactor, &json!({"pattern": "answer-token"}));
        assert!(out.starts_with("no match"), "{out}");
        assert!(out.contains("skipped"), "{out}");
        let out = AdvisorTool::Find.run(&fs, &redactor, &json!({"pattern": "values"}));
        assert!(out.starts_with("no file matches"), "{out}");
        assert!(out.contains("skipped"), "{out}");
    }

    #[test]
    fn a_sensitive_directory_name_gives_one_answer_whether_or_not_it_exists() {
        let (tmp, fs) = project();
        let root = tmp.path().join("work");
        fs::create_dir_all(root.join("app/.npmrc")).unwrap();
        fs::write(root.join("app/.npmrc/x.rs"), "x\n").unwrap();
        let redactor = Redactor::default();
        for tool in [AdvisorTool::Read, AdvisorTool::Ls] {
            let there = tool.run(&fs, &redactor, &json!({"path": "app/.npmrc/x.rs"}));
            let missing = tool.run(&fs, &redactor, &json!({"path": "lib/.npmrc/x.rs"}));
            assert_eq!(
                there.replace("app/", "lib/"),
                missing,
                "{}: an existing and a missing path must read the same",
                tool.name()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn searches_say_when_a_directory_could_not_be_read() {
        use std::os::unix::fs::PermissionsExt;
        let (tmp, fs) = project();
        let locked = tmp.path().join("work/src/locked");
        fs::create_dir_all(&locked).unwrap();
        fs::write(locked.join("hidden.rs"), "fn answer() {}\n").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        // Running as root (or in a user namespace mapped to root) reads it
        // anyway: then there is nothing to report.
        let readable = std::fs::read_dir(&locked).is_ok();

        let grep = AdvisorTool::Grep.run(
            &fs,
            &Redactor::default(),
            &json!({"pattern": "nothing-matches-this", "path": "src"}),
        );
        let find = AdvisorTool::Find.run(
            &fs,
            &Redactor::default(),
            &json!({"pattern": "nothing-matches-this", "path": "src"}),
        );
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        if readable {
            return;
        }
        for out in [grep, find] {
            assert!(
                out.contains("[1 entry could not be read: the search did not cover it]"),
                "{out}"
            );
        }
    }

    #[test]
    fn walk_note_reports_what_could_not_be_read() {
        let note = walk_note(Walked {
            end: Walk::Complete,
            refused: 0,
            unreadable: 2,
        });
        assert_eq!(
            note,
            "\n[2 entries could not be read: the search did not cover them]"
        );
    }

    #[test]
    fn find_matches_paths_and_skips_what_must_not_be_seen() {
        let (_tmp, fs) = project();
        let out = AdvisorTool::Find.run(&fs, &Redactor::default(), &json!({"pattern": r"\.rs$"}));
        assert_eq!(out, format!("src/main.rs\nsrc/nested/lib.rs{TWO_SKIPPED}"));

        // Everything a walk reaches: no .env, nothing under .git or target,
        // nothing outside.
        let out = AdvisorTool::Find.run(&fs, &Redactor::default(), &json!({"pattern": "."}));
        assert_eq!(
            out,
            format!("README.md\nsrc/main.rs\nsrc/nested/lib.rs{TWO_SKIPPED}")
        );

        // "Nothing found" comes with what was not looked at, so that it is
        // not taken for "nothing there".
        assert_eq!(
            AdvisorTool::Find.run(&fs, &Redactor::default(), &json!({"pattern": "zzz"})),
            format!("no file matches{TWO_SKIPPED}")
        );
        assert_eq!(
            AdvisorTool::Find.run(&fs, &Redactor::default(), &json!({"pattern": r"\.env"})),
            format!("no file matches{TWO_SKIPPED}")
        );
        // A search that came across nothing of the kind says nothing more.
        assert_eq!(
            AdvisorTool::Find.run(
                &fs,
                &Redactor::default(),
                &json!({"pattern": "zzz", "path": "src"})
            ),
            "no file matches"
        );
        for args in [
            json!({"pattern": "("}),
            json!({"pattern": ".", "path": ".."}),
            json!({"pattern": ".", "path": ".git"}),
            json!({}),
        ] {
            let out = AdvisorTool::Find.run(&fs, &Redactor::default(), &args);
            assert!(out.starts_with("error:"), "{args}: {out}");
        }
    }

    #[test]
    fn grep_searches_contents_inside_the_root_only() {
        let (_tmp, fs) = project();
        let out = AdvisorTool::Grep.run(&fs, &Redactor::default(), &json!({"pattern": "answer"}));
        // Not the .env token, not .git/config, not target/, not the file
        // outside; and case-sensitive unless asked otherwise.
        assert_eq!(
            out,
            format!(
                "src/main.rs:2:     let answer = 42;\nsrc/nested/lib.rs:1: pub fn answer() -> u32 {{{TWO_SKIPPED}"
            )
        );

        let out = AdvisorTool::Grep.run(
            &fs,
            &Redactor::default(),
            &json!({"pattern": "answer", "ignore_case": true}),
        );
        assert!(out.starts_with("README.md:2: The ANSWER is here."), "{out}");

        // Nothing is skipped in a search of one file, or of a directory
        // that holds nothing off limits.
        for path in ["src/main.rs", "src"] {
            let out = AdvisorTool::Grep.run(
                &fs,
                &Redactor::default(),
                &json!({"pattern": "let answer", "path": path}),
            );
            assert_eq!(out, "src/main.rs:2:     let answer = 42;", "{path}");
        }

        // The token in .env is there, and the search says that it did not
        // look everywhere.
        for pattern in ["zzz", "API_TOKEN"] {
            assert_eq!(
                AdvisorTool::Grep.run(&fs, &Redactor::default(), &json!({"pattern": pattern})),
                format!("no match{TWO_SKIPPED}"),
                "{pattern}"
            );
        }
        for args in [
            json!({"pattern": "answer", "path": ".env"}),
            json!({"pattern": "answer", "path": ".git"}),
            json!({"pattern": "answer", "path": "../outside.txt"}),
            json!({"pattern": "answer", "path": "/"}),
            json!({"pattern": "["}),
        ] {
            let out = AdvisorTool::Grep.run(&fs, &Redactor::default(), &args);
            assert!(out.starts_with("error:"), "{args}: {out}");
            assert!(!out.contains("token"), "{args}: {out}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn walks_do_not_follow_symlinks() {
        use std::os::unix::fs::symlink;
        let (tmp, fs) = project();
        let root = tmp.path().join("work");
        symlink(tmp.path().join("outside.txt"), root.join("src/leak.rs")).unwrap();
        symlink(tmp.path(), root.join("src/up")).unwrap();

        // The links are passed over, and are not among what is reported as
        // skipped for what it may hold.
        let out = AdvisorTool::Grep.run(&fs, &Redactor::default(), &json!({"pattern": "outside"}));
        assert_eq!(out, format!("no match{TWO_SKIPPED}"));
        let out = AdvisorTool::Find.run(
            &fs,
            &Redactor::default(),
            &json!({"pattern": "leak|outside"}),
        );
        assert_eq!(out, format!("no file matches{TWO_SKIPPED}"));
        let out = AdvisorTool::Find.run(
            &fs,
            &Redactor::default(),
            &json!({"pattern": "leak|outside", "path": "src"}),
        );
        assert_eq!(out, "no file matches");
        // Listing shows that the links exist, without following them.
        let out = AdvisorTool::Ls.run(&fs, &Redactor::default(), &json!({"path": "src"}));
        assert_eq!(out, "leak.rs@\nmain.rs\nnested/\nup@");
    }

    #[test]
    fn results_are_capped() {
        let (tmp, fs) = project();
        let root = tmp.path().join("work");
        std::fs::create_dir_all(root.join("many")).unwrap();
        for i in 0..(MAX_LS_ENTRIES + 20) {
            std::fs::write(root.join(format!("many/f{i:04}.txt")), "needle\n").unwrap();
        }
        let out = AdvisorTool::Ls.run(&fs, &Redactor::default(), &json!({"path": "many"}));
        assert_eq!(out.lines().count(), MAX_LS_ENTRIES + 1);
        assert!(
            out.ends_with("[20 more entries]"),
            "{}",
            &out[out.len() - 30..]
        );

        let out = AdvisorTool::Grep.run(
            &fs,
            &Redactor::default(),
            &json!({"pattern": "needle", "path": "many"}),
        );
        assert_eq!(out.lines().count(), MAX_MATCHES + 1);
        assert!(out.ends_with("[more results not shown]"));
        let out = AdvisorTool::Find.run(
            &fs,
            &Redactor::default(),
            &json!({"pattern": "many/", "path": "many"}),
        );
        assert_eq!(out.lines().count(), MAX_MATCHES + 1);
        assert!(out.ends_with("[more results not shown]"));
        // From the top, the same results and both things left to say.
        let out = AdvisorTool::Grep.run(&fs, &Redactor::default(), &json!({"pattern": "needle"}));
        assert_eq!(out.lines().count(), MAX_MATCHES + 2);
        assert!(out.ends_with(&format!("\n[more results not shown]{TWO_SKIPPED}")));
    }

    /// A project file that no name rule refuses and that holds secrets.
    fn project_with_secrets_in_plain_files() -> (TempDir, ConfinedFs, Redactor) {
        let (tmp, confined) = project();
        let root = tmp.path().join("work");
        fs::create_dir_all(root.join("config")).unwrap();
        let mut lines: Vec<String> = (1..=20).map(|n| format!("setting_{n}: {n}")).collect();
        lines.push("private_key: |".to_string());
        lines.push("  -----BEGIN RSA PRIVATE KEY-----".to_string());
        lines.extend((0..6).map(|n| {
            format!("  MIIEowIBAAKCAQEAkeybody{n}+/abcdefghijklmnopqrstuvwxyz0123456789")
        }));
        lines.push("  -----END RSA PRIVATE KEY-----".to_string());
        lines.push("db_password: \"hunter2hunter2\"".to_string());
        lines.push(format!(
            "comment: {}known-provider-key-0123456789",
            "x".repeat(280)
        ));
        fs::write(root.join("config/app.yaml"), lines.join("\n")).unwrap();
        let redactor = Redactor::new(
            [("SOME_API_KEY", "known-provider-key-0123456789")],
            Vec::<(String, String)>::new(),
            &[],
        );
        (tmp, confined, redactor)
    }

    #[test]
    fn no_window_on_a_file_shows_part_of_a_secret() {
        let (_tmp, fs, redactor) = project_with_secrets_in_plain_files();
        // Every window a model could ask for, one line at a time and whole.
        let mut outputs =
            vec![AdvisorTool::Read.run(&fs, &redactor, &json!({"path": "config/app.yaml"}))];
        for offset in 1..=32 {
            for limit in [1, 3, 400] {
                outputs.push(AdvisorTool::Read.run(
                    &fs,
                    &redactor,
                    &json!({"path": "config/app.yaml", "offset": offset, "limit": limit}),
                ));
            }
        }
        for out in &outputs {
            assert!(!out.contains("keybody"), "{out}");
            assert!(!out.contains("hunter2"), "{out}");
            // The known value sits across the point where a long line is cut.
            assert!(!out.contains("known-provider"), "{out}");
        }
        // The file is still readable around what was removed.
        assert!(outputs[0].contains("setting_20: 20"), "{}", outputs[0]);
        assert!(
            outputs[0].contains("db_password: \"[redacted]\""),
            "{}",
            outputs[0]
        );
    }

    #[test]
    fn a_search_matches_what_may_be_seen_and_nothing_else() {
        let (_tmp, fs, redactor) = project_with_secrets_in_plain_files();
        // Probing for the content of a secret finds nothing, in the file
        // given or in the tree.
        for pattern in [
            "hunter2",
            "^\\s+MIIE",
            "keybody[0-9]",
            "known-provider-key-01",
        ] {
            for (args, expected) in [
                (
                    json!({"pattern": pattern}),
                    format!("no match{TWO_SKIPPED}"),
                ),
                (
                    json!({"pattern": pattern, "path": "config/app.yaml"}),
                    "no match".to_string(),
                ),
            ] {
                assert_eq!(
                    AdvisorTool::Grep.run(&fs, &redactor, &args),
                    expected,
                    "{pattern}"
                );
            }
        }
        // Looking for where a password is set finds the line, without it.
        let out = AdvisorTool::Grep.run(
            &fs,
            &redactor,
            &json!({"pattern": "password", "path": "config"}),
        );
        assert_eq!(out, "config/app.yaml:30: db_password: \"[redacted]\"");
        // File names and errors go through the same redaction.
        let out = AdvisorTool::Read.run(
            &fs,
            &redactor,
            &json!({"path": "known-provider-key-0123456789.txt"}),
        );
        assert_eq!(out, "error: [redacted].txt: no such file or directory");
    }

    /// A known secret that is also the name of a directory and of a file.
    fn project_with_a_secret_in_its_paths() -> (TempDir, ConfinedFs, Redactor) {
        let (tmp, confined) = project();
        let deploy = tmp.path().join("work/deploy");
        fs::create_dir_all(deploy.join(KNOWN)).unwrap();
        fs::write(deploy.join(KNOWN).join("values.txt"), "three replicas\n").unwrap();
        fs::write(deploy.join(format!("{KNOWN}.txt")), "one replica\n").unwrap();
        fs::write(deploy.join("aaa.txt"), "two replicas\n").unwrap();
        fs::write(deploy.join("notes.txt"), "no replica\n").unwrap();
        let redactor = Redactor::new(
            [("SOME_API_KEY", KNOWN)],
            Vec::<(String, String)>::new(),
            &[],
        );
        (tmp, confined, redactor)
    }

    const KNOWN: &str = "known-provider-key-0123456789";

    #[test]
    fn find_matches_a_path_as_it_is_shown_and_cannot_probe_what_is_hidden() {
        let (_tmp, fs, redactor) = project_with_a_secret_in_its_paths();
        let out = AdvisorTool::Find.run(
            &fs,
            &redactor,
            &json!({"pattern": "values", "path": "deploy"}),
        );
        assert_eq!(out, "deploy/[redacted]/values.txt");

        // Whether a path comes back says nothing about the hidden part,
        // however the pattern is narrowed down.
        for pattern in [
            KNOWN,
            "known-provider",
            "key-0123",
            "^deploy/k",
            "^deploy/[a-m][a-z]+-",
            "^deploy/[^/]{29}/",
            "0123456789\\.txt$",
        ] {
            let out = AdvisorTool::Find.run(
                &fs,
                &redactor,
                &json!({"pattern": pattern, "path": "deploy"}),
            );
            assert_eq!(out, "no file matches", "{pattern}");
        }
        // What is shown is what there is to match.
        let out = AdvisorTool::Find.run(
            &fs,
            &redactor,
            &json!({"pattern": r"^deploy/\[redacted\]", "path": "deploy"}),
        );
        let mut found: Vec<&str> = out.lines().collect();
        found.sort();
        assert_eq!(
            found,
            ["deploy/[redacted].txt", "deploy/[redacted]/values.txt"]
        );
    }

    #[test]
    fn every_tool_redacts_the_paths_it_shows_by_itself() {
        let (_tmp, fs, redactor) = project_with_a_secret_in_its_paths();
        // The functions behind the tools, with nothing redacting after them.
        let listed = ls(&fs, &redactor, &json!({"path": "deploy"})).unwrap();
        // In the order of what is shown: where a name comes in the list
        // does not depend on what was removed from it. A name that starts
        // with a bracket once redacted is written as a path, so that no line
        // of a listing can pass for a note of the tool.
        assert_eq!(
            listed,
            "./[redacted].txt\n./[redacted]/\naaa.txt\nnotes.txt"
        );

        let found = find(&fs, &redactor, &json!({"pattern": ".", "path": "deploy"})).unwrap();
        assert_eq!(found.lines().count(), 4, "{found}");
        assert!(
            found.contains("deploy/[redacted]/values.txt")
                && found.contains("deploy/[redacted].txt"),
            "{found}"
        );

        let searched = grep(
            &fs,
            &redactor,
            &json!({"pattern": "replica", "path": "deploy"}),
        )
        .unwrap();
        assert_eq!(searched.lines().count(), 4, "{searched}");
        for line in [
            "deploy/[redacted]/values.txt:1: three replicas",
            "deploy/[redacted].txt:1: one replica",
            "deploy/notes.txt:1: no replica",
        ] {
            assert!(searched.contains(line), "{line}: {searched}");
        }
        // A search of one file names it the same way.
        let searched = grep(
            &fs,
            &redactor,
            &json!({"pattern": "replica", "path": format!("deploy/{KNOWN}/values.txt")}),
        )
        .unwrap();
        assert_eq!(searched, "deploy/[redacted]/values.txt:1: three replicas");

        let beyond = read(
            &fs,
            &redactor,
            &json!({"path": format!("deploy/{KNOWN}.txt"), "offset": 5}),
        )
        .unwrap();
        assert_eq!(
            beyond,
            "deploy/[redacted].txt: no lines at offset 5 (1 lines)"
        );

        for out in [listed, found, searched, beyond] {
            assert!(!out.contains("known-provider"), "{out}");
        }
    }

    #[test]
    fn an_error_is_a_path_and_a_reason_redacted_apart() {
        let (tmp, fs, redactor) = project_with_a_secret_in_its_paths();
        let root = tmp.path().join("work");
        fs::write(root.join("src/token.rs"), [0u8, 159, 146, 150]).unwrap();
        for (tool, args, expected) in [
            // The name of the file is not the name of a field, and what is
            // wrong with it is not a value.
            (
                AdvisorTool::Read,
                json!({"path": "src/token.rs"}),
                "error: src/token.rs: not a text file".to_string(),
            ),
            (
                AdvisorTool::Ls,
                json!({"path": "src/token.rs"}),
                "error: src/token.rs: not a directory".to_string(),
            ),
            (
                AdvisorTool::Grep,
                json!({"pattern": "x", "path": "src/password"}),
                "error: src/password: may hold credentials or internal state, access refused"
                    .to_string(),
            ),
            // A path is redacted whether the model wrote it or the tool
            // found it.
            (
                AdvisorTool::Read,
                json!({"path": format!("deploy/{KNOWN}/gone.txt")}),
                "error: deploy/[redacted]/gone.txt: no such file or directory".to_string(),
            ),
            (
                AdvisorTool::Find,
                json!({"pattern": ".", "path": format!("deploy/{KNOWN}.txt")}),
                "error: deploy/[redacted].txt: not a directory".to_string(),
            ),
            // So is a failure that is about no path.
            (
                AdvisorTool::Find,
                json!({"path": KNOWN}),
                "error: missing string argument \"pattern\"".to_string(),
            ),
        ] {
            assert_eq!(tool.run(&fs, &redactor, &args), expected, "{args}");
        }
        let out = AdvisorTool::Grep.run(&fs, &redactor, &json!({"pattern": format!("({KNOWN}")}));
        assert!(
            out.starts_with("error: invalid regular expression"),
            "{out}"
        );
        assert!(!out.contains("known-provider"), "{out}");
    }

    #[test]
    fn grep_keeps_the_line_number_of_a_file_named_after_a_secret() {
        let (tmp, fs) = project();
        let root = tmp.path().join("work");
        fs::write(
            root.join("src/token.rs"),
            "pub struct Token;\n\nfn next_token() {}\n",
        )
        .unwrap();
        fs::write(
            root.join("src/password_reset.rs"),
            "fn send_reset_mail() {}\n",
        )
        .unwrap();
        // The path and the line are redacted apart: together, the name of
        // the file would be read as the name of a field, and the line number
        // as its value.
        let out = AdvisorTool::Grep.run(
            &fs,
            &Redactor::default(),
            &json!({"pattern": "fn (next|send)", "path": "src"}),
        );
        assert_eq!(
            out,
            "src/password_reset.rs:1: fn send_reset_mail() {}\nsrc/token.rs:3: fn next_token() {}"
        );
    }

    #[test]
    fn a_search_below_a_directory_named_after_secrets_covers_what_is_not_data() {
        let (tmp, fs) = project();
        let store = tmp.path().join("work/crates/secret-store");
        fs::create_dir_all(store.join("src")).unwrap();
        fs::create_dir_all(store.join("fixtures")).unwrap();
        fs::write(store.join("src/lib.rs"), "pub fn open() {}\n").unwrap();
        fs::write(store.join("schema.sql"), "create table entries (id int);\n").unwrap();
        fs::write(store.join("build.sh"), "cargo build # open\n").unwrap();
        fs::write(store.join("fixtures/prod.yaml"), "entries: open\n").unwrap();

        let out = AdvisorTool::Grep.run(
            &fs,
            &Redactor::default(),
            &json!({"pattern": "open|entries", "path": "crates"}),
        );
        assert_eq!(
            out,
            "crates/secret-store/build.sh:1: cargo build # open\n\
             crates/secret-store/schema.sql:1: create table entries (id int);\n\
             crates/secret-store/src/lib.rs:1: pub fn open() {}\n\
             [1 entry was skipped because it may hold credentials or internal state]"
        );
        // The data file is there and is not shown: the answer says that
        // something was left out, not that there is nothing.
        let out = AdvisorTool::Find.run(
            &fs,
            &Redactor::default(),
            &json!({"pattern": "prod", "path": "crates"}),
        );
        assert_eq!(
            out,
            "no file matches\n[1 entry was skipped because it may hold credentials or internal state]"
        );
        let out = AdvisorTool::Read.run(
            &fs,
            &Redactor::default(),
            &json!({"path": "crates/secret-store/fixtures/prod.yaml"}),
        );
        assert!(out.contains("access refused"), "{out}");
    }

    #[test]
    fn a_search_that_was_cut_short_says_so() {
        let (tmp, fs) = project();
        let root = tmp.path().join("work").canonicalize().unwrap();
        // The top of the project holds five entries: three is not enough to
        // read them, and nothing is visited from a directory read in part.
        let mut visited = 0;
        let walked = walk_within(3, MAX_WALK_TIME, &fs, &root, |_| {
            visited += 1;
            true
        });
        assert_eq!(walked.end, Walk::CutShort);
        assert_eq!(visited, 0);
        assert!(walk_note(walked).contains("stopped before it had looked everywhere"));

        // A walk that covered the tree, or was stopped by its visitor, says
        // something else.
        let complete = walk_files(&fs, &root, |_| true);
        assert_eq!(complete.end, Walk::Complete);
        assert_eq!(complete.refused, 2);
        assert_eq!(walk_note(complete), TWO_SKIPPED);
        let stopped = walk_files(&fs, &root.join("src"), |_| false);
        assert_eq!(
            stopped,
            Walked {
                end: Walk::Stopped,
                refused: 0,
                unreadable: 0
            }
        );
        assert_eq!(walk_note(stopped), "\n[more results not shown]");
    }

    #[test]
    fn walk_limits_count_what_is_left_out_and_bound_one_large_directory() {
        let (tmp, fs) = project();
        let root = tmp.path().join("work").canonicalize().unwrap();
        // A directory of files that are all left out for their names, and a
        // tree of directories that hold nothing but build output.
        fs::create_dir_all(root.join("corpus")).unwrap();
        fs::create_dir_all(root.join("output")).unwrap();
        for i in 0..40 {
            fs::write(root.join(format!("corpus/sample-{i}.pem")), "x").unwrap();
            fs::create_dir_all(root.join(format!("output/{i}/target"))).unwrap();
        }
        fs::write(root.join("corpus/zz-last.txt"), "x").unwrap();

        // With room for every entry, the walk goes through all of them.
        let mut visited = Vec::new();
        let walked = walk_within(100, MAX_WALK_TIME, &fs, &root.join("corpus"), |path| {
            visited.push(fs.display(path));
            true
        });
        assert_eq!(visited, ["corpus/zz-last.txt"]);
        assert_eq!(
            walked,
            Walked {
                end: Walk::Complete,
                refused: 40,
                unreadable: 0
            }
        );

        // Entries that are left out count like the others: a walk does not
        // go through any number of them for free.
        for (dir, max_entries) in [("corpus", 10), ("corpus", 40), ("output", 79)] {
            let mut visited = 0;
            let walked = walk_within(max_entries, MAX_WALK_TIME, &fs, &root.join(dir), |_| {
                visited += 1;
                true
            });
            assert_eq!(walked.end, Walk::CutShort, "{dir} {max_entries}");
            assert!(walked.refused <= max_entries, "{dir} {max_entries}");
            // One directory is not read past the limit, so that it is never
            // held and sorted whole: the file in it is not reached.
            assert_eq!(visited, 0, "{dir} {max_entries}");
        }
        let walked = walk_within(80, MAX_WALK_TIME, &fs, &root.join("output"), |_| true);
        assert_eq!(walked.end, Walk::Complete);

        // So does the time they take: it is looked at for each of them.
        let walked = walk_within(
            MAX_WALK_ENTRIES,
            Duration::ZERO,
            &fs,
            &root.join("corpus"),
            |_| true,
        );
        assert_eq!(
            walked,
            Walked {
                end: Walk::CutShort,
                refused: 0,
                unreadable: 0
            }
        );
    }
}
