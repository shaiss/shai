// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: OVH SAS

//! Redaction of secrets from text sent to the advisor.
//!
//! The advisor usually runs on a different provider than the session. What it
//! is shown comes from the session's conversation and from files in the
//! working directory, and either can contain credentials: a command that
//! printed its environment, a config file, a pasted token. Everything on its
//! way to the advisor goes through a [`Redactor`] first, and it goes through
//! it before it is cut to size, so that a limit of the advisor's does not
//! leave half a secret behind. Text that was cut before it got here, a file
//! read up to a size limit, goes through [`Redactor::redact_truncated`].
//!
//! Three layers:
//!
//! * **Known values.** What the process holds is replaced wherever it appears
//!   verbatim: the settings of the configured providers, and every value of
//!   the process environment that is not plainly harmless. The environment is
//!   treated as secret by default, not by the name of its variables; the
//!   exceptions are listed in [`environment_value_is_secret`].
//! * **Shapes.** Text that is a credential by its form (well-known token
//!   prefixes, private key blocks, bearer and basic values, the user part of
//!   a URL, the value of a `--password` flag) is replaced without having to
//!   be known.
//! * **Assignments.** In `name = value`, `name: value` and their relatives,
//!   the value goes when the name says it is a credential and the value is a
//!   literal. The value of an `Authorization` or `Cookie` header goes whole.
//!
//! The last two are heuristics: they catch the common cases, not every secret
//! a file can hold, and they err on the side of removing too much. A value
//! too short to be a known value (see [`MIN_SECRET_LEN`]) is only caught where
//! one of them recognizes it.

use regex::{Captures, Regex};
use std::path::Path;
use std::sync::LazyLock;

/// What a redacted secret is replaced with.
pub(crate) const REDACTED: &str = "[redacted]";

/// Shortest value replaced wherever it appears. A shorter one cannot be told
/// from ordinary text: replacing every `test` or `1234` would wreck what the
/// advisor reads.
const MIN_SECRET_LEN: usize = 8;

/// Shortest part of a URL setting (user, password, query value) that is
/// replaced wherever it appears.
const MIN_URL_SECRET_LEN: usize = 6;

/// Shortest beginning of a known value that is removed from the end of text
/// that was cut to size before it was redacted.
const MIN_CUT_SECRET_LEN: usize = 4;

/// Environment variables whose value is never a secret, by what they are for.
/// Hiding these would hide the paths and names that make a review readable.
/// The last two are set by shai itself, to the session's own model.
const PLAIN_VARIABLES: &[&str] = &[
    "HOME",
    "PWD",
    "OLDPWD",
    "PATH",
    "USER",
    "LOGNAME",
    "USERNAME",
    "HOSTNAME",
    "SHELL",
    "LANG",
    "LANGUAGE",
    "TERM",
    "TERM_PROGRAM",
    "COLORTERM",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "TMPDIR",
    "TZ",
    "DISPLAY",
    "SHLVL",
    "_",
    "SHAI_MODEL",
    "SHAI_PROVIDER",
];

/// Whether an upper-case name, as variables and settings are written, says
/// that its value is a credential.
fn is_secret_variable(name: &str) -> bool {
    const ANYWHERE: &[&str] = &[
        "secret",
        "token",
        "passw",
        "passphrase",
        "credential",
        "apikey",
        "accesskey",
        "privatekey",
        "webhook",
        "cookie",
    ];
    const WORDS: &[&str] = &[
        "key",
        "keys",
        "pass",
        "pwd",
        "pat",
        "auth",
        "cred",
        "creds",
        "dsn",
        "private",
        "signature",
        "salt",
    ];
    let lower = name.to_ascii_lowercase();
    ANYWHERE.iter().any(|word| lower.contains(word))
        || lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|part| WORDS.contains(&part))
}

/// Whether the name of a field in code or in a config file says that its
/// value is a credential. A list of its own, not a part of the one above:
/// `key` and `auth` alone name too many ordinary things in source code.
fn is_secret_field(name: &str) -> bool {
    const ANYWHERE: &[&str] = &[
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "credential",
        "apikey",
        "api_key",
        "api-key",
        "accesskey",
        "access_key",
        "privatekey",
        "private_key",
        "authkey",
        "auth_key",
        "signingkey",
        "signing_key",
        "encryptionkey",
        "encryption_key",
    ];
    // The key of something that holds credentials: `AccountKey`,
    // `client-key-data`, `Ocp-Apim-Subscription-Key`, `master_key`.
    const KEY_OWNERS: &[&str] = &[
        "account",
        "auth",
        "master",
        "subscription",
        "client",
        "signing",
        "encryption",
        "private",
        "secret",
        "access",
        "app",
        "consumer",
        "shared",
        "storage",
        "service",
        "hmac",
        "license",
        "deploy",
        "ssh",
        "webhook",
        "sas",
    ];
    let lower = name.to_ascii_lowercase();
    let compact: String = lower.chars().filter(char::is_ascii_alphanumeric).collect();
    let owner = ["keydata", "keys", "key"]
        .iter()
        .find_map(|suffix| compact.strip_suffix(suffix));
    ANYWHERE.iter().any(|word| lower.contains(word))
        || lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|part| part == "pass" || part == "pwd")
        || owner.is_some_and(|owner| KEY_OWNERS.iter().any(|word| owner.ends_with(word)))
}

/// A value that is plainly not a credential: one unremarkable word, a number,
/// or paths that exist on this machine.
fn is_plain_value(value: &str) -> bool {
    let plain_word = value.len() <= 20 && value.chars().all(|c| c.is_ascii_alphabetic());
    let paths = value
        .split(':')
        .all(|path| path.starts_with('/') && Path::new(path).exists());
    plain_word || value.parse::<f64>().is_ok() || paths
}

/// Whether a value of the process environment is kept out of what the advisor
/// is sent.
///
/// Every value is, unless it is plainly harmless: shorter than
/// [`MIN_SECRET_LEN`], the value of one of [`PLAIN_VARIABLES`], or, under a
/// name that does not look like a credential's, the value of a locale
/// variable, a [plain value](is_plain_value) or a part of one of the `public`
/// texts.
///
/// `public` is what the advisor is shown anyway and has to be able to read:
/// the path of the working directory. A project's name is often in the
/// environment too, and hiding it would hide every path of the project.
fn environment_value_is_secret(name: &str, value: &str, public: &[&str]) -> bool {
    if value.len() < MIN_SECRET_LEN || PLAIN_VARIABLES.contains(&name) {
        return false;
    }
    is_secret_variable(name)
        || !(name.starts_with("LC_")
            || is_plain_value(value)
            || public.iter().any(|text| text.contains(value)))
}

/// Whether a value can be replaced wherever it appears. One without a letter
/// or a digit (blanks, a row of dashes) is ordinary text: replacing it would
/// take the text apart, and hide nothing.
fn can_be_known(value: &str) -> bool {
    value.chars().any(char::is_alphanumeric)
}

/// `text` with its JSON escapes `\uXXXX` (either case, surrogate pairs
/// joined) and `\/` decoded, and for each byte of the decoded text, the
/// offset in `text` it comes from, with one more entry for its end.
fn decode_json_escapes(text: &str) -> (String, Vec<usize>) {
    let bytes = text.as_bytes();
    let unit_at = |at: usize| -> Option<u16> {
        (bytes.get(at) == Some(&b'\\') && bytes.get(at + 1) == Some(&b'u'))
            .then(|| text.get(at + 2..at + 6))
            .flatten()
            .and_then(|hex| u16::from_str_radix(hex, 16).ok())
    };
    let mut decoded = String::with_capacity(text.len());
    let mut origin = Vec::with_capacity(text.len() + 1);
    let mut at = 0;
    while at < text.len() {
        let (c, len) = match unit_at(at) {
            Some(high @ 0xD800..=0xDBFF) => match unit_at(at + 6) {
                Some(low @ 0xDC00..=0xDFFF) => (
                    char::decode_utf16([high, low]).next().and_then(Result::ok),
                    12,
                ),
                _ => (None, 6),
            },
            Some(unit) => (char::from_u32(u32::from(unit)), 6),
            None if bytes[at] == b'\\' && bytes.get(at + 1) == Some(&b'/') => (Some('/'), 2),
            None => {
                let c = text[at..].chars().next().unwrap_or('\u{fffd}');
                (Some(c), c.len_utf8())
            }
        };
        let c = c.unwrap_or('\u{fffd}');
        for _ in 0..c.len_utf8() {
            origin.push(at);
        }
        decoded.push(c);
        at += len;
    }
    origin.push(text.len());
    (decoded, origin)
}

/// `value` as programs write it into text: escaped for JSON (by serde, with
/// `\/` as PHP writes it, with `\uXXXX` for what is not ASCII as Python
/// writes it, with `&`, `<` and `>` escaped as Go writes them), escaped for
/// HTML, and percent-encoded for a URL or a form.
fn encoded_forms(value: &str) -> Vec<String> {
    let mut forms = Vec::new();
    if let Ok(json) = serde_json::to_string(value) {
        let json = json[1..json.len() - 1].to_string();
        let ascii: String = json
            .chars()
            .map(|c| {
                if c.is_ascii() {
                    c.to_string()
                } else {
                    c.encode_utf16(&mut [0; 2])
                        .iter()
                        .map(|unit| format!("\\u{unit:04x}"))
                        .collect()
                }
            })
            .collect();
        let upper: String = json
            .chars()
            .map(|c| {
                if c.is_ascii() {
                    c.to_string()
                } else {
                    c.encode_utf16(&mut [0; 2])
                        .iter()
                        .map(|unit| format!("\\u{unit:04X}"))
                        .collect()
                }
            })
            .collect();
        forms.push(upper);
        forms.push(ascii.replace('/', "\\/"));
        forms.push(
            json.replace('&', "\\u0026")
                .replace('<', "\\u003c")
                .replace('>', "\\u003e"),
        );
        forms.push(json.replace('/', "\\/"));
        forms.push(ascii);
        forms.push(json);
    }
    forms.push(
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;"),
    );
    let percent = |upper: bool| -> String {
        value
            .bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                    (byte as char).to_string()
                } else if upper {
                    format!("%{byte:02X}")
                } else {
                    format!("%{byte:02x}")
                }
            })
            .collect()
    };
    forms.push(percent(true).replace("%20", "+"));
    forms.push(percent(true));
    forms.push(percent(false));
    forms.retain(|form| form != value);
    forms
}

/// The parts of a URL setting that are credentials: the user, the password
/// and the values of its query, except those that are plainly options of the
/// endpoint. The host and the path stay readable.
fn url_secrets(value: &str) -> Vec<String> {
    let Ok(url) = reqwest::Url::parse(value) else {
        // Not a URL after all: treat it like any other setting.
        return if value.len() >= MIN_SECRET_LEN {
            vec![value.to_string()]
        } else {
            Vec::new()
        };
    };
    // The user and the password come back as they are written in the URL;
    // what they decode to is the same secret.
    let mut parts = vec![url.username().to_string()];
    parts.extend(url.password().map(str::to_string));
    let decoded: Vec<String> = parts.iter().map(|part| percent_decoded(part)).collect();
    parts.extend(decoded);
    // The values of the query, as they are written and as they decode. An
    // option such as `api-version=2024-02-01` or `format=json` is not a
    // secret, and replacing it everywhere would take ordinary words out of
    // what the advisor reads.
    for pair in url.query().into_iter().flat_map(|query| query.split('&')) {
        let (name, written) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded = percent_decoded(&written.replace('+', " "));
        if is_secret_variable(name) || !is_plain_option(&decoded) {
            parts.push(written.to_string());
            parts.push(decoded);
        }
    }
    // The encoded form is what appears when the URL is printed.
    if let Some((userinfo, _)) = value
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .and_then(|authority| authority.rsplit_once('@'))
    {
        parts.extend(userinfo.split(':').map(str::to_string));
    }
    parts.retain(|part| part.len() >= MIN_URL_SECRET_LEN);
    parts
}

/// A query value that is an option of an endpoint and not a credential: a
/// lower-case word, a number, a date or a version.
fn is_plain_option(value: &str) -> bool {
    let word = value.len() <= 24
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '-' || c == '_');
    let number = value
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | ':' | '_'));
    word || number || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false")
}

/// `text` with every `%XX` replaced by the byte it stands for.
fn percent_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let byte = (bytes[at] == b'%')
            .then(|| text.get(at + 1..at + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match byte {
            Some(byte) => {
                out.push(byte);
                at += 3;
            }
            None => {
                out.push(bytes[at]);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The largest index of `text`, at most `max`, that does not split a
/// character.
fn char_floor(text: &str, max: usize) -> usize {
    let mut index = max.min(text.len());
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// The marker that opens a private key block: PEM, or armored PGP.
static KEY_BEGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP (?:PRIVATE|SECRET) KEY BLOCK)-----")
        .unwrap()
});

/// The marker that closes a private key block.
static KEY_END: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----END (?:[A-Z0-9 ]*PRIVATE KEY|PGP (?:PRIVATE|SECRET) KEY BLOCK)-----").unwrap()
});

/// The private lines of a PuTTY key file, after the line that counts them.
static PUTTY_PRIVATE: LazyLock<Regex> = LazyLock::new(|| {
    // The count line and each private line may carry what a listing puts in
    // front of a line: a number and a hash, a diff mark, `file:12:` as
    // `grep -n` writes it.
    Regex::new(
        r"(?m)^([^\n]{0,80}?Private-Lines: *\d+)[ \t]*\r?\n((?:(?:[ \t]*\d+(?::[ \t]*[0-9a-f]{8}[ \t]|\t|[:|]))?(?:[^\n:]{0,64}:\d+[:-])?[-+> ]?[ \t]*[A-Za-z0-9+/=]+[ \t]*(?:\r?\n|$))+)",
    )
    .unwrap()
});

/// How far after its opening marker the end of a private key block is looked
/// for. A key of 8192 bits takes less than half of this, written one line to
/// a string literal.
const KEY_SPAN: usize = 16 * 1024;

/// `text` with every private key block replaced.
///
/// A block that has its end marker goes from one marker to the other,
/// whatever stands in between: the key may be quoted, indented, written as
/// string literals joined together, or prefixed line by line as in a diff. A
/// block with no end marker in reach goes as far as the text looks like the
/// body of a key. The line breaks of a block are kept, so that the lines
/// after it keep their numbers.
fn redact_private_keys(text: &str) -> String {
    let ends: Vec<(usize, usize)> = KEY_END
        .find_iter(text)
        .map(|end| (end.start(), end.end()))
        .collect();
    let mut next_end = 0;
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    for begin in KEY_BEGIN.find_iter(text) {
        // A marker inside a block that is already gone.
        if begin.start() < copied {
            continue;
        }
        while ends.get(next_end).is_some_and(|end| end.0 < begin.end()) {
            next_end += 1;
        }
        let stop = match ends.get(next_end) {
            Some(&(start, end)) if start - begin.end() <= KEY_SPAN => end,
            _ => begin.end() + key_body_len(&text[begin.end()..]),
        };
        out.push_str(&text[copied..begin.start()]);
        out.push_str(REDACTED);
        let lines = text[begin.start()..stop].matches('\n').count();
        out.extend(std::iter::repeat_n('\n', lines));
        copied = stop;
    }
    out.push_str(&text[copied..]);
    out
}

/// How many bytes at the start of `rest`, the text after the opening marker
/// of a private key, are the body of that key when no end marker is in
/// reach.
///
/// The body is judged line by line, the line breaks as they are or written
/// `\n`. A line belongs to the key while it holds a run of base64 that looks
/// like key material, whatever numbering, quoting or diff mark stands around
/// it, and the body ends with that run. Ordinary words after a marker are
/// not a body.
fn key_body_len(rest: &str) -> usize {
    let bytes = rest.as_bytes();
    let base64 = |byte: &u8| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=');
    // Where the last run of base64 on a line ends, when that run is long and
    // mixed enough to be key material and not a word or a path.
    let key_run_end = |line: &[u8]| {
        let mut found = None;
        let mut at = 0;
        while at < line.len() {
            if !base64(&line[at]) {
                at += 1;
                continue;
            }
            let start = at;
            while at < line.len() && base64(&line[at]) {
                at += 1;
            }
            let run = &line[start..at];
            let mixed = run.iter().any(u8::is_ascii_uppercase)
                && run.iter().any(u8::is_ascii_lowercase)
                && run.iter().any(|byte| !byte.is_ascii_alphabetic());
            if run.len() >= 16 && mixed {
                found = Some(at);
            }
        }
        found
    };
    // A short last line: a run of base64 with nothing but marks around it.
    // Right after the marker it also has to hold more than letters.
    let short_run_end = |line: &[u8], letters_alone: bool| {
        let lead = line
            .iter()
            .take_while(|byte| {
                byte.is_ascii_whitespace() || matches!(byte, b'+' | b'-' | b'>' | b'"' | b'\'')
            })
            .count();
        // A `+` is base64 too: what was taken as a mark may start the run.
        let lead = if line[lead..].first().is_some_and(base64) {
            lead
        } else {
            line.iter()
                .take_while(|byte| byte.is_ascii_whitespace())
                .count()
        };
        let run = line[lead..].iter().take_while(|byte| base64(byte)).count();
        let after = &line[lead + run..];
        let marked = line[lead..lead + run]
            .iter()
            .any(|byte| !byte.is_ascii_alphabetic());
        (run > 0 && (letters_alone || marked) && !after.iter().any(u8::is_ascii_alphanumeric))
            .then_some(lead + run)
    };

    let mut end = 0;
    let mut at = 0;
    let mut in_body = false;
    // Whether the line before was a line of the key, or the marker itself.
    let mut below_key = true;
    // Whether something that joins string literals stood in between.
    let mut glued = false;
    let mut first = true;
    while at < bytes.len() {
        // One line, up to a line break as it is or written `\n`. A line
        // of a key is short: of a longer one only the beginning is looked
        // at, and it is the last.
        let limit = bytes.len().min(at + MAX_KEY_LINE);
        let mut stop = at;
        let mut next = None;
        while stop < limit {
            if bytes[stop] == b'\n' {
                next = Some(stop + 1);
                break;
            }
            if bytes[stop] == b'\\' && matches!(bytes.get(stop + 1), Some(b'n' | b'r')) {
                next = Some(stop + 2);
                break;
            }
            stop += 1;
        }
        // A key written without any line break is one run of base64,
        // however long.
        if next.is_none() && bytes[at..stop].iter().all(base64) {
            while bytes.get(stop).is_some_and(base64) {
                stop += 1;
            }
        }
        let next = next.unwrap_or(bytes.len());
        let line = &bytes[at..stop];
        let blank = line.iter().all(u8::is_ascii_whitespace);
        // What joins two string literals, or closes one: no letter, no digit.
        let glue = !blank && line.len() <= 8 && !line.iter().any(u8::is_ascii_alphanumeric);
        let header = !in_body
            && [
                &b"Proc-Type:"[..],
                &b"DEK-Info:"[..],
                &b"Version:"[..],
                &b"Comment:"[..],
                &b"Charset:"[..],
            ]
            .iter()
            .any(|name| line.windows(name.len()).any(|part| part == *name));
        if header {
            end = stop;
        } else if let Some(run_end) = key_run_end(line) {
            end = at + run_end;
            in_body = true;
            below_key = true;
            glued = false;
        } else if blank {
            // The rest of the marker's own line is not a blank line.
            below_key = below_key && first;
        } else if glue {
            glued = true;
        } else {
            // Letters alone are the last line of a key only right below
            // another line of it.
            let letters_alone = in_body && !glued;
            if let Some(run_end) = short_run_end(line, letters_alone).filter(|_| below_key) {
                end = at + run_end;
            }
            break;
        }
        first = false;
        at = next;
    }
    // A line that was only looked at in part may have been cut inside a
    // character.
    char_floor(rest, end)
}

/// How much of one line is looked at to tell whether it is a line of a key.
const MAX_KEY_LINE: usize = 1024;

/// Text that is a credential by its shape alone, with what replaces it.
static SECRET_SHAPES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        // Bearer and basic authorization values, on the line of the word.
        (
            r"(?i)\b(?:bearer|basic)[ \t]+[A-Za-z0-9._~+/=-]{16,}",
            REDACTED,
        ),
        // Provider API keys (OpenAI, Anthropic, OpenRouter and lookalikes).
        (r"\bsk-[A-Za-z0-9_-]{16,}", REDACTED),
        // Payment provider keys.
        (r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}", REDACTED),
        // GitHub and GitLab tokens.
        (
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,})",
            REDACTED,
        ),
        // AWS access key ids.
        (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", REDACTED),
        // Slack tokens.
        (r"\bxox[abprs]-[A-Za-z0-9-]{10,}", REDACTED),
        // Google API keys.
        (r"\bAIza[0-9A-Za-z_-]{30,}", REDACTED),
        // JSON Web Tokens.
        (
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
            REDACTED,
        ),
        // Whatever stands before the last `@` of the host part of a URL: a
        // user and a password, or a token alone. The scheme and the host are
        // kept. See [`URL_PASSWORD`] for a password with other signs in it.
        (
            r#"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/?#"'<>]*@"#,
            "${1}[redacted]@",
        ),
    ]
    .into_iter()
    .map(|(pattern, replacement)| (Regex::new(pattern).unwrap(), replacement))
    .collect()
});

/// `scheme://user:password@`, where the password may hold an `@`, a `?` or a
/// `#` of its own: it ends at the last `@` before the path.
static URL_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?P<scheme>[a-z][a-z0-9+.-]*://)[^\s/?#"'<>:@]*:(?P<password>[^\s/"'<>]*)@"#,
    )
    .unwrap()
});

/// `text` with the user and the password of URLs replaced, where the
/// password holds signs that the plain rule stops at.
fn redact_url_passwords(text: &str) -> String {
    URL_PASSWORD
        .replace_all(text, |found: &Captures<'_>| {
            // `host:8080?mail=me@example.com` has a port there, not a
            // password.
            let password = &found["password"];
            let digits = password.chars().take_while(|c| c.is_ascii_digit()).count();
            let port = digits > 0 && password[digits..].starts_with(['?', '#']);
            if port {
                found[0].to_string()
            } else {
                format!("{}{REDACTED}@", &found["scheme"])
            }
        })
        .into_owned()
}

/// Credentials handed over by a call or written as markup, rather than
/// assigned, each with the name that says what the value is, where there is
/// one.
static HANDED_OVER: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    // A quoted value, which ends at the quote it opened with only, past any
    // escaped quote: one alternative per kind of quote.
    const VALUE: &str = r#"(?:"(?P<dq>(?:\\.|[^"\\\n])*)"|'(?P<sq>(?:\\.|[^'\\\n])*)')"#;
    [
        // A call given a name and a value: `define('DB_PASSWORD', 'x')`,
        // `os.Setenv("API_TOKEN", "x")`, `headers.put("X-Api-Key", "x")`.
        format!(
            r#"\b[A-Za-z_][\w.:]{{0,60}}\s*\(\s*["'](?P<name>[A-Za-z_][\w.-]{{0,80}})["']\s*,\s*{VALUE}"#
        ),
        // A setter named after what it sets: `ds.setPassword("x")`.
        format!(r#"\bset(?P<name>[A-Z][A-Za-z]{{0,40}})\s*\(\s*{VALUE}"#),
        // An element of markup: `<password>x</password>`.
        r#"<(?P<name>[A-Za-z_][\w.:-]{0,60})>(?P<value>[^<\n]{1,512})</"#.to_string(),
        // An element named by an attribute:
        // `<property name="hibernate.connection.password">x</property>`.
        r#"<(?:property|entry|add|param|setting|parameter)\b[^>\n]{0,200}?\b(?:name|key)\s*=\s*["'](?P<name>[^"'\n]{1,80})["'][^>\n]{0,200}?>(?P<value>[^<\n]{1,512})</"#.to_string(),
        // A name and its value as attributes, in either order:
        // `<add key="Password" value="x"/>`, `<property value="x" name="password"/>`.
        format!(
            r#"\b(?:key|name)\s*=\s*["'](?P<name>[^"'\n]{{1,80}})["'][^>\n]{{0,200}}?\bvalue\s*=\s*{VALUE}"#
        ),
        format!(
            r#"\bvalue\s*=\s*{VALUE}\s+(?:key|name)\s*=\s*["'](?P<name>[^"'\n]{{1,80}})["']"#
        ),
        // SQL: `IDENTIFIED BY 'x'`, `IDENTIFIED WITH plugin BY 'x'`,
        // `WITH PASSWORD 'x'`, a quote written twice inside the value.
        r#"(?i)\b(?:identified\s+(?:with\s+\w+\s+)?by|password)\s+'(?P<sq>(?:''|\\.|[^'\\\n])*)'"#.to_string(),
    ]
    .into_iter()
    .map(|pattern| Regex::new(&pattern).unwrap())
    .collect()
});

/// `text` with the credentials of [`HANDED_OVER`] replaced: the value goes
/// when the name says it is a credential, or when the form says so alone.
fn redact_handed_over(text: &str) -> String {
    let mut out = text.to_string();
    for rule in HANDED_OVER.iter() {
        if !rule.is_match(&out) {
            continue;
        }
        out = rule
            .replace_all(&out, |found: &Captures<'_>| {
                let whole = found.get(0).expect("the whole match");
                let Some(value) = found
                    .name("value")
                    .or_else(|| found.name("dq"))
                    .or_else(|| found.name("sq"))
                else {
                    return whole.as_str().to_string();
                };
                let named = found
                    .name("name")
                    .is_none_or(|name| NameKind::of(name.as_str(), Operator::Colon).is_some());
                let shown = value.as_str().trim();
                // A placeholder that a tool fills in is not the value.
                let placeholder = ["${", "#{", "$(", "%(", "{{"]
                    .iter()
                    .any(|mark| shown.starts_with(mark));
                if !named || shown.is_empty() || shown == REDACTED || placeholder {
                    return whole.as_str().to_string();
                }
                let (start, end) = (value.start() - whole.start(), value.end() - whole.start());
                format!(
                    "{}{REDACTED}{}",
                    &whole.as_str()[..start],
                    &whole.as_str()[end..]
                )
            })
            .into_owned();
    }
    out
}

/// A command-line option given as two words, `--password value`, with the
/// value bare or in quotes.
static LONG_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?P<lead>(?:^|[\s"'])--(?P<name>[A-Za-z][A-Za-z0-9_-]*)[ \t]+)(?P<value>"[^"\n]*"|'[^'\n]*'|[^\s"'-][^\s"']*)"#,
    )
    .unwrap()
});

/// `-u user:password`, as curl and its relatives take it.
static USER_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?P<lead>(?:^|\s)(?:-u|--user)[ \t]+["']?[^\s:"'$]+:)(?P<value>[^\s"']+)"#)
        .unwrap()
});

/// `text` with the credentials given to commands as options replaced.
fn redact_flags(text: &str) -> String {
    let mut out = text.to_string();
    if LONG_FLAG.is_match(&out) {
        out = LONG_FLAG
            .replace_all(&out, |found: &Captures<'_>| {
                let (name, value) = (&found["name"], &found["value"]);
                let quote = value.chars().next().filter(|c| *c == '"' || *c == '\'');
                let bare = value.trim_matches(['"', '\'']);
                // `--password-stdin` takes no value: what follows it is
                // another argument.
                // A sign after the option makes it an assignment, which is
                // read as one.
                let keep = !is_secret_field(name)
                    || name.to_ascii_lowercase().ends_with("stdin")
                    || bare.is_empty()
                    || bare == REDACTED
                    || bare.starts_with(['$', '=', ':'])
                    || is_number_or_keyword(bare);
                if keep {
                    return found[0].to_string();
                }
                let quote = quote.map(String::from).unwrap_or_default();
                format!("{}{quote}{REDACTED}{quote}", &found["lead"])
            })
            .into_owned();
    }
    if USER_FLAG.is_match(&out) {
        out = USER_FLAG
            .replace_all(&out, |found: &Captures<'_>| {
                let whole = &found["value"];
                let value = without_closers(whole);
                // `-u 1000:1000` names a user and a group by number, and a
                // path after a host is not a password either.
                if value.is_empty()
                    || value == REDACTED
                    || value.starts_with(['/', '~', '.'])
                    || value.chars().all(|c| c.is_ascii_digit())
                {
                    return found[0].to_string();
                }
                format!("{}{REDACTED}{}", &found["lead"], &whole[value.len()..])
            })
            .into_owned();
    }
    out
}

/// The start of an assignment: a name, and the operator after it. The name
/// may be the key of an index (`config["password"] = ...`) or an array
/// (`char password[] = ...`).
static ASSIGNED_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)(?:\\{1,7}["']|["'])?(?:\]|\[\])?(?P<before>[ \t]*)(?P<op>::|:=|\?=|\+=|===?|!==?|=~|=>|[:=])(?P<after>[ \t]*)"#,
    )
    .unwrap()
});

/// What stands between a name and a value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operator {
    /// `=`, and what sets a value in a makefile or in Go: `:=`, `?=`, `+=`.
    Equals,
    /// `:`
    Colon,
    /// `=>`
    Arrow,
    /// `==`, `!=` and the like: the value is compared, not assigned.
    Compare,
}

impl Operator {
    /// The operator written `text`, or `None` for `::`, which is a path and
    /// not an assignment.
    fn parse(text: &str) -> Option<Self> {
        match text {
            "::" => None,
            ":" => Some(Self::Colon),
            "=>" => Some(Self::Arrow),
            "=" | ":=" | "?=" | "+=" => Some(Self::Equals),
            _ => Some(Self::Compare),
        }
    }
}

/// How the name of an assignment says that its value is a credential.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NameKind {
    /// Written like a variable, `DB_PASSWORD`: the wider list of names.
    Variable,
    /// A field in code or in a config file.
    Field,
    /// An HTTP header whose whole value is a credential.
    Header,
}

impl NameKind {
    /// What `name` says about the value that `operator` gives it: `None`
    /// when it says nothing.
    fn of(name: &str, operator: Operator) -> Option<Self> {
        const HEADERS: &[&str] = &[
            "x-auth",
            "x-api-key",
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
        ];
        let lower = name.to_ascii_lowercase();
        // A header is written `Name: value`. With another sign the same
        // word is a variable or a field like any other.
        if operator == Operator::Colon && HEADERS.contains(&lower.as_str()) {
            return Some(Self::Header);
        }
        let variable = name.len() > 1
            && name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        if variable {
            (is_secret_variable(name) || is_secret_field(name)).then_some(Self::Variable)
        } else {
            is_secret_field(name).then_some(Self::Field)
        }
    }
}

/// Whether a name is that of a file, by how it ends: `token.rs`. A colon
/// after such a name may be followed by a position or by words about the
/// file, which are not its content.
fn is_file_name(name: &str) -> bool {
    const FILES: &[&str] = &[
        "rs", "py", "js", "jsx", "ts", "tsx", "go", "rb", "java", "kt", "c", "h", "cc", "cpp",
        "hpp", "cs", "php", "swift", "sh", "bash", "zsh", "sql", "md", "txt", "json", "yaml",
        "yml", "toml", "xml", "html", "css", "lock", "log", "cfg", "conf", "ini",
    ];
    name.to_ascii_lowercase()
        .rsplit_once('.')
        .is_some_and(|(_, extension)| FILES.contains(&extension))
}

/// Whether a variable holds a directory by what it is called, however much
/// `PWD` looks like a password.
fn is_directory_variable(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(), "pwd" | "oldpwd")
}

/// How far into a value the decision whether it is a literal looks. A longer
/// value is judged by its beginning.
const VALUE_SAMPLE: usize = 256;

/// What may close an expression or a quotation right after an unquoted
/// value, and is not part of it.
const CLOSERS: &[char] = &[',', ';', ')', ']', '}', '"', '\'', '\\'];

/// A value that is an expression or a reference rather than a literal: a
/// call, an index, a path through fields or modules, a variable.
fn looks_like_code(value: &str) -> bool {
    static FIELD_PATH: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$").unwrap()
    });
    // A long piece that mixes digits and both cases is a token with dots in
    // it, not the name of a field.
    let token_like = |part: &str| {
        part.len() >= 16
            && part.chars().any(|c| c.is_ascii_digit())
            && part.chars().any(|c| c.is_ascii_uppercase())
            && part.chars().any(|c| c.is_ascii_lowercase())
    };
    value.starts_with(['$', '&', '*', '!'])
        || ["(", "[", "{", "::", "->", "=>", "<"]
            .iter()
            .any(|mark| value.contains(mark))
        || (FIELD_PATH.is_match(value) && !value.split('.').any(token_like))
}

fn is_number_or_keyword(value: &str) -> bool {
    value.parse::<f64>().is_ok()
        || matches!(
            value.to_ascii_lowercase().as_str(),
            "true" | "false" | "null" | "none" | "nil" | "undefined"
        )
}

/// A position in a file, as it follows a file name: `12:` or `12:5:`.
fn is_position(value: &str) -> bool {
    let digits = value.strip_suffix(':').unwrap_or(value);
    !digits.is_empty()
        && digits
            .split(':')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

/// The name of a type, as it follows a field in a declaration.
fn is_type_name(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "str"
            | "string"
            | "int"
            | "integer"
            | "float"
            | "double"
            | "bool"
            | "boolean"
            | "bytes"
            | "byte"
            | "char"
            | "number"
            | "any"
            | "object"
            | "unknown"
            | "usize"
            | "isize"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "f32"
            | "f64"
    )
}

/// One word made of letters, as a variable or a weak password is.
fn is_bare_word(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_alphabetic() || c == '_')
}

/// Words of a phrase, as opposed to the rest of a command line: no path, no
/// option, no assignment, nothing a shell or a programming language gives a
/// meaning to.
fn is_plain_words(text: &str) -> bool {
    text.split_whitespace().all(|word| {
        !word.starts_with('-')
            && !word.contains([
                '/', '=', '$', '|', '&', '<', '>', ';', '(', ')', '{', '}', '[', ']', '`', ':',
                '\\', '"', '\'',
            ])
            && !word
                .split_once('.')
                .is_some_and(|(_, after)| after.starts_with(|c: char| c.is_ascii_alphanumeric()))
    })
}

/// `token` without what closes an expression or a quotation at its end. The
/// marker of a redaction ends with a bracket of its own, which stays.
fn without_closers(token: &str) -> &str {
    let mut token = token;
    while !token.ends_with(REDACTED) {
        match token.strip_suffix(CLOSERS) {
            Some(shorter) => token = shorter,
            None => break,
        }
    }
    token
}

/// Whether the name that starts at `name_start` is the first thing on its
/// line, after indentation, an opening quote, the dash of a list or a
/// keyword that sets a variable. That is where config files and scripts
/// write `name: value` and `NAME=value`, with the value running to the end
/// of the line.
fn starts_line(text: &str, name_start: usize) -> bool {
    const LEAD: usize = 48;
    let mut from = name_start.saturating_sub(LEAD);
    while !text.is_char_boundary(from) {
        from += 1;
    }
    let before = &text[from..name_start];
    let line = match before.rfind('\n') {
        Some(line_break) => &before[line_break + 1..],
        None if from == 0 => before,
        None => return false,
    };
    let lead = line.trim_start().trim_end_matches(['"', '\'']).trim_end();
    matches!(
        lead,
        "" | "-" | "export" | "set" | "setenv" | "declare" | "local" | "readonly" | "env"
    )
}

/// In `name: Type = value`, where the value starts in `rest`, the text after
/// the colon. `None` when the colon is not followed by one type and an `=`.
///
/// A type is one word, with blanks only inside its brackets or after what
/// may stand before it (`&`, a lifetime, `mut`, `dyn`, `impl`). Two words
/// before an `=` are a value and something else, not a declaration.
fn typed_value(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let mut at = 0;
    loop {
        let before = at;
        for lead in ["&", "*", "mut ", "const ", "dyn ", "impl "] {
            if rest[at..].starts_with(lead) {
                at += lead.len();
            }
        }
        if bytes.get(at) == Some(&b'\'') {
            let name = bytes[at + 1..]
                .iter()
                .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
                .count();
            if name > 0 && bytes.get(at + 1 + name) == Some(&b' ') {
                at += name + 2;
            }
        }
        if at == before {
            break;
        }
    }
    let start = at;
    let mut depth = 0usize;
    while let Some(byte) = bytes.get(at) {
        match byte {
            b'<' | b'[' | b'(' => depth += 1,
            b'>' | b']' | b')' => depth = depth.checked_sub(1)?,
            b' ' | b'\t' if depth == 0 => break,
            b' ' | b'\t' | b';' if depth > 0 => {}
            byte if byte.is_ascii_alphanumeric() || b"_.,:?|&*'".contains(byte) => {}
            _ => return None,
        }
        at += 1;
        if at > 96 {
            return None;
        }
    }
    if at == start || depth != 0 {
        return None;
    }
    let value = rest[at..]
        .trim_start_matches([' ', '\t'])
        .strip_prefix('=')?;
    if value.starts_with(['=', '>', '~']) {
        return None;
    }
    Some(rest.len() - value.trim_start_matches([' ', '\t']).len())
}

/// An assignment found in the text: what stands before its value.
struct Assignment<'a> {
    name: &'a str,
    kind: NameKind,
    operator: Operator,
    /// `name=value` with nothing around the sign, as in a query string.
    tight: bool,
    /// Whether the name [starts its line](starts_line).
    starts_line: bool,
    /// Whether a type and an `=` follow the colon: `name: Type = value`.
    typed: bool,
}

/// How much of the text after an operator is replaced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    /// Nothing: the value is not a credential, as far as can be told.
    Keep,
    /// The value itself: a quoted text, or one word.
    Value,
    /// Everything up to this offset: a value of several words.
    Line(usize),
}

/// The value that follows a name and its operator, at the start of `rest`.
struct AssignedValue<'a> {
    rest: &'a str,
    /// How many bytes stand before the text of a quoted value: the prefix of
    /// a literal (`b`, `r#`, `f`) and the opening quote.
    open: usize,
    /// What closes a quoted value: a quote, or a quote written `\"` inside a
    /// text that is itself quoted. Empty for a value without quotes.
    quote: &'a str,
    /// The value without its quotes, or the beginning of it when it is longer
    /// than [`VALUE_SAMPLE`].
    sample: &'a str,
    /// Whether `sample` is the whole value.
    whole: bool,
}

impl<'a> AssignedValue<'a> {
    fn at(rest: &'a str) -> Self {
        let (open, quote) = Self::opening(rest);
        let (end, whole) = Self::content_end(&rest[open..], quote, VALUE_SAMPLE);
        Self {
            rest,
            open,
            quote,
            sample: &rest[open..open + end],
            whole,
        }
    }

    /// The length of what opens a quoted value at the start of `rest`, and
    /// what closes it.
    fn opening(rest: &'a str) -> (usize, &'a str) {
        let bytes = rest.as_bytes();
        // What some languages write before a string: `b"..."`, `r#"..."#`,
        // `f'...'`, `@"..."`.
        const PREFIXES: &[&str] = &[
            "b", "r", "f", "u", "c", "l", "rb", "br", "fr", "rf", "cr", "@", "$", "$@", "@$",
        ];
        let letters = bytes
            .iter()
            .take(2)
            .take_while(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'@' | b'$'))
            .count();
        let prefix = if PREFIXES.contains(&rest[..letters].to_ascii_lowercase().as_str()) {
            letters
                + bytes[letters..]
                    .iter()
                    .take(3)
                    .take_while(|byte| **byte == b'#')
                    .count()
        } else {
            0
        };
        for start in [prefix, 0] {
            match bytes.get(start) {
                Some(b'"' | b'\'') => return (start + 1, &rest[start..start + 1]),
                // A quote escaped once or more, as in JSON that is itself
                // in a string: `\"`, `\\\"`.
                Some(b'\\') if start == 0 => {
                    let slashes = bytes
                        .iter()
                        .take(8)
                        .take_while(|byte| **byte == b'\\')
                        .count();
                    if slashes < 8 && matches!(bytes.get(slashes), Some(b'"' | b'\'')) {
                        return (slashes + 1, &rest[..=slashes]);
                    }
                }
                _ => {}
            }
        }
        (0, "")
    }

    /// Where the text of a value ends in `body`, and whether that was found
    /// within `limit` bytes. A quoted value ends at its quote, or at the end
    /// of the line when the quote is never closed; any other value ends at
    /// the first blank.
    fn content_end(body: &str, quote: &str, limit: usize) -> (usize, bool) {
        let mut escaped = false;
        for (index, c) in body.char_indices() {
            let ends = match quote {
                // In a list of `Name=value;` pairs, as connection strings are
                // written, a value ends where the next pair starts.
                "" => c.is_whitespace() || (c == ';' && starts_a_pair(&body[index + 1..])),
                "\"" | "'" => !escaped && (c == '\n' || quote.starts_with(c)),
                _ => c == '\n' || body[index..].starts_with(quote),
            };
            if ends {
                return (index, true);
            }
            if index >= limit {
                return (index, false);
            }
            escaped = quote.len() == 1 && !escaped && c == '\\';
        }
        (body.len(), true)
    }

    fn is_quoted(&self) -> bool {
        !self.quote.is_empty()
    }

    /// An unquoted value, without what closes an expression after it.
    fn token(&self) -> &'a str {
        without_closers(self.sample)
    }

    /// What follows an unquoted value on its line, up to a comment: the
    /// blanks included. `None` when the line is too long to be looked at.
    fn line_tail(&self) -> Option<&'a str> {
        let after = &self.rest[self.sample.len()..];
        let window = &after[..char_floor(after, VALUE_SAMPLE)];
        let line = match window.find('\n') {
            Some(line_break) => &window[..line_break],
            None if window.len() == after.len() => window,
            None => return None,
        };
        let line = [" #", "\t#", " //", "\t//"]
            .iter()
            .filter_map(|comment| line.find(comment))
            .min()
            .map_or(line, |comment| &line[..comment]);
        Some(line.trim_end())
    }

    /// Whether the value is nothing but the marker of a redaction.
    fn is_redacted(&self) -> bool {
        if self.is_quoted() {
            self.sample == REDACTED
        } else {
            self.token() == REDACTED
        }
    }

    /// Whether the value is a literal that the name makes a credential,
    /// whatever the operator: a quoted text, or a word that is neither an
    /// expression nor a plain word.
    fn is_secret_literal(&self) -> bool {
        if self.sample.is_empty() || self.is_redacted() {
            return false;
        }
        let value = if self.is_quoted() {
            self.sample
        } else {
            self.token()
        };
        if value.is_empty() || (self.whole && is_number_or_keyword(value)) {
            return false;
        }
        self.is_quoted()
            // What an earlier rule left of a value goes with the rest of it.
            || value.starts_with(REDACTED)
            || !(looks_like_code(value)
                || is_type_name(value)
                || is_position(value)
                || (self.whole && is_bare_word(value)))
    }

    /// How much of the value is a credential, given what it is assigned to.
    fn verdict(&self, assignment: &Assignment<'_>) -> Verdict {
        if self.sample.is_empty() || self.is_redacted() {
            return Verdict::Keep;
        }
        let directory = is_directory_variable(assignment.name);
        if self.is_quoted() {
            let keyword = self.whole && is_number_or_keyword(self.sample);
            let path = directory && self.sample.starts_with(['/', '~', '.']);
            return if keyword || path {
                Verdict::Keep
            } else {
                Verdict::Value
            };
        }
        let token = self.token();
        let closed = token.len() < self.sample.len();
        if token.is_empty()
            || assignment.operator == Operator::Compare
            || (self.whole && (is_number_or_keyword(token) || is_position(token)))
            || (directory && token.starts_with(['/', '~', '.']))
        {
            return Verdict::Keep;
        }
        let secret = match (assignment.kind, assignment.operator) {
            // A value of which an earlier rule replaced the beginning: the
            // rest of it is the same secret.
            _ if token.starts_with(REDACTED) => true,
            // `NAME=value`, as variables are set: the value goes whatever it
            // looks like, unless it refers to another variable.
            (NameKind::Variable, Operator::Equals) => !token.starts_with('$'),
            // In `name=value` with nothing around the sign, a leading `!` or
            // `*` belongs to a password, not to an expression.
            (_, Operator::Equals)
                if assignment.tight
                    && token.starts_with(['!', '*'])
                    && !looks_like_code(&token[1..]) =>
            {
                true
            }
            _ if looks_like_code(token) => false,
            (_, Operator::Colon) if is_type_name(token) => false,
            _ if self.whole && is_bare_word(token) => self.bare_word_is_secret(assignment, closed),
            _ => true,
        };
        if !secret {
            return Verdict::Keep;
        }
        // At the start of a line a value runs to the end of it, when what
        // follows is more words and not the command the variable is set for.
        let line = matches!(assignment.operator, Operator::Equals | Operator::Colon)
            && assignment.starts_line
            && !closed
            && self.whole;
        match self.line_tail().filter(|_| line) {
            Some(tail) if !tail.is_empty() && is_plain_words(tail) => {
                Verdict::Line(self.sample.len() + tail.len())
            }
            _ => Verdict::Value,
        }
    }

    /// Whether one bare word is a literal. In code it is a variable
    /// (`token: token`, `f(password=pw)`); in a query string, a connection
    /// string, a properties file or a YAML file it is a weak password.
    fn bare_word_is_secret(&self, assignment: &Assignment<'_>, closed: bool) -> bool {
        let token = self.token();
        if token.eq_ignore_ascii_case(assignment.name) {
            return false;
        }
        // A bracket or a comma after the word ends an argument in code. A
        // quote or a `;` ends the text the assignment is written in.
        let in_code = self.sample[token.len()..].starts_with([')', ']', '}', ',']);
        match assignment.operator {
            Operator::Equals => assignment.tight && !in_code,
            Operator::Colon => {
                !closed
                    && assignment.starts_line
                    && !assignment.typed
                    && self.line_tail().is_some_and(is_plain_words)
            }
            _ => false,
        }
    }

    /// How many bytes of `rest` the value takes, quotes included, and how
    /// many of them at its end are not part of it.
    fn extent(&self) -> (usize, usize) {
        let (end, _) = Self::content_end(&self.rest[self.open..], self.quote, usize::MAX);
        let end = self.open + end;
        if self.is_quoted() {
            let closed = self.rest[end..].starts_with(self.quote);
            (end + if closed { self.quote.len() } else { 0 }, 0)
        } else {
            (end, end - without_closers(&self.rest[..end]).len())
        }
    }
}

/// Whether `rest` starts with `Name=`: the next pair of a list of pairs.
fn starts_a_pair(rest: &str) -> bool {
    let name = rest
        .bytes()
        .take(64)
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b' ' | b'.'))
        .count();
    name > 0 && rest.as_bytes().get(name) == Some(&b'=')
}

/// Longest block of lines taken as one value: a YAML block scalar or a
/// heredoc.
const MAX_BLOCK: usize = 64 * 1024;

/// Where each line that could end a heredoc stands in a text: a line made of
/// a word alone, by that word, at the line break before it. Built once for a
/// text, so that the end of a heredoc is looked up rather than searched for
/// again for every heredoc that opens.
struct HeredocEnds<'a>(std::collections::HashMap<&'a str, Vec<usize>>);

impl<'a> HeredocEnds<'a> {
    fn of(text: &'a str) -> Self {
        let mut ends: std::collections::HashMap<&'a str, Vec<usize>> = Default::default();
        let mut at = 0;
        for line in text.split('\n') {
            let word = line.trim();
            let marker = !word.is_empty()
                && word.len() <= 64
                && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if marker && at > 0 {
                ends.entry(word).or_default().push(at - 1);
            }
            at += line.len() + 1;
        }
        Self(ends)
    }

    /// The line break before the first line from `from` on, and before
    /// `to`, that is `marker` alone.
    fn after(&self, marker: &str, from: usize, to: usize) -> Option<usize> {
        let positions = self.0.get(marker)?;
        let first = positions.partition_point(|at| *at < from);
        positions.get(first).copied().filter(|at| *at < to)
    }
}

/// Where a value written as a block of lines ends, when `token`, alone on its
/// line after the name that starts at `name_start`, opens one: a YAML block
/// scalar (`|`, `>-`) takes the lines indented more than the name, a heredoc
/// (`<<EOF`) the lines up to its end marker.
fn block_end<'a>(
    text: &'a str,
    name_start: usize,
    value_start: usize,
    token: &str,
    heredoc_ends: &std::cell::OnceCell<HeredocEnds<'a>>,
) -> Option<usize> {
    let line_end = text[value_start..]
        .find('\n')
        .map_or(text.len(), |at| value_start + at);
    // Alone on its line, but for a comment, and for a YAML tag before it
    // (`!!binary |`).
    let mut shown = &text[value_start..line_end];
    if let Some(comment) = shown.find([' ', '\t']).and_then(|blank| {
        shown[blank..]
            .find('#')
            .filter(|at| shown[blank..blank + at].trim().is_empty())
            .map(|at| blank + at)
    }) {
        shown = &shown[..comment];
    }
    let mut shown = shown.trim();
    if shown.starts_with("!!") {
        shown = shown
            .split_once(char::is_whitespace)
            .map_or("", |(_, rest)| rest.trim());
    }
    // What the line holds, rather than the value as it was read: a heredoc
    // marker keeps its quotes, `<<'EOF'`.
    let token = if token.starts_with("!!") || shown.starts_with("<<") {
        shown
    } else {
        token
    };
    if shown != token || line_end == text.len() {
        return None;
    }
    let scalar = token.starts_with(['|', '>'])
        && token[1..]
            .chars()
            .all(|c| matches!(c, '-' | '+') || c.is_ascii_digit());
    let marker = token
        .strip_prefix("<<")
        .map(|marker| {
            marker
                .trim_start_matches(['-', '~'])
                .trim_matches(['"', '\''])
        })
        .filter(|marker| {
            !marker.is_empty()
                && marker
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
    if !scalar && marker.is_none() {
        return None;
    }
    let limit = (line_end + MAX_BLOCK).min(text.len());
    if let Some(marker) = marker {
        // A heredoc whose end is not in reach is not taken for one.
        return heredoc_ends
            .get_or_init(|| HeredocEnds::of(text))
            .after(marker, line_end, limit);
    }
    let line_start = text[..name_start].rfind('\n').map_or(0, |at| at + 1);
    let lead = &text[line_start..name_start];
    let indent = lead.len() - lead.trim_start_matches([' ', '\t']).len();
    let mut end = line_end;
    let mut at = line_end;
    while at < limit {
        let start = at + 1;
        let stop = text[start..]
            .find('\n')
            .map_or(text.len(), |found| start + found);
        let line = &text[start..stop];
        let line_indent = line.len() - line.trim_start_matches([' ', '\t']).len();
        if !line.trim().is_empty() && line_indent <= indent {
            break;
        }
        end = stop;
        at = stop;
    }
    (end > line_end).then_some(end)
}

/// The quote that opens the quotation a header stands in, if it stands in
/// one: the quote right before its name, or the nearest one before it on
/// its line.
fn opening_quote(text: &str, name_start: usize) -> Option<char> {
    let mut from = name_start.saturating_sub(VALUE_SAMPLE);
    while !text.is_char_boundary(from) {
        from += 1;
    }
    let before = &text[from..name_start];
    let line = before.rfind('\n').map_or(before, |at| &before[at + 1..]);
    line.chars().rev().find(|c| *c == '"' || *c == '\'')
}

/// A text being copied with some of its parts replaced, from left to right.
struct Rewrite<'a> {
    text: &'a str,
    out: String,
    /// How much of `text` is in `out` already, as it was or replaced.
    copied: usize,
}

impl Rewrite<'_> {
    /// Replaces `text[from..to]`, keeping its line breaks so that the lines
    /// after it keep their numbers.
    fn replace_lines(&mut self, from: usize, to: usize) {
        let lines = self.text[from..to].matches('\n').count();
        self.out.push_str(&self.text[self.copied..from]);
        self.out.push_str(REDACTED);
        self.out.extend(std::iter::repeat_n('\n', lines));
        self.copied = to;
    }

    /// Replaces `text[from..to]`, which is in quotes when `quoted` is given:
    /// the opening and the closing of the quotation.
    fn replace(&mut self, from: usize, to: usize, quoted: Option<(&str, &str)>) {
        let (open, close) = quoted.unwrap_or_default();
        self.out.push_str(&self.text[self.copied..from]);
        self.out.push_str(open);
        self.out.push_str(REDACTED);
        self.out.push_str(close);
        self.copied = to;
    }

    /// Replaces the value that starts at `start`, and returns where the text
    /// goes on after it.
    fn replace_value(&mut self, start: usize, value: &AssignedValue<'_>) -> usize {
        let (len, tail) = value.extent();
        let end = start + len;
        if value.is_quoted() {
            let open = &value.rest[..value.open];
            let closed = len > value.open && value.rest[..len].ends_with(value.quote);
            let close = if closed { value.quote } else { "" };
            self.replace(start, end, Some((open, close)));
        } else {
            self.replace(start, end - tail, None);
        }
        end - tail
    }

    fn finish(mut self) -> String {
        self.out.push_str(&self.text[self.copied..]);
        self.out
    }
}

/// `text` with the value of every assignment to a secret-looking name
/// replaced, when that value is a literal.
///
/// The text is gone through once, from left to right. An assignment that is
/// left alone is looked into from where its value starts, since a value can
/// hold an assignment of its own, as the query of a URL does behind the `:`
/// of its scheme.
fn redact_assignments(text: &str) -> String {
    let mut rewrite = Rewrite {
        text,
        out: String::with_capacity(text.len()),
        copied: 0,
    };
    let mut search = 0;
    let heredoc_ends = std::cell::OnceCell::new();
    while let Some(found) = ASSIGNED_NAME.captures_at(text, search) {
        let (Some(whole), Some(name)) = (found.get(0), found.name("name")) else {
            break;
        };
        let value_start = whole.end();
        search = value_start;
        let Some(operator) = Operator::parse(&found["op"]) else {
            continue;
        };
        // Most names say nothing about a secret: their values are not read.
        let Some(kind) = NameKind::of(name.as_str(), operator) else {
            continue;
        };
        let rest = &text[value_start..];
        let starts_line = starts_line(text, name.start());

        // The value of a header is the rest of its line, or of the quotation
        // the header stands in.
        if kind == NameKind::Header && AssignedValue::opening(rest).1.is_empty() {
            // Judged by its first word, before the whole of it is measured.
            let window = &rest[..char_floor(rest, VALUE_SAMPLE)];
            let first = window
                .split('\n')
                .next()
                .and_then(|line| line.split_whitespace().next())
                .unwrap_or_default();
            // In code the value of a header is an expression. At the start
            // of a line, as headers are sent and logged, it is the
            // credential, whatever it looks like.
            let code = !starts_line && !first.starts_with(REDACTED) && looks_like_code(first);
            if first.is_empty() || code {
                continue;
            }
            let quote = opening_quote(text, name.start())
                .filter(|quote| !starts_line || text[..name.start()].ends_with(*quote));
            let end = match quote {
                Some(quote) => rest.find(['\n', quote]),
                None => rest.find('\n'),
            }
            .unwrap_or(rest.len());
            let end = value_start + rest[..end].trim_end().len();
            if &text[value_start..end] != REDACTED {
                rewrite.replace(value_start, end, None);
            }
            search = end;
            continue;
        }

        let value = AssignedValue::at(rest);
        // `token.rs:12: ...` and `token.rs: a few words` are about a file. A
        // single value after `password.txt:` is what the file holds.
        if operator == Operator::Colon && is_file_name(name.as_str()) && !value.is_quoted() {
            let about =
                is_position(value.token()) || value.line_tail().is_none_or(|tail| !tail.is_empty());
            if about {
                continue;
            }
        }
        // A value written as a block of lines after its name: all of it.
        if matches!(operator, Operator::Colon | Operator::Equals)
            && starts_line
            && !value.is_quoted()
        {
            if let Some(end) = block_end(
                text,
                name.start(),
                value_start,
                value.token(),
                &heredoc_ends,
            ) {
                rewrite.replace_lines(value_start, end);
                search = end;
                continue;
            }
        }
        let typed = if operator == Operator::Colon {
            typed_value(rest)
        } else {
            None
        };
        let assignment = Assignment {
            name: name.as_str(),
            kind,
            operator,
            tight: found["before"].is_empty() && found["after"].is_empty(),
            starts_line,
            typed: typed.is_some(),
        };
        let mut end = match value.verdict(&assignment) {
            Verdict::Keep => None,
            Verdict::Line(len) => {
                rewrite.replace(value_start, value_start + len, None);
                Some(value_start + len)
            }
            Verdict::Value => Some(rewrite.replace_value(value_start, &value)),
        };
        // In a declaration the colon is followed by a type, and the value is
        // what follows the `=` after it.
        if let Some(start) = typed.map(|offset| value_start + offset) {
            let declared = AssignedValue::at(&text[start..]);
            if end.is_none_or(|end| end <= start) && declared.is_secret_literal() {
                end = Some(rewrite.replace_value(start, &declared));
            }
        }
        if let Some(end) = end {
            search = end;
        }
    }
    rewrite.finish()
}

/// Removes secrets from text before it reaches the advisor.
#[derive(Clone, Default)]
pub(crate) struct Redactor {
    /// Known secret values, longest first so that a value containing another
    /// is replaced whole.
    known: Vec<String>,
}

impl Redactor {
    /// A redactor that knows the given secrets.
    ///
    /// `settings` are `(name, value)` pairs from the config: every value is a
    /// secret, except that a URL only gives up its credentials. `environment`
    /// is the process environment and `public` what is not to be hidden for
    /// being in it: see [`environment_value_is_secret`].
    pub(crate) fn new<'a>(
        settings: impl IntoIterator<Item = (&'a str, &'a str)>,
        environment: impl IntoIterator<Item = (String, String)>,
        public: &[&str],
    ) -> Self {
        let mut known: Vec<String> = Vec::new();
        let mut urls: Vec<&str> = Vec::new();
        for (name, value) in settings {
            // Redacting a base URL whole would hide every mention of the
            // host, which is not a secret.
            if name.to_ascii_uppercase().ends_with("_URL") {
                known.extend(url_secrets(value));
                urls.push(value);
            } else if value.len() >= MIN_SECRET_LEN {
                known.push(value.to_string());
            }
        }
        for (name, value) in environment {
            // A URL of the config that shai exported is the same URL.
            if environment_value_is_secret(&name, &value, public) && !urls.contains(&value.as_str())
            {
                known.push(value);
            }
        }
        known.retain(|value| can_be_known(value));
        // A value is the same secret in the forms programs write it in.
        let forms: Vec<String> = known
            .iter()
            .flat_map(|value| encoded_forms(value))
            .collect();
        known.extend(forms);
        known.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        known.dedup();
        Self { known }
    }

    /// `text` with every known or recognizable secret replaced.
    pub(crate) fn redact(&self, text: &str) -> String {
        let mut out = self.redact_escaped_known(text);
        for secret in &self.known {
            if out.contains(secret.as_str()) {
                // A value of several lines leaves its line breaks behind, so
                // that the lines after it keep their numbers.
                let lines = "\n".repeat(secret.matches('\n').count());
                out = out.replace(secret.as_str(), &format!("{REDACTED}{lines}"));
            }
        }
        if KEY_BEGIN.is_match(&out) {
            out = redact_private_keys(&out);
        }
        if PUTTY_PRIVATE.is_match(&out) {
            out = PUTTY_PRIVATE
                .replace_all(&out, |found: &Captures<'_>| {
                    // The line breaks of the body stay, so that the lines
                    // after it keep their numbers.
                    let lines = "\n".repeat(found[2].matches('\n').count());
                    format!("{}\n{REDACTED}{lines}", &found[1])
                })
                .into_owned();
        }
        if URL_PASSWORD.is_match(&out) {
            out = redact_url_passwords(&out);
        }
        for (shape, replacement) in SECRET_SHAPES.iter() {
            if shape.is_match(&out) {
                out = shape.replace_all(&out, *replacement).into_owned();
            }
        }
        redact_assignments(&redact_flags(&redact_handed_over(&out)))
    }

    /// `text` with the values this redactor knows replaced where they are
    /// written with JSON escapes: `\uXXXX` in either case, as every encoder
    /// writes the characters it escapes, and `\/`. The escapes are decoded
    /// in a copy, the values looked for there, and what they were written as
    /// replaced in `text`.
    fn redact_escaped_known(&self, text: &str) -> String {
        if !(text.contains("\\u") || text.contains("\\/")) {
            return text.to_string();
        }
        let (decoded, origin) = decode_json_escapes(text);
        let mut spans: Vec<(usize, usize)> = Vec::new();
        for secret in &self.known {
            for (start, found) in decoded.match_indices(secret.as_str()) {
                let end = start + found.len();
                let from = origin[start];
                let to = origin[end];
                // Written without escapes, it is replaced as it stands.
                if text[from..to] != *found {
                    spans.push((from, to));
                }
            }
        }
        if spans.is_empty() {
            return text.to_string();
        }
        spans.sort();
        let mut out = String::with_capacity(text.len());
        let mut copied = 0;
        for (from, to) in spans {
            if to <= copied {
                continue;
            }
            let from = from.max(copied);
            out.push_str(&text[copied..from]);
            out.push_str(REDACTED);
            copied = to;
        }
        out.push_str(&text[copied..]);
        out
    }

    /// `text` with the values this redactor knows replaced, and nothing
    /// else: for text that was redacted whole already and changed since.
    pub(crate) fn redact_known(&self, text: &str) -> String {
        let mut out = text.to_string();
        for secret in &self.known {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), REDACTED);
            }
        }
        out
    }

    /// [`Redactor::redact`] for text that was cut to a size before it got
    /// here. The cut may have gone through a known value, of which only the
    /// beginning is left at the end of the text: that beginning goes too.
    pub(crate) fn redact_truncated(&self, text: &str) -> String {
        // The longest beginning of a known value that the text ends with.
        let cut = self
            .known
            .iter()
            .filter_map(|secret| {
                (MIN_CUT_SECRET_LEN..secret.len())
                    .rev()
                    .filter(|len| secret.is_char_boundary(*len))
                    .find(|len| text.ends_with(&secret[..*len]))
            })
            .max();
        let Some(len) = cut else {
            return self.redact(text);
        };
        // What looks like a beginning may be the end of a value that is
        // there in full, as in a password that repeats itself: a value the
        // cut would go through goes whole.
        let mut start = text.len() - len;
        while let Some(head) = self.known.iter().find_map(|secret| {
            (1..secret.len())
                .filter(|head| secret.is_char_boundary(*head))
                .find(|head| {
                    text[..start].ends_with(&secret[..*head])
                        && text[start..].starts_with(&secret[*head..])
                })
        }) {
            start -= head;
        }
        self.redact(&format!("{}{REDACTED}", &text[..start]))
    }

    /// `json`, the arguments of a tool call as the model wrote them, with
    /// every string and every name in it redacted.
    ///
    /// The strings are redacted as what they say, not as they are escaped: a
    /// key with its line breaks written `\n`, or a quoted assignment inside a
    /// command, is the same secret. Under a name that says it holds a
    /// credential, every string goes whole. Text that is not JSON is redacted
    /// as it stands.
    pub(crate) fn redact_json(&self, json: &str) -> String {
        use serde_json::Value;
        fn walk(redactor: &Redactor, value: Value, secret: bool) -> Value {
            match value {
                Value::String(text) if secret && !text.is_empty() => {
                    Value::String(REDACTED.to_string())
                }
                Value::String(text) => Value::String(redactor.redact(&text)),
                Value::Array(items) => Value::Array(
                    items
                        .into_iter()
                        .map(|item| walk(redactor, item, secret))
                        .collect(),
                ),
                Value::Object(fields) => Value::Object(
                    fields
                        .into_iter()
                        .map(|(name, field)| {
                            let secret = secret || NameKind::of(&name, Operator::Colon).is_some();
                            (redactor.redact(&name), walk(redactor, field, secret))
                        })
                        .collect(),
                ),
                // A number written without quotes is still a known value.
                Value::Number(number) => {
                    let shown = number.to_string();
                    // Its digits too: written out again, a large number can
                    // come back as `1.234...e20`, a point inside the value.
                    let digits: String = shown
                        .split(['e', 'E'])
                        .next()
                        .unwrap_or_default()
                        .chars()
                        .filter(char::is_ascii_digit)
                        .collect();
                    if redactor.redact_known(&shown) == shown
                        && redactor.redact_known(&digits) == digits
                    {
                        Value::Number(number)
                    } else {
                        Value::String(REDACTED.to_string())
                    }
                }
                other => other,
            }
        }
        match serde_json::from_str::<Value>(json) {
            // What is written out again is looked at once more: a number
            // can come back in another form than it was given in.
            Ok(value) => self.redact_known(&walk(self, value, false).to_string()),
            Err(_) => self.redact(json),
        }
    }
}

// Never print what the redactor knows.
impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Redactor({} known values)", self.known.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ovh-key-0123456789abcdef";
    const ENV_TOKEN: &str = "ghs-not-a-real-shape-9876543210";

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    fn redactor() -> Redactor {
        Redactor::new(
            [
                ("OVH_API_KEY", KEY),
                ("OVH_BASE_URL", "https://llm.example.com/v1"),
                ("SHORT", "abc"),
            ],
            env(&[
                ("DEPLOY_TOKEN", ENV_TOKEN),
                ("HOME", "/home/someone"),
                ("EDITOR", "vim-with-a-long-name"),
            ]),
            &[],
        )
    }

    #[test]
    fn known_values_are_replaced_wherever_they_appear() {
        let text = format!(
            "curl -H 'x-api-key: {KEY}' https://llm.example.com/v1 && echo {ENV_TOKEN}{KEY}"
        );
        let out = redactor().redact(&text);
        assert!(!out.contains(KEY), "{out}");
        assert!(!out.contains(ENV_TOKEN), "{out}");
        // Base URLs and unremarkable variables are left alone.
        assert!(out.contains("https://llm.example.com/v1"), "{out}");
        let out = redactor().redact("cd /home/someone && vim-with-a-long-name abc");
        assert_eq!(out, "cd /home/someone && vim-with-a-long-name abc");
    }

    #[test]
    fn a_secret_containing_another_is_replaced_whole() {
        let redactor = Redactor::new(
            [("A_KEY", "abcdefgh"), ("B_KEY", "abcdefgh-and-more")],
            Vec::<(String, String)>::new(),
            &[],
        );
        assert_eq!(redactor.redact("x abcdefgh-and-more y"), "x [redacted] y");
    }

    #[test]
    fn the_environment_is_secret_unless_plainly_harmless() {
        let dir = tempfile::TempDir::new().unwrap();
        let here = dir.path().to_string_lossy().into_owned();
        let path_list = format!("{here}:{here}");
        let redactor = Redactor::new(
            Vec::<(&str, &str)>::new(),
            env(&[
                // Secrets under names no list of names would have guessed.
                ("SMTP_HOST_LINE", "mail.internal.example:2525"),
                ("DB_PASS", "sunshineday"),
                ("GH_PAT", "0123456789abcdef"),
                ("REDIS_URL", "redis://cache.internal:6379/0"),
                ("GIT_AUTHOR_NAME", "Ada Lovelace"),
                ("ODD_ONE", "/Zx3+abc/def=="),
                // Harmless by what the variable is.
                ("PWD", "/srv/work/project-with-a-long-name"),
                ("OLDPWD", "/srv/work/other-project"),
                ("USER", "a-rather-long-login"),
                ("LC_ALL", "en_US.UTF-8"),
                // Harmless by what the value is.
                ("NODE_ENV", "production"),
                ("BUILD_NUMBER", "1234567890"),
                ("VIRTUAL_ENV", here.as_str()),
                ("SOME_PATHS", path_list.as_str()),
                // Part of what the advisor is shown anyway.
                ("npm_package_name", "my-project-2"),
                ("PROJECT_ROOT", "/srv/code/my-project-2"),
                // The same kind of value under a name that says "secret".
                ("DEPLOY_KEY_NAME", "my-project-2-key"),
                // Too short to tell from ordinary text.
                ("PIN", "1234"),
            ]),
            &["/srv/code/my-project-2-key/checkout"],
        );

        for secret in [
            "mail.internal.example:2525",
            "sunshineday",
            "0123456789abcdef",
            "redis://cache.internal:6379/0",
            "Ada Lovelace",
            "/Zx3+abc/def==",
        ] {
            let out = redactor.redact(&format!("before {secret} after"));
            assert_eq!(out, "before [redacted] after", "{secret}");
        }
        for plain in [
            "/srv/work/project-with-a-long-name/src/lib.rs",
            "/srv/work/other-project",
            "a-rather-long-login",
            "en_US.UTF-8",
            "production",
            "1234567890",
            here.as_str(),
            "1234",
            "/srv/code/my-project-2/src/main.rs",
        ] {
            let text = format!("before {plain} after");
            assert_eq!(redactor.redact(&text), text, "{plain}");
        }
        assert_eq!(
            redactor.redact("uses my-project-2-key to deploy"),
            "uses [redacted] to deploy"
        );
    }

    #[test]
    fn a_url_setting_gives_up_its_credentials_and_keeps_its_host() {
        let redactor = Redactor::new(
            [
                (
                    "OPENAI_COMPATIBLE_BASE_URL",
                    "https://gatewaytoken99@gateway.example.com/v1?key=querysecret77",
                ),
                (
                    "OTHER_BASE_URL",
                    "https://someuser:p%40ssw0rd@other.example.com/v1",
                ),
            ],
            Vec::<(String, String)>::new(),
            &[],
        );
        let out = redactor
            .redact("curl https://gateway.example.com/v1 # gatewaytoken99 querysecret77 someuser");
        assert_eq!(
            out,
            "curl https://gateway.example.com/v1 # [redacted] [redacted] [redacted]"
        );
        // The password as it is written in the URL, and as it decodes.
        for form in ["p%40ssw0rd", "p@ssw0rd"] {
            assert!(!redactor.redact(&format!("x {form} y")).contains(form));
        }
    }

    #[test]
    fn a_known_value_is_found_in_its_json_escaped_form() {
        let secret = "line one\nline \"two\" of a secret";
        let redactor = Redactor::new([("SOME_KEY", secret)], Vec::<(String, String)>::new(), &[]);
        let arguments = serde_json::json!({ "command": format!("echo {secret}") }).to_string();
        assert!(arguments.contains(r#"line one\nline \"two\""#));
        for out in [
            redactor.redact(&arguments),
            redactor.redact_json(&arguments),
        ] {
            assert!(!out.contains("of a secret"), "{out}");
            assert!(out.contains(REDACTED), "{out}");
        }
    }

    #[test]
    fn credential_shapes_are_replaced_without_being_known() {
        let redactor = Redactor::default();
        // Built at run time, so that secret scanners do not take them for real keys.
        let stripe_live = ["sk", "live", "abcdefghijklmnopqrstuvwx"].join("_");
        let stripe_restricted = ["rk", "test", "abcdefghijklmnopqrstuvwx"].join("_");
        for secret in [
            "sk-proj-abcdefghijklmnopqrstuvwx",
            "sk-ant-api03-abcdefghijklmnopqrstuvwx",
            stripe_live.as_str(),
            stripe_restricted.as_str(),
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz",
            "glpat-abcdefghijklmnopqrst",
            "AKIAIOSFODNN7EXAMPLE",
            "xoxb-123456789012-abcdefghijkl",
            "AIzaSyA-abcdefghijklmnopqrstuvwxyz012345",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
        ] {
            let out = redactor.redact(&format!("value {secret} end"));
            assert!(!out.contains(secret), "{secret} survived: {out}");
            assert!(out.ends_with(" end"), "{out}");
        }

        let out = redactor.redact("Authorization: Bearer abcdefghijklmnopqrstuvwxyz");
        assert!(!out.contains("abcdefghijklmnopqrstuvwxyz"), "{out}");
    }

    #[test]
    fn the_user_part_of_a_url_goes_and_the_rest_stays() {
        let redactor = Redactor::default();
        for (input, expected) in [
            (
                "git clone https://user:hunter2hunter2@git.example.com/repo.git",
                "git clone https://[redacted]@git.example.com/repo.git",
            ),
            (
                "redis://:Sup3rS3cret@cache:6379/0",
                "redis://[redacted]@cache:6379/0",
            ),
            (
                "https://TOKEN123@host.example/path",
                "https://[redacted]@host.example/path",
            ),
        ] {
            assert_eq!(redactor.redact(input), expected);
        }
        // An `@` further on is not a user part.
        let plain = "see https://example.com/users/a@b and mail me@example.com";
        assert_eq!(redactor.redact(plain), plain);
    }

    #[test]
    fn a_private_key_goes_whole_and_takes_nothing_else_with_it() {
        let redactor = Redactor::default();
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0123ABCD\n\nMIIEow+/abc=\nabc\n-----END RSA PRIVATE KEY-----";
        let text = format!("before\n{pem}\n(after)");
        let out = redactor.redact(&text);
        // Nothing of the block is left, and what follows it is on the line
        // it was on.
        assert_eq!(out.replace('\n', ""), "before[redacted](after)");
        assert_eq!(out.lines().count(), text.lines().count());
        assert_eq!(out.lines().last(), Some("(after)"));

        // The same key with its line breaks escaped, as inside JSON.
        let escaped = pem.replace('\n', "\\n");
        let out = redactor.redact(&format!("{{\"key\":\"{escaped}\"}}"));
        assert!(!out.contains("MIIEow"), "{out}");

        // A key cut off before its end marker is still removed, and what
        // comes after it is still there.
        let out = redactor.redact(
            "before\n-----BEGIN PRIVATE KEY-----\nMIIEow+/abc\n\n{\"command\":\"rm -rf build\"}",
        );
        assert!(!out.contains("MIIEow"), "{out}");
        assert!(out.ends_with("{\"command\":\"rm -rf build\"}"), "{out}");

        // The marker alone, as in code that parses keys, costs only itself.
        let out = redactor.redact(
            "if pem.starts_with(\"-----BEGIN PRIVATE KEY-----\") { parse(pem) } else { fail() }",
        );
        assert_eq!(
            out,
            "if pem.starts_with(\"[redacted]\") { parse(pem) } else { fail() }"
        );
    }

    #[test]
    fn assignments_to_secret_names_lose_their_value() {
        let redactor = Redactor::default();
        for (input, expected) in [
            // Variables, as `env` prints them and as a shell sets them.
            (
                "DB_PASSWORD=correct-horse-battery",
                "DB_PASSWORD=[redacted]",
            ),
            (
                "export GITHUB_TOKEN=abcdefgh12345678",
                "export GITHUB_TOKEN=[redacted]",
            ),
            ("SMTP_PASS=Sup3rS3cretValue", "SMTP_PASS=[redacted]"),
            (
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG",
                "AWS_SECRET_ACCESS_KEY=[redacted]",
            ),
            (
                "STRIPE_SECRET_KEY='abc def'",
                "STRIPE_SECRET_KEY='[redacted]'",
            ),
            ("PGPASSWORD=dev1234", "PGPASSWORD=[redacted]"),
            ("GH_PAT=abc", "GH_PAT=[redacted]"),
            (
                "ENCRYPTION_KEY=Tr0ub4dor&3xyzzy!",
                "ENCRYPTION_KEY=[redacted]",
            ),
            (
                "docker run -e DB_PASS=hunter2 -e MODE=fast img",
                "docker run -e DB_PASS=[redacted] -e MODE=fast img",
            ),
            // Fields in config files and in code, when the value is a literal.
            ("api_key: \"abcdefgh12345678\"", "api_key: \"[redacted]\""),
            (
                "\"client_secret\": \"abcdefgh12345678\"",
                "\"client_secret\": \"[redacted]\"",
            ),
            (
                "\"clientSecret\": \"x\"",
                "\"clientSecret\": \"[redacted]\"",
            ),
            ("accessToken = 'abc'", "accessToken = '[redacted]'"),
            ("password: \"hunter2!hunter2\"", "password: \"[redacted]\""),
            (
                "\"password\": \"P@ss!word#2024\"",
                "\"password\": \"[redacted]\"",
            ),
            (
                "POSTGRES_PASSWORD: \"Pg!2024secret\"",
                "POSTGRES_PASSWORD: \"[redacted]\"",
            ),
            (
                "  db_password: Tr0ub4dor&3xyzzy",
                "  db_password: [redacted]",
            ),
            ("password=hunter", "password=[redacted]"),
            (
                "https://x.example/y?api_key=abcd1234&z=1",
                "https://x.example/y?api_key=[redacted]",
            ),
            ("_authToken=npm_abcdef", "_authToken=[redacted]"),
            ("secret: s3cr3t,", "secret: [redacted],"),
        ] {
            assert_eq!(redactor.redact(input), expected, "{input}");
        }
    }

    #[test]
    fn ordinary_code_and_text_are_left_alone() {
        let redactor = Redactor::default();
        for input in [
            "let token = parse(input);",
            "fn password_is_valid(password: &str) -> bool",
            "tokens: 1234",
            "max_tokens = 4096",
            "token: self.token.clone()",
            "password: user.password_hash,",
            "api_key: config.api_key.clone(),",
            "token = TokenKind::Identifier",
            "secret: std::env::var(\"SECRET\")",
            "password=os.environ['DB_PASSWORD']",
            "Self { token, password: password }",
            "api_key: ${API_KEY}",
            "DB_PASSWORD=$DB_PASSWORD",
            "use_token: true",
            "password: None",
            "PWD=/srv/work/project",
            "PATH=/usr/bin:/bin",
            "MODE=fast KEYBOARD=us",
            "\"key\": \"ArrowLeft\"",
            "primary_key: \"user_id\"",
            "note: nothing to hide here",
            "https://example.com/a/b?page=2",
            "error: no such file",
        ] {
            assert_eq!(redactor.redact(input), input);
        }
        // What was redacted once is not redacted into something else.
        for input in [
            "password: \"hunter2\"",
            "DB_PASS=abc secret: s3cr3t, api_key='x y'",
        ] {
            let once = redactor.redact(input);
            assert_ne!(once, input);
            assert_eq!(redactor.redact(&once), once);
        }
    }

    #[test]
    fn a_value_that_is_not_closed_or_very_long_goes_to_its_end() {
        let redactor = Redactor::default();
        // A quote that never closes: the value is the rest of the line.
        assert_eq!(
            redactor.redact("password: \"hunter2 and more\nnext line"),
            "password: \"[redacted]\nnext line"
        );
        // An escaped quote does not end the value.
        assert_eq!(
            redactor.redact(r#"secret = "a\"b c" # kept"#),
            r#"secret = "[redacted]" # kept"#
        );
        // A value longer than what is looked at to judge it goes whole.
        let long = "Z9".repeat(2_000);
        assert_eq!(
            redactor.redact(&format!("API_TOKEN={long} tail")),
            "API_TOKEN=[redacted] tail"
        );
        assert_eq!(
            redactor.redact(&format!("auth_token: \"{long}\", next")),
            "auth_token: \"[redacted]\", next"
        );
    }

    #[test]
    fn hostile_text_costs_time_in_proportion_to_its_length() {
        let redactor = Redactor::new([("SOME_KEY", KEY)], Vec::<(String, String)>::new(), &[]);
        let time = |text: &str| {
            let started = std::time::Instant::now();
            assert!(!redactor.redact(text).is_empty());
            started.elapsed()
        };
        // One token with an assignment at every other character, each of
        // which is left alone or looked into: no recursion, no rescanning.
        // Eight times the text may take eight times as long, not sixty-four.
        for unit in [
            "a:",
            "token:(",
            "x=",
            "password::",
            "k:\"",
            "secret:'",
            "token: a = ",
            "-----BEGIN PRIVATE KEY-----",
            "Cookie: ",
            "Cookie: f( ",
            "TOKEN = <<EOF\n",
            "password: <<EOF\nx\n",
            "x Cookie: 'a ",
            "-----BEGIN PRIVATE KEY-----\n",
            "-----BEGIN PRIVATE KEY-----aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "a://b:c",
            "token: T = a(",
            "--password ",
            "password=a b\n",
        ] {
            let small = time(&unit.repeat(80_000 / unit.len()));
            let large = time(&unit.repeat(640_000 / unit.len()));
            assert!(
                large < small * 24 + std::time::Duration::from_millis(250),
                "{unit:?}: {small:?} for 80 kB, {large:?} for 640 kB"
            );
        }
    }

    #[test]
    fn a_heredoc_that_never_closes_costs_what_a_line_that_opens_none_costs() {
        let redactor = Redactor::default();
        let time = |text: &str| {
            let started = std::time::Instant::now();
            let _ = redactor.redact(text);
            started.elapsed()
        };
        // Its end is looked up, not searched for: a search capped at 64 kB
        // for every opener would make the first far slower than the second.
        let _ = time("TOKEN = <<EOF\n");
        for (unit, control) in [
            ("TOKEN = <<EOF\n", "TOKEN = <<E-F\n"),
            ("password: <<EOF\nx\n", "password: <<E-F\nx\n"),
        ] {
            let heredocs = time(&unit.repeat(160_000 / unit.len()));
            let plain = time(&control.repeat(160_000 / control.len()));
            assert!(
                heredocs < plain * 4 + std::time::Duration::from_millis(250),
                "{unit:?}: {heredocs:?} against {plain:?}"
            );
        }
    }

    #[test]
    fn tool_call_arguments_are_redacted_as_what_they_say() {
        let redactor = Redactor::new([("SOME_KEY", KEY)], Vec::<(String, String)>::new(), &[]);
        let arguments = serde_json::json!({
            "command": "export DB_PASS=\"abc def\" && echo -----BEGIN PRIVATE KEY-----\nMIIEow\n-----END PRIVATE KEY----- done",
            "env": {"API_TOKEN": "short", "note": "kept"},
            "files": [{"path": "a.txt", "content": format!("key is {KEY}")}],
            "count": 3
        })
        .to_string();
        let out = redactor.redact_json(&arguments);
        let value: serde_json::Value = serde_json::from_str(&out).expect("still JSON");
        // The two line breaks of the key are kept.
        assert_eq!(
            value["command"],
            "export DB_PASS=\"[redacted]\" && echo [redacted]\n\n done"
        );
        assert_eq!(value["env"]["API_TOKEN"], REDACTED);
        assert_eq!(value["env"]["note"], "kept");
        assert_eq!(value["files"][0]["content"], "key is [redacted]");
        assert_eq!(value["count"], 3);

        // Not JSON: redacted as text.
        assert_eq!(
            redactor.redact_json(&format!("not json {KEY}")),
            "not json [redacted]"
        );
    }

    #[test]
    fn a_private_key_goes_however_it_is_written() {
        let redactor = Redactor::default();
        let body = [
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj",
            "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu",
            "Zw==",
        ];
        let begin = "-----BEGIN PRIVATE KEY-----";
        let end = "-----END PRIVATE KEY-----";
        let gone = |text: &str| {
            let out = redactor.redact(text);
            for line in body {
                assert!(!out.contains(line), "{line} survived in:\n{out}");
            }
            assert_eq!(out.lines().count(), text.lines().count(), "{out}");
            out
        };

        // String literals joined together.
        let literal = format!(
            "let key = \"{begin}\\n\" +\n    \"{}\\n\" +\n    \"{}\\n\" +\n    \"{}\\n\" +\n    \"{end}\\n\";\nnext();",
            body[0], body[1], body[2]
        );
        assert!(gone(&literal).ends_with("\nnext();"));

        // A diff that removes the key, one that adds it, and a quotation.
        for mark in ["-", "+", "> ", "    "] {
            let lines: Vec<String> = [begin, body[0], body[1], body[2], end]
                .iter()
                .map(|line| format!("{mark}{line}"))
                .collect();
            let text = format!("before\n{}\nafter", lines.join("\n"));
            assert!(gone(&text).ends_with("\nafter"), "{mark:?}");
        }

        // Cut off before its end marker: the body goes as far as it looks
        // like one, in a diff too, and the text after it stays.
        for mark in ["", "-", "+"] {
            let text = format!(
                "{mark}{begin}\n{mark}{}\n{mark}{}\n\nThe next paragraph.",
                body[0], body[1]
            );
            assert!(gone(&text).ends_with("The next paragraph."), "{mark:?}");
        }

        // An end marker far away belongs to another block.
        let far = format!(
            "{begin} is how a key starts.\n{}\n{end}",
            "x\n".repeat(KEY_SPAN)
        );
        let out = redactor.redact(&far);
        assert!(
            out.starts_with("[redacted] is how a key starts.\nx\n"),
            "{}",
            &out[..60]
        );

        // Words after a marker are not a key.
        assert_eq!(
            redactor.redact(&format!("{begin} is the marker to look for in a file")),
            "[redacted] is the marker to look for in a file"
        );
    }

    #[test]
    fn a_value_that_cannot_be_known_is_not_one() {
        // A blank setting, a URL setting that is no URL, and environment
        // values without a letter or a digit: none of them is replaced, and
        // none of them takes the text apart.
        let redactor = Redactor::new(
            [
                ("OVH_BASE_URL", ""),
                ("OTHER_BASE_URL", " "),
                ("THIRD_BASE_URL", "x"),
                ("SOME_KEY", KEY),
            ],
            env(&[("INDENT", "        "), ("RULE", "----------")]),
            &[],
        );
        let text = "fn main() {\n        let x = 1; // ----------\n}";
        assert_eq!(redactor.redact(text), text);
        assert_eq!(redactor.redact(KEY), REDACTED);
    }

    #[test]
    fn what_shai_exports_of_its_own_config_is_not_hidden() {
        let url = "https://llm.example.com/v1";
        let redactor = Redactor::new(
            [("OVH_BASE_URL", url), ("OVH_API_KEY", KEY)],
            env(&[
                ("OVH_BASE_URL", url),
                ("OVH_API_KEY", KEY),
                ("SHAI_MODEL", "gpt-4o-mini-2024"),
                ("SHAI_PROVIDER", "ovhcloud-ai"),
                ("LC_SECRET_TOKEN", "en_US.UTF-8-not-a-locale"),
            ]),
            &[],
        );
        let text = format!("POST {url}/chat with gpt-4o-mini-2024 on ovhcloud-ai");
        assert_eq!(redactor.redact(&text), text);
        assert_eq!(redactor.redact(&format!("key {KEY}")), "key [redacted]");
        // A locale variable is plain, unless its name says otherwise.
        assert_eq!(redactor.redact("en_US.UTF-8-not-a-locale"), REDACTED);
    }

    #[test]
    fn the_query_of_a_url_setting_is_known_as_it_is_written_too() {
        let redactor = Redactor::new(
            [("X_BASE_URL", "https://h.example/v1?sig=a%2Fb%2Bc9zz")],
            Vec::<(String, String)>::new(),
            &[],
        );
        for form in ["a%2Fb%2Bc9zz", "a/b+c9zz"] {
            assert_eq!(redactor.redact(&format!("x {form} y")), "x [redacted] y");
        }
    }

    #[test]
    fn a_known_value_of_several_lines_keeps_the_line_count() {
        let secret = "first line of it\nsecond line of it";
        let redactor = Redactor::new([("SOME_KEY", secret)], Vec::<(String, String)>::new(), &[]);
        assert_eq!(
            redactor.redact(&format!("a\n{secret}\nlast")),
            "a\n[redacted]\n\nlast"
        );
    }

    #[test]
    fn text_cut_inside_a_known_value_loses_what_is_left_of_it() {
        let redactor = Redactor::new([("SOME_KEY", KEY)], Vec::<(String, String)>::new(), &[]);
        let cut = format!("line\nheader: {}", &KEY[..KEY.len() - 5]);
        assert_eq!(redactor.redact_truncated(&cut), "line\nheader: [redacted]");
        assert_eq!(redactor.redact_truncated("nothing cut"), "nothing cut");
        // A beginning too short to tell from ordinary text stays.
        assert_eq!(redactor.redact_truncated("the ovh"), "the ovh");
    }

    #[test]
    fn operators_of_more_than_one_character_are_read_whole() {
        let redactor = Redactor::default();
        for (input, expected) in [
            ("apiKey := \"abc\"", "apiKey := \"[redacted]\""),
            ("SECRET_KEY ?= abc123", "SECRET_KEY ?= [redacted]"),
            ("'password' => 'hunter2'", "'password' => '[redacted]'"),
            (
                "if password == \"hunter2\" {",
                "if password == \"[redacted]\" {",
            ),
            ("assert token != 'abc123'", "assert token != '[redacted]'"),
        ] {
            assert_eq!(redactor.redact(input), expected, "{input}");
        }
        // A comparison with something that is not a literal, a path, and a
        // function are not assignments.
        for input in [
            "if token == expected {",
            "if token === other.token {",
            "password !== confirmation",
            "token =~ /^[a-z]+$/",
            "password := os.Getenv(\"DB_PASSWORD\")",
            "token => token.trim()",
            "secret::Key",
        ] {
            assert_eq!(redactor.redact(input), input);
        }
    }

    #[test]
    fn typed_declarations_and_prefixed_literals_lose_their_value() {
        let redactor = Redactor::default();
        for (input, expected) in [
            (
                "SECRET_KEY: str = \"abc\"",
                "SECRET_KEY: str = \"[redacted]\"",
            ),
            (
                "const API_KEY: &str = \"abc\";",
                "const API_KEY: &str = \"[redacted]\";",
            ),
            (
                "const apiKey: string = \"abc\"",
                "const apiKey: string = \"[redacted]\"",
            ),
            (
                "static TOKEN: &'static [u8] = b\"abc\";",
                "static TOKEN: &'static [u8] = b\"[redacted]\";",
            ),
            (
                "val password: String = \"hunter2\"",
                "val password: String = \"[redacted]\"",
            ),
            (
                "def f(password: str = \"default-pw\", n: int = 3):",
                "def f(password: str = \"[redacted]\", n: int = 3):",
            ),
            ("secret = b\"abc\"", "secret = b\"[redacted]\""),
            ("token = r'abc'", "token = r'[redacted]'"),
            ("password = f\"abc\"", "password = f\"[redacted]\""),
            ("password = @\"abc\";", "password = @\"[redacted]\";"),
            ("let token = r#\"abc\"#;", "let token = r#\"[redacted]\"#;"),
            (
                "config['password'] = 'hunter2'",
                "config['password'] = '[redacted]'",
            ),
            (
                "os.environ[\"API_KEY\"] = \"abc\"",
                "os.environ[\"API_KEY\"] = \"[redacted]\"",
            ),
            (
                "char password[] = \"abc\";",
                "char password[] = \"[redacted]\";",
            ),
            (
                "\"deploy\": \"API_TOKEN=\\\"abc 123\\\" ./deploy.sh\"",
                "\"deploy\": \"API_TOKEN=\\\"[redacted]\\\" ./deploy.sh\"",
            ),
        ] {
            assert_eq!(redactor.redact(input), expected, "{input}");
        }
        // A type is not a value, and a declaration without a literal has
        // nothing to hide.
        for input in [
            "const MAX_TOKENS: usize = 4096;",
            "max_tokens: u32,",
            "    password: String,",
            "    token: str",
            "SECRET_KEY: str",
            "let password: String = read_password()?;",
            "const token: string = process.env.TOKEN;",
            "token: Optional[str] = None,",
            "    password: impl Into<String>,",
        ] {
            assert_eq!(redactor.redact(input), input);
        }
    }

    #[test]
    fn variables_and_fields_of_config_files_lose_their_value() {
        let redactor = Redactor::default();
        for (input, expected) in [
            // Names of both lists, whichever sign follows.
            (
                "TS_AUTHKEY=tskey-auth-kABCDEF1CNTRL-0123456789",
                "TS_AUTHKEY=[redacted]",
            ),
            ("SIGNINGKEY=0123456789abcdef", "SIGNINGKEY=[redacted]"),
            (
                "DRIVER={ODBC Driver 17};SERVER=db;UID=sa;PWD=Hunter2!x",
                "DRIVER={ODBC Driver 17};SERVER=db;UID=sa;PWD=[redacted]",
            ),
            ("Uid=sa;Pwd=hunter2;", "Uid=sa;Pwd=[redacted];"),
            (
                "\"APP_KEY\": \"base64:abcdefghij0123456789==\"",
                "\"APP_KEY\": \"[redacted]\"",
            ),
            // Maps of a compose file or a manifest: one plain word is a
            // password there.
            (
                "    POSTGRES_PASSWORD: example",
                "    POSTGRES_PASSWORD: [redacted]",
            ),
            ("  MYSQL_PWD: hunter2", "  MYSQL_PWD: [redacted]"),
            ("password: changeme", "password: [redacted]"),
            (
                "- password: changeme # default",
                "- password: [redacted] # default",
            ),
            // A value of several words goes to the end of its line.
            (
                "passphrase: correct horse battery staple",
                "passphrase: [redacted]",
            ),
            (
                "SECRET_KEY=my secret phrase with spaces\nNEXT=1",
                "SECRET_KEY=[redacted]\nNEXT=1",
            ),
            (
                "db_password: Tr0ub4dor&3 and more  # rotate me",
                "db_password: [redacted]  # rotate me",
            ),
            // A quote inside a value does not end it.
            ("password=it's-me-123", "password=[redacted]"),
            ("db.password=pa\"ss'word1", "db.password=[redacted]"),
            // A token with dots in it is not a path through fields.
            (
                "bot_token: Zm9vYmFyYmF6cXV4.Ab3dEf.Gh1jKl2mNo3pQr4sTu5vWx6yZa7",
                "bot_token: [redacted]",
            ),
        ] {
            assert_eq!(redactor.redact(input), expected, "{input}");
        }
        // The command a variable is set for is not part of its value.
        assert_eq!(
            redactor.redact("DATABASE_PASSWORD=hunter2 ./manage.py migrate --noinput"),
            "DATABASE_PASSWORD=[redacted] ./manage.py migrate --noinput"
        );
        assert_eq!(
            redactor.redact("export GITHUB_TOKEN=abcdefgh12345678 && gh pr list"),
            "export GITHUB_TOKEN=[redacted] && gh pr list"
        );
    }

    #[test]
    fn references_in_code_keep_their_brackets_and_their_names() {
        let redactor = Redactor::default();
        for input in [
            "client = Client(api_key=settings.api_key)",
            "connect(user=user, password=password)",
            "connect(user=user, password=pw)",
            "User.create(email: email, password: password)",
            "login({username: u, password: p})",
            "let password = *ptr;",
            "let ok = !token;",
            "password = default",
            "pwd=$(pwd)",
            "PWD=~/work",
            "    token: token,",
            "headers: { Cookie: jar.get(url) }",
        ] {
            assert_eq!(redactor.redact(input), input);
        }
    }

    #[test]
    fn positions_in_files_are_not_assignments() {
        let redactor = Redactor::default();
        for input in [
            "src/lexer/token.rs:42: fn next(&mut self)",
            "src/auth/token.rs:120:7: the expiry is checked too late",
            "tokenizer.rs: off-by-one in peek, the last one is skipped",
            "app/models/password_reset.rb: uses a constant-time compare",
            "config/secrets:12: # managed by ops",
        ] {
            assert_eq!(redactor.redact(input), input);
        }
        // What stands on such a line is still read.
        assert_eq!(
            redactor.redact("src/credentials.rs:7: let password = \"hunter2\";"),
            "src/credentials.rs:7: let password = \"[redacted]\";"
        );
    }

    #[test]
    fn credential_headers_lose_their_whole_value() {
        let redactor = Redactor::default();
        for (input, expected) in [
            (
                "Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
                "Authorization: [redacted]",
            ),
            (
                "curl -H 'Authorization: ApiKey VnVhQ2ZHY0JDZGJr==' https://api.example.com",
                "curl -H 'Authorization: [redacted]' https://api.example.com",
            ),
            (
                "authorization: Basic dXNlcjpwYXNz",
                "authorization: [redacted]",
            ),
            (
                "Proxy-Authorization: Bearer abc:def-0123456789\nHost: x",
                "Proxy-Authorization: [redacted]\nHost: x",
            ),
            (
                "Set-Cookie: sessionid=0123456789abcdef; HttpOnly",
                "Set-Cookie: [redacted]",
            ),
            (
                "Cookie: session=abcdef0123456789; csrftoken=xyz",
                "Cookie: [redacted]",
            ),
            (
                "\"Authorization\": \"Token abcdef\"",
                "\"Authorization\": \"[redacted]\"",
            ),
        ] {
            let once = redactor.redact(input);
            assert_eq!(once, expected, "{input}");
            assert_eq!(redactor.redact(&once), once, "{input}");
        }
    }

    #[test]
    fn credentials_given_as_options_are_replaced() {
        let redactor = Redactor::default();
        for (input, expected) in [
            (
                "docker login -u me --password hunter2 registry.example.com",
                "docker login -u me --password [redacted] registry.example.com",
            ),
            (
                "tool --api-key \"abc def\" --verbose",
                "tool --api-key \"[redacted]\" --verbose",
            ),
            ("cli --token 'abc' run", "cli --token '[redacted]' run"),
            (
                "curl -u admin:hunter2 https://example.com",
                "curl -u admin:[redacted] https://example.com",
            ),
            (
                "curl --user \"admin:hunter2\" https://example.com",
                "curl --user \"admin:[redacted]\" https://example.com",
            ),
        ] {
            let once = redactor.redact(input);
            assert_eq!(once, expected, "{input}");
            assert_eq!(redactor.redact(&once), once, "{input}");
        }
        for input in [
            "docker login --password-stdin registry.example.com",
            "llm --max-tokens 4096 --model small",
            "docker run -u 1000:1000 image",
            "rsync -u host:/srv/data .",
            "git push -u origin main",
            "tool --token $TOKEN",
            "tool --password --other",
        ] {
            assert_eq!(redactor.redact(input), input);
        }
    }

    #[test]
    fn a_shape_does_not_reach_past_its_line_or_its_field() {
        let redactor = Redactor::default();
        for input in [
            // `basic` at the end of one line, a long word on the next.
            "auth:\n  type: basic\n  connection_timeout_seconds: 30\n  retries: 3",
            "examples/Dockerfile.basic\nexamples/Dockerfile.multi-stage",
            // An `@` in another field, in a query, in a mail address.
            "{\"url\":\"https://example.com\",\"user\":\"me@example.com\"}",
            "https://example.com?email=me@example.com",
            "see https://example.com/users/a@b and mail me@example.com",
        ] {
            assert_eq!(redactor.redact(input), input);
        }
        // A password with an `@` of its own goes whole.
        assert_eq!(
            redactor.redact("mysql://root:p@ss@host/db"),
            "mysql://[redacted]@host/db"
        );
    }

    #[test]
    fn names_and_nested_values_of_tool_call_arguments_are_redacted() {
        let redactor = Redactor::new([("SOME_KEY", KEY)], Vec::<(String, String)>::new(), &[]);
        let arguments = serde_json::json!({
            "headers": {KEY: "on"},
            "passwords": ["hunter2", "opensesame"],
            "secrets": {"db": "hunter2", "port": 5432},
            "env": {"GH_PAT": "abc", "MODE": "fast"},
        })
        .to_string();
        let out = redactor.redact_json(&arguments);
        assert!(!out.contains(KEY) && !out.contains("hunter2"), "{out}");
        let value: serde_json::Value = serde_json::from_str(&out).expect("still JSON");
        assert_eq!(value["headers"][REDACTED], "on");
        assert_eq!(value["passwords"], serde_json::json!([REDACTED, REDACTED]));
        assert_eq!(value["secrets"]["db"], REDACTED);
        assert_eq!(value["secrets"]["port"], 5432);
        assert_eq!(value["env"]["GH_PAT"], REDACTED);
        assert_eq!(value["env"]["MODE"], "fast");
    }

    #[test]
    fn redacting_twice_changes_nothing_more() {
        let redactor = Redactor::new([("SOME_KEY", KEY)], Vec::<(String, String)>::new(), &[]);
        for input in [
            "password: \"hunter2\"",
            "DB_PASS=abc secret: s3cr3t, api_key='x y'",
            "SECRET_KEY=my secret phrase with spaces",
            "passphrase: correct horse battery staple",
            "const API_KEY: &str = \"abc\";",
            "secret: s3cr3t,",
            "connect(password=s3cr3t)",
            "mysql://root:p@ss@host/db",
            "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n",
            &format!("key {KEY} and {{\"token\":\"x\",\"n\":1}}"),
        ] {
            let once = redactor.redact(input);
            assert_ne!(once, input);
            assert_eq!(redactor.redact(&once), once, "{input}");
        }
    }

    #[test]
    fn a_cut_does_not_go_through_a_value_that_is_there_in_full() {
        let known = |values: &[&'static str]| {
            Redactor::new(
                values.iter().map(|value| ("SOME_KEY", *value)),
                Vec::<(String, String)>::new(),
                &[],
            )
        };
        // A value that ends the way it begins, there in full at the cut.
        for value in ["hunter2hunter2", "adminadmin", "abcd-1234-abcd"] {
            let redactor = known(&[value]);
            assert_eq!(
                redactor.redact_truncated(&format!("the password is {value}")),
                "the password is [redacted]",
                "{value}"
            );
        }
        // A value that ends the way another one begins.
        let redactor = known(&[KEY, "cdef-other-secret-value"]);
        assert_eq!(
            redactor.redact_truncated(&format!("line\nkey: {KEY}")),
            "line\nkey: [redacted]"
        );
        // A value in full, followed by the beginning of itself.
        let out = known(&["hunter2hunter2"]).redact_truncated("see hunter2hunter2hunt");
        assert!(!out.contains("hunter2"), "{out}");
        // A value that begins like a shorter one, cut after that beginning.
        let redactor = known(&["abcdefgh", "abcdefgh-and-more"]);
        assert_eq!(
            redactor.redact_truncated("x abcdefgh-and-m"),
            "x [redacted]"
        );
    }

    #[test]
    fn a_plain_word_in_a_string_is_a_password_and_in_a_call_a_variable() {
        let redactor = Redactor::default();
        for (input, expected) in [
            (
                "Server=db;Database=app;User Id=myUsername;Password=myPassword;",
                "Server=db;Database=app;User Id=myUsername;Password=[redacted];",
            ),
            (
                "conn = psycopg2.connect(\"dbname=test user=postgres password=secret\")",
                "conn = psycopg2.connect(\"dbname=test user=postgres password=[redacted]\")",
            ),
            (
                "echo \"password=changeme\" > .env",
                "echo \"password=[redacted]\" > .env",
            ),
            (
                "curl -d \"grant_type=password&username=bob&password=hunter\" https://x.example/token",
                "curl -d \"grant_type=password&username=bob&password=[redacted]\" https://x.example/token",
            ),
            (
                "terraform apply -var 'db_password=changeme'",
                "terraform apply -var 'db_password=[redacted]'",
            ),
            ("password=hunter;", "password=[redacted];"),
            ("db.password=!Passw0rd1", "db.password=[redacted]"),
            (
                "https://x.example/login?user=a&password=!Passw0rd1",
                "https://x.example/login?user=a&password=[redacted]",
            ),
            ("password=*Secret123*", "password=[redacted]"),
        ] {
            assert_eq!(redactor.redact(input), expected, "{input}");
        }
        for input in [
            "connect(user=user, password=pw)",
            "f(password=pw);",
            "a[password=pw]",
            "let password = *ptr;",
            "let ok = !token;",
        ] {
            assert_eq!(redactor.redact(input), input);
        }
    }

    #[test]
    fn a_value_goes_whole_when_a_part_of_it_was_replaced_before() {
        let redactor = Redactor::new(
            [("SMTP_USER", "mailer@example.com")],
            Vec::<(String, String)>::new(),
            &[],
        );
        for (input, expected) in [
            (
                "S3_CREDENTIALS=AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "S3_CREDENTIALS=[redacted]",
            ),
            (
                "API_KEYS=sk-aaaaaaaaaaaaaaaaaaaaaaaa,custom-key-123456",
                "API_KEYS=[redacted]",
            ),
            (
                "password: \"sk-abcdefghijklmnopqrstuvwx and the rest\"",
                "password: \"[redacted]\"",
            ),
            (
                "SMTP_AUTH=mailer@example.com:Sup3rS3cret!",
                "SMTP_AUTH=[redacted]",
            ),
            (
                "\"password\": \"mailer@example.com:Sup3rS3cret!\"",
                "\"password\": \"[redacted]\"",
            ),
            (
                "  db_password: mailer@example.com-and-more",
                "  db_password: [redacted]",
            ),
            (
                "Authorization: sk-abcdefghijklmnopqrstuvwx and-more",
                "Authorization: [redacted]",
            ),
        ] {
            let once = redactor.redact(input);
            assert_eq!(once, expected, "{input}");
            assert_eq!(redactor.redact(&once), once, "{input}");
        }
    }

    #[test]
    fn a_key_without_its_end_goes_as_far_as_its_lines_do() {
        let redactor = Redactor::default();
        let begin = "-----BEGIN PRIVATE KEY-----";
        let body = [
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj",
            "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu",
        ];
        let gone = |text: &str| {
            let out = redactor.redact(text);
            for line in body {
                assert!(!out.contains(line), "{line} survived in:\n{out}");
            }
            assert_eq!(out.lines().count(), text.lines().count(), "{out}");
            out
        };
        // As a file-reading tool shows it: numbered, with something in front
        // of every line, and cut before the end of the key.
        let shown = format!(
            "   1: 3f2a9c1d {begin}\n   2: 9c1d77ab {}\n   3: 77ab0e1f {}\n\n(Showing lines 1-3 of 28.)",
            body[0], body[1]
        );
        assert!(gone(&shown).ends_with("\n\n(Showing lines 1-3 of 28.)"));
        // Inside JSON, with the line breaks escaped: what closes the string
        // stays.
        let json = format!("{{\"key\":\"{begin}\\n{}\\n{}\"}}", body[0], body[1]);
        assert_eq!(gone(&json), "{\"key\":\"[redacted]\"}");
        // Cut off by something that puts its mark right behind the text.
        let cut = format!("{begin}\n{}\n{}…[truncated]", body[0], body[1]);
        assert_eq!(gone(&cut), "[redacted]\n\n…[truncated]");
        // String literals joined together.
        let literal = format!(
            "let key = \"{begin}\\n\" +\n    \"{}\\n\" +\n    \"{}\\n\" +\n    more();",
            body[0], body[1]
        );
        assert!(gone(&literal).ends_with("more();"));
        // On one line, without any break.
        let one_line = format!("{begin}{}{} and then text", body[0], body[1]);
        assert_eq!(gone(&one_line), "[redacted] and then text");
        // A long word or a path after a marker is not a key.
        for text in [
            format!("{begin}\nsee /usr/local/lib/python3/site-packages for more"),
            format!("{begin} marks an internationalization key"),
        ] {
            assert_eq!(redactor.redact(&text), text.replace(begin, REDACTED));
        }
    }

    #[test]
    fn a_password_in_a_url_may_hold_the_signs_of_a_url() {
        let redactor = Redactor::default();
        for (input, expected) in [
            (
                "postgres://user:pa#ss@host/db",
                "postgres://[redacted]@host/db",
            ),
            (
                "redis://:Sup3r?S3cret@cache:6379/0",
                "redis://[redacted]@cache:6379/0",
            ),
            (
                "amqp://guest:p@ss#w?rd@mq.internal:5672/vhost",
                "amqp://[redacted]@mq.internal:5672/vhost",
            ),
        ] {
            let once = redactor.redact(input);
            assert_eq!(once, expected, "{input}");
            assert_eq!(redactor.redact(&once), once, "{input}");
        }
        // A port is not a password, and an `@` in a query is not a host.
        for input in [
            "http://localhost:3000?email=me@example.com",
            "https://example.com:8443/path?x=a@b",
            "https://example.com:8443#me@example.com",
        ] {
            assert_eq!(redactor.redact(input), input);
        }
    }

    #[test]
    fn the_same_word_is_a_header_a_variable_or_a_file_by_what_follows() {
        let redactor = Redactor::default();
        for (input, expected) in [
            // A variable, not a header.
            ("export COOKIE=abc123def456", "export COOKIE=[redacted]"),
            (
                "COOKIE=sessionid=abc123def456 curl https://x.example",
                "COOKIE=[redacted] curl https://x.example",
            ),
            // What a file holds, not something about the file.
            (
                "stringData:\n  password.txt: hunter2hunter2\n  api-token.txt: abc123def",
                "stringData:\n  password.txt: [redacted]\n  api-token.txt: [redacted]",
            ),
            (
                "secrets/db_password.txt:hunter2hunter2",
                "secrets/db_password.txt:[redacted]",
            ),
            // A header as it is sent: the whole line, whatever it holds.
            (
                "Cookie: name=\"value with a quote\"; other=secret123",
                "Cookie: [redacted]",
            ),
            ("Cookie: $Version=1; session=abc", "Cookie: [redacted]"),
            // A header in a quotation: up to the quote that closes it.
            (
                "curl -H \"Cookie: a='b'; c=d\" https://x.example",
                "curl -H \"Cookie: [redacted]\" https://x.example",
            ),
            (
                "curl -H 'Accept: */*' -H 'Cookie: a=\"b\"; c=d' https://x.example",
                "curl -H 'Accept: */*' -H 'Cookie: [redacted]' https://x.example",
            ),
        ] {
            let once = redactor.redact(input);
            assert_eq!(once, expected, "{input}");
            assert_eq!(redactor.redact(&once), once, "{input}");
        }
    }

    #[test]
    fn two_words_before_a_sign_are_not_a_declaration() {
        let redactor = Redactor::default();
        for (input, expected) in [
            (
                "secret: abc123 expires = 2024-01-01",
                "secret: [redacted] expires = 2024-01-01",
            ),
            (
                "token: 5f3a9c1e2b (ttl = 3600s)",
                "token: [redacted] (ttl = 3600s)",
            ),
            // One word that is no type, and a literal: both go.
            (
                "password: hunter2 = \"x\"",
                "password: [redacted] = \"[redacted]\"",
            ),
            (
                "tool --password = hunter2 --verbose",
                "tool --password = [redacted] --verbose",
            ),
            ("(curl -u name:pw)", "(curl -u name:[redacted])"),
        ] {
            let once = redactor.redact(input);
            assert_eq!(once, expected, "{input}");
            assert_eq!(redactor.redact(&once), once, "{input}");
        }
        // The directory a shell is in, however it is written.
        for input in [
            "declare -x PWD=\"/home/user/project\"",
            "\"PWD\": \"/srv/work\"",
            "OLDPWD='~/other'",
        ] {
            assert_eq!(redactor.redact(input), input);
        }
    }

    #[test]
    fn options_of_an_endpoint_are_not_known_values() {
        let redactor = Redactor::new(
            [(
                "X_BASE_URL",
                "https://h.example/v1?api-version=2024-02-01&format=markdown&project_ref=abcdefghijklmnopqrst&key=s3cr3tvalue&sig=Zx9%2Bqq",
            )],
            Vec::<(String, String)>::new(),
            &[],
        );
        let text = "on 2024-02-01 the markdown of abcdefghijklmnopqrst";
        assert_eq!(redactor.redact(text), text);
        assert_eq!(redactor.redact("x s3cr3tvalue y"), "x [redacted] y");
        assert_eq!(
            redactor.redact("x Zx9+qq y Zx9%2Bqq z"),
            "x [redacted] y [redacted] z"
        );
    }

    #[test]
    fn a_long_line_after_a_key_marker_is_cut_between_characters() {
        let redactor = Redactor::default();
        // A header of an encrypted key on a line that is longer than what is
        // looked at, made of characters of two bytes, at both offsets.
        for lead in ["", "x"] {
            let text = format!(
                "-----BEGIN PRIVATE KEY-----{lead} Proc-Type: {}",
                "é".repeat(MAX_KEY_LINE)
            );
            let out = redactor.redact(&text);
            assert!(out.starts_with(REDACTED), "{lead:?}");
        }
    }

    #[test]
    fn a_known_value_is_found_in_the_forms_programs_write_it_in() {
        let redactor = Redactor::new(
            [
                ("SOME_API_KEY", "abc+def/ghi=jkl0123"),
                ("NUM_API_KEY", "1234567890123456"),
                ("MB_KEY", "clé-très-secrète-42"),
                ("AMP_KEY", "Tr0ub4dor&3xyz<>"),
            ],
            Vec::<(String, String)>::new(),
            &[],
        );
        for text in [
            "GET /search?q=abc%2Bdef%2Fghi%3Djkl0123 HTTP/1.1",
            "GET /search?q=abc%2bdef%2fghi%3djkl0123 HTTP/1.1",
            r#"{"k":"abc+def\/ghi=jkl0123"}"#,
            r#"{"k": "cl\u00e9-tr\u00e8s-secr\u00e8te-42"}"#,
            r#"{"k": "cl\u00E9-tr\u00E8s-secr\u00E8te-42"}"#,
            r#"["x=Tr0ub4dor\u00263xyz\u003c\u003e"]"#,
            "value=Tr0ub4dor&amp;3xyz&lt;&gt;",
            "q=Tr0ub4dor%263xyz%3C%3E",
            // .NET's default encoder: upper-case hex for `+`, `&`, `<`, `>`.
            r#"{"Key":"abc\u002Bdef/ghi=jkl0123"}"#,
            r#"{"k": "Tr0ub4dor\u00263xyz\u003C\u003E"}"#,
        ] {
            let out = redactor.redact(text);
            assert!(out.contains(REDACTED), "{text} -> {out}");
            for piece in ["jkl0123", "secr", "3xyz"] {
                assert!(
                    !out.contains(piece) || !text.contains(piece),
                    "{text} -> {out}"
                );
            }
        }
        // A number in the arguments of a tool call, however it is written.
        let out = redactor.redact_json(r#"{"pin": 1234567890123456, "count": 3}"#);
        assert_eq!(out, r#"{"count":3,"pin":"[redacted]"}"#);
        for number in [
            "-1234567890123456",
            "1234567890123456.0",
            "1.234567890123456e15",
            "12345678901234560",
            "1234567890123456e5",
            "-1.234567890123456e25",
        ] {
            let out = redactor.redact_json(&format!(r#"{{"pin": {number}}}"#));
            assert!(!out.contains("1234567890123456"), "{number} -> {out}");
        }
    }

    #[test]
    fn pgp_and_putty_private_keys_go_whole() {
        let redactor = Redactor::default();
        let pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\nlQOYBF8xQ0kBCADC2J3vZk9pQf8Yk1sQ0+M3s2YbR7rT5Z6H2l9d0wVxq4n1Kp8J\nq0n6e4cXv2Q1r9Wf7a3h5k2Lm8d4Pz1sT6uV0yX3bN9cR5gH7jK2lM4nP6qS8tU0\n=Xy1Z\n-----END PGP PRIVATE KEY BLOCK-----\nafter";
        let out = redactor.redact(pgp);
        assert!(!out.contains("lQOYBF8") && !out.contains("q0n6e4"), "{out}");
        assert_eq!(out.lines().count(), pgp.lines().count());
        assert!(out.ends_with("\nafter"));
        // Without its end marker, as a listing cut short shows it.
        let cut = "-----BEGIN PGP SECRET KEY BLOCK-----\nVersion: 1\n\nlQOYBF8xQ0kBCADC2J3vZk9pQf8Yk1sQ0+M3s2YbR7rT5Z6H2l9d0wVxq4n1Kp8J\n";
        assert!(!redactor.redact(cut).contains("lQOYBF8"));

        // As a listing shows it, with numbered lines.
        for lead in ["-", "+", "key.ppk:12:"] {
            let text = format!(
                "{lead}Private-Lines: 1\n{lead}AAABAQCs0123456789abcdef\n{lead}Private-MAC: 0a1b"
            );
            assert!(!redactor.redact(&text).contains("AAABAQCs"), "{lead}");
        }
        let listed = "   7: 3f2a9c1d Private-Lines: 2\n   8: 9c1d77ab AAABAQCs0123456789abcdef\n   9: 77ab0e1f AAAAgQDabcdef0123456789\n  10: 0e1f2a3b Private-MAC: 0a1b";
        let out = redactor.redact(listed);
        assert!(
            !out.contains("AAABAQCs") && !out.contains("AAAAgQD"),
            "{out}"
        );
        let putty = "PuTTY-User-Key-File-2: ssh-rsa\nPublic-Lines: 1\nAAAAB3NzaC1yc2E\nPrivate-Lines: 2\nAAABAQCs0123456789abcdef\nAAAAgQDabcdef0123456789\nPrivate-MAC: 0a1b2c\n";
        let out = redactor.redact(putty);
        assert!(
            !out.contains("AAABAQCs") && !out.contains("AAAAgQD"),
            "{out}"
        );
        assert!(out.contains("Public-Lines: 1\nAAAAB3NzaC1yc2E\n"), "{out}");
        assert!(out.contains("\nPrivate-MAC: 0a1b2c"), "{out}");
        assert_eq!(out.lines().count(), putty.lines().count());
    }

    #[test]
    fn assignments_inside_escaped_json_lose_their_value() {
        let redactor = Redactor::default();
        for (input, expected) in [
            (
                r#"String body = "{\"username\":\"bob\",\"password\":\"hunter22\"}";"#,
                r#"String body = "{\"username\":\"bob\",\"password\":\"[redacted]\"}";"#,
            ),
            (
                r#"level=info body="{\"token\":\"abcd1234efgh\",\"user\":\"bob\"}""#,
                r#"level=info body="{\"token\":\"[redacted]\",\"user\":\"bob\"}""#,
            ),
            (
                r#"{\\\"password\\\":\\\"hunter 22 more\\\"}"#,
                r#"{\\\"password\\\":\\\"[redacted]\\\"}"#,
            ),
            (
                r#""{\"Cookie\":\"session=abc123def\"}""#,
                r#""{\"Cookie\":\"[redacted]\"}""#,
            ),
        ] {
            let once = redactor.redact(input);
            assert_eq!(once, expected, "{input}");
            assert_eq!(redactor.redact(&once), once, "{input}");
        }
        for input in [
            r#"msg = "the \"token\" field is required""#,
            r#""\"password\": \"\"""#,
        ] {
            assert_eq!(redactor.redact(input), input);
        }
        // Time in proportion to the length, whatever the backslashes.
        let text = format!("password:{}\"{}", "\\".repeat(64_000), "\\".repeat(192_000));
        let started = std::time::Instant::now();
        let _ = redactor.redact(&text);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn keys_of_accounts_and_services_are_credentials() {
        let redactor = Redactor::default();
        for (input, expected) in [
            (
                "DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;EndpointSuffix=core.windows.net",
                "DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey=[redacted];EndpointSuffix=core.windows.net",
            ),
            ("account_key: Eby8vdM02xNOcq", "account_key: [redacted]"),
            (
                "    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ",
                "    client-key-data: [redacted]",
            ),
            (
                "Ocp-Apim-Subscription-Key: 0123456789abcdef0123456789abcdef",
                "Ocp-Apim-Subscription-Key: [redacted]",
            ),
            ("X-Auth: Sup3rS3cretPw", "X-Auth: [redacted]"),
            (
                "X-Auth-Key: c2547eb745079dac9320b638f5e225cf483cc5cfdda41",
                "X-Auth-Key: [redacted]",
            ),
        ] {
            assert_eq!(redactor.redact(input), expected, "{input}");
        }
        for input in [
            "primary_key: \"user_id\"",
            "sort_key: \"created_at\"",
            "let cache_key = format!(\"{id}\");",
        ] {
            assert_eq!(redactor.redact(input), input);
        }
    }

    #[test]
    fn credentials_handed_over_by_calls_and_markup_lose_their_value() {
        let redactor = Redactor::default();
        for (input, expected) in [
            (
                "define( 'DB_PASSWORD', 'Sup3rS3cretPw' );",
                "define( 'DB_PASSWORD', '[redacted]' );",
            ),
            (
                "os.Setenv(\"API_TOKEN\", \"abcd1234efgh5678\")",
                "os.Setenv(\"API_TOKEN\", \"[redacted]\")",
            ),
            (
                "System.setProperty(\"javax.net.ssl.keyStorePassword\", \"Sup3rS3cretPw\");",
                "System.setProperty(\"javax.net.ssl.keyStorePassword\", \"[redacted]\");",
            ),
            (
                "ds.setPassword(\"Sup3rS3cretPw\");",
                "ds.setPassword(\"[redacted]\");",
            ),
            (
                "<password>Sup3rS3cretPw</password>",
                "<password>[redacted]</password>",
            ),
            (
                "<add key=\"Password\" value=\"Sup3rS3cretPw\" />",
                "<add key=\"Password\" value=\"[redacted]\" />",
            ),
            (
                "ALTER USER bob IDENTIFIED BY 'Sup3rS3cretPw';",
                "ALTER USER bob IDENTIFIED BY '[redacted]';",
            ),
            (
                "CREATE USER bob WITH PASSWORD 'Sup3rS3cretPw';",
                "CREATE USER bob WITH PASSWORD '[redacted]';",
            ),
            (
                "CREATE USER 'app'@'%' IDENTIFIED WITH caching_sha2_password BY 'Sup3r''s3cret';",
                "CREATE USER 'app'@'%' IDENTIFIED WITH caching_sha2_password BY '[redacted]';",
            ),
            (
                "define('DB_PASSWORD', \"it's-a-s3cret\");",
                "define('DB_PASSWORD', \"[redacted]\");",
            ),
            (
                "headers.put(\"X-Api-Key\", \"abcd1234efgh5678\");",
                "headers.put(\"X-Api-Key\", \"[redacted]\");",
            ),
            (
                "<add key=\"Password\" type=\"string\" value=\"Sup3rS3cretPw\" />",
                "<add key=\"Password\" type=\"string\" value=\"[redacted]\" />",
            ),
            (
                "ALTER USER bob IDENTIFIED BY 'it\\'s-Sup3rS3cret';",
                "ALTER USER bob IDENTIFIED BY '[redacted]';",
            ),
            (
                "<property name=\"hibernate.connection.password\">Sup3rS3cretPw</property>",
                "<property name=\"hibernate.connection.password\">[redacted]</property>",
            ),
            (
                "<property name=\"password\" value=\"Sup3rS3cretPw\"/>",
                "<property name=\"password\" value=\"[redacted]\"/>",
            ),
            (
                "<property value='Sup3rS3cretPw' name='password'/>",
                "<property value='[redacted]' name='password'/>",
            ),
            (
                "<entry key=\"db.password\">Sup3rS3cretPw</entry>",
                "<entry key=\"db.password\">[redacted]</entry>",
            ),
        ] {
            let once = redactor.redact(input);
            assert_eq!(once, expected, "{input}");
            assert_eq!(redactor.redact(&once), once, "{input}");
        }
        for input in [
            "define('WP_DEBUG', 'true');",
            "config.set(\"mode\", \"fast\")",
            "<name>project</name>",
            "<password>${env.DB_PASSWORD}</password>",
            "ds.setUrl(\"jdbc:postgresql://db/app\");",
            "throw new Error(\"Invalid password \" + attempts + \" attempts left\");",
        ] {
            assert_eq!(redactor.redact(input), input);
        }
    }

    #[test]
    fn a_value_written_as_a_block_of_lines_goes_whole() {
        let redactor = Redactor::default();
        for (input, expected) in [
            (
                "client_secret: |\n  9f8e7d6c5b4a39281706f5e4d3c2b1a0\n  second line\nnext: 1",
                "client_secret: [redacted]\n\n\nnext: 1",
            ),
            (
                "  password: >-\n    Sup3rS3cretPw\n\n  other: 2",
                "  password: [redacted]\n\n\n  other: 2",
            ),
            (
                "client_secret: | # rotate yearly\n  9f8e7d6c5b4a39281706\nnext: 1",
                "client_secret: [redacted]\n\nnext: 1",
            ),
            (
                "private_key: !!binary |\n  LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t\nnext: 1",
                "private_key: [redacted]\n\nnext: 1",
            ),
            (
                "private_key = <<EOF\nabcd1234efgh5678ijkl9012mnop3456\nEOF\nnext = 1",
                "private_key = [redacted]\n\nEOF\nnext = 1",
            ),
            (
                "private_key = <<-'EOT'\nabcd1234efgh5678ijkl9012mnop3456\nEOT\nnext = 1",
                "private_key = [redacted]\n\nEOT\nnext = 1",
            ),
            (
                "password: |\t# rotate\n  Sup3rS3cretPw\nnext: 1",
                "password: [redacted]\n\nnext: 1",
            ),
        ] {
            let once = redactor.redact(input);
            assert_eq!(once, expected, "{input}");
            assert_eq!(once.lines().count(), input.lines().count(), "{input}");
            assert_eq!(redactor.redact(&once), once, "{input}");
        }
        // A heredoc whose end is not there is not a heredoc, and an empty
        // block under a secret name takes no line with it.
        for input in ["token = <<EOF\nnever closed", "password: |\nnext: 1"] {
            let out = redactor.redact(input);
            assert!(
                out.ends_with("\nnever closed") || out.ends_with("\nnext: 1"),
                "{out}"
            );
        }
    }

    #[test]
    fn no_text_makes_the_redactor_fail() {
        // Pieces that the rules look for, next to characters of more than one
        // byte and to the ends of the text, put together in every order a
        // fixed sequence of numbers gives.
        let long = "x".repeat(300);
        let wide = "é".repeat(140);
        let wider = "日本".repeat(200);
        let pieces: &[&str] = &[
            "password",
            "TOKEN",
            "api_key",
            "Authorization",
            "Cookie",
            "secret.rs",
            "pwd",
            "é",
            "日本",
            "🦀",
            "\u{301}",
            "=",
            ":",
            ": ",
            " = ",
            ":=",
            "==",
            "=>",
            "::",
            "\"",
            "'",
            "\\\"",
            "\\",
            "\n",
            "\r\n",
            " ",
            "\t",
            "#",
            "//",
            ",",
            ";",
            ")",
            "]",
            "}",
            "(",
            "[",
            "{",
            "$",
            "&",
            "-",
            "--password ",
            "-u a:",
            "b\"",
            "r#\"",
            "str",
            "u32",
            "12:",
            "abc",
            "Tr0ub4dor&3",
            "[redacted]",
            "https://",
            "@",
            "/",
            "?",
            ".",
            "Bearer ",
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
            "Proc-Type: ",
            "Version: ",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "Private-Lines: 2\n",
            "<<EOF\n",
            "EOF",
            ": |\n",
            "  ",
            "define('DB_PASSWORD', '",
            "<password>",
            "</password>",
            "setPassword(\"",
            "IDENTIFIED BY '",
            "AccountKey=",
            ";Name=",
            "\\\"",
            "%2F",
            "&amp;",
            "\\u00e9",
            "DEK-Info: ",
            "export ",
            "- ",
            &long,
            &wide,
            &wider,
        ];
        let redactor = Redactor::new(
            [
                ("SOME_KEY", KEY),
                ("X_BASE_URL", "https://us€r:pä55word@h.example/?q=vàlue99"),
            ],
            env(&[("ODD", "ключ-значение"), ("LINES", "one line\nand another")]),
            &[],
        );
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = |below: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % below as u64) as usize
        };
        for _ in 0..4_000 {
            let mut text = String::new();
            for _ in 0..next(24) + 1 {
                text.push_str(pieces[next(pieces.len())]);
            }
            // None of these may panic, whatever they are given.
            let once = redactor.redact(&text);
            let _ = redactor.redact(&once);
            let _ = redactor.redact_truncated(&text);
            let _ = redactor.redact_json(&text);
            let _ = redactor
                .redact_json(&serde_json::json!({ text.as_str(): [text.as_str()] }).to_string());
            assert!(!once.contains(KEY), "{text:?}");
        }
    }

    #[test]
    fn debug_does_not_reveal_known_values() {
        let debug = format!("{:?}", redactor());
        assert!(debug.starts_with("Redactor(") && debug.ends_with(" known values)"));
        assert!(
            !debug.contains(KEY) && !debug.contains(ENV_TOKEN),
            "{debug}"
        );
    }
}
