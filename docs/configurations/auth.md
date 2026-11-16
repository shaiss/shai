# Auth Configuration

The auth configuration file stores provider credentials and LLM settings.

## Location

```
~/.config/shai/auth.config.json
```

Or via `XDG_CONFIG_HOME`:

```
$XDG_CONFIG_HOME/shai/auth.config.json
```

## Migration

Previous versions of Shai used `auth.config` (without `.json` extension). If `auth.config.json` does not exist, Shai will fall back to reading the legacy `auth.config` file automatically. No manual migration is needed.

## Schema

```jsonc
{
  "providers": [
    {
      "provider": "ovhcloud",
      "env_vars": {
        "OVH_API_KEY": "your-api-key"
      },
      "model": "qwen3-32b-instruct",
      "tool_method": "FunctionCall"
    }
  ],
  "selected_provider": 0,
  "mcp_configs": {},
  "roles": {
    "planner": "ovhcloud/another-model"
  },
  "prewalk": {
    "into": "planner"
  },
  "advisor": {
    "enabled": false
  }
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `providers` | [ProviderConfig](#providerconfig)[] | List of configured LLM providers |
| `selected_provider` | integer | Index into `providers` array for the active provider |
| `mcp_configs` | object&lt;string, object&gt; | MCP server configurations |
| `roles` | object&lt;string, string&gt; | Optional. Named secondary models, see [Roles](#roles) |
| `prewalk` | object | Optional. One-shot handoff to another model, see [Prewalk](#prewalk) |
| `advisor` | object | Optional. Second model that reviews the agent's steps, see [Advisor](#advisor) |

### ProviderConfig

| Field | Type | Description |
|-------|------|-------------|
| `provider` | string | Provider identifier (e.g. `"ovhcloud"`, `"openai"`, `"anthropic"`) |
| `env_vars` | object&lt;string, string&gt; | Environment variables passed to the provider (API keys, base URLs) |
| `model` | string | Model identifier |
| `tool_method` | string | Tool call method (`"Auto"`, `"FunctionCall"`, `"FunctionCallRequired"`, `"StructuredOutput"`) |

## Roles

A session runs on one primary model, the one `selected_provider` points to. The optional `roles` section names additional models that opt-in features can use next to it. Nothing uses a role unless a feature asks for it by name, so a config without `roles` behaves exactly as before.

```jsonc
{
  "providers": [
    // an "openai" entry and an "ollama" entry, added with `shai auth`
  ],
  "selected_provider": 0,
  "roles": {
    "planner": "openai/gpt-4o-mini",
    "cheap": "ollama/qwen3:8b"
  }
}
```

Each role is a `<provider>/<model>` string:

- `<provider>` must be the `provider` of an entry in `providers`. The role reuses that entry's `env_vars` (API key, base URL) and only changes the model. This is how you point a role at a second model of a provider you already configured, without entering its credentials again.
- `<model>` is everything after the first `/`, so model names that contain slashes work (`openrouter/anthropic/claude-sonnet-4`). It is limited to visible ASCII characters.
- Role names use lowercase letters, digits, `-` and `_`.

The rules are strict on purpose, so that a mistake does not quietly send a conversation to a model you did not pick:

- A role that is not listed is simply off.
- Roles only come from your own config file. The starter config Shai downloads on first run never carries any.
- A role is a string. It cannot hold credentials of its own; an object is rejected.
- A role that names a provider with no entry in `providers`, or whose reference is malformed, is an error when a feature tries to use it. Shai does not substitute the primary model, another provider, or the built-in default configuration.
- A role only reads the provider entry it names. Unlike the primary model, it does not pick a missing key or base URL up from your shell environment. Concretely, an entry of a provider that needs an API key must hold its own to back a role (so an `ovhcloud` entry without `OVH_API_KEY`, which uses anonymous access, cannot), and an `ollama` entry must hold its `OLLAMA_BASE_URL`; its `OLLAMA_API_KEY` stays optional.
- The reference must single out one way to reach the model. If entries of that provider are configured for exactly that model, one of those is used: they must be usable and agree with each other. Otherwise every entry of that provider must be usable and hold the same settings. If an entry of the provider you name cannot back a role, or two of them point at different endpoints, the reference is rejected rather than routed to whichever entry happens to work. In practice: if the keyless starter `ovhcloud` entry is still next to your own, remove it with `shai auth`, or name the model your own entry is configured for.
- If the `roles` section is not an object, if one of its keys is not a valid role name or appears twice, or if the file has two `roles` sections, every role is rejected until that is fixed.

Two limits to keep in mind:

- Resolving a role is offline. Shai does not ask the provider whether it serves the model, so a wrong model name shows up as that provider's error the first time the role is used. A role also inherits the entry's base URL: if that URL serves a single model, as OVHcloud's per-model endpoints do, name that model in the role.
- A wrong value inside `roles`, or a `roles` section written twice, does not stop the rest of the file from loading. A JSON syntax error does, in `roles` like anywhere else in the file, and so does a `roles` section that is not valid UTF-8 text. When the file cannot be read, the TUI and headless mode do not start a session (see [Prewalk](#prewalk)); `shai serve` and the shell assistant fall back to the built-in default, as they always have.

## Prewalk

Prewalk hands a session off to another model, once, while it is running. The session starts on the primary model. When the agent has a todo list **and** its first `write` or `edit` has succeeded, the next request goes to the target model instead, and so does every request after it. The usual use is to plan on a strong model and do the edits on a cheaper or local one.

It is off by default. Turn it on for one run with a flag, or for every session in the config:

```bash
shai --prewalk-into cheap                      # a role from "roles"
shai -p "fix the flaky test" --prewalk-into ollama/qwen3:8b
```

```jsonc
"prewalk": { "into": "cheap" }
```

The target is a role name or a `<provider>/<model>` reference and follows the same rules as [roles](#roles): it must resolve, offline, to a provider entry that holds its own credentials. The flag wins over the config.

What to expect:

- **A notice when it is armed and when it switches.** The TUI shows both in the conversation and updates the model in the status bar; headless mode prints one line on stderr for each.
- **Everything carries over.** The conversation so far, the todo list, the working directory and permissions are unchanged. Only the model that receives the next request changes. This also means the whole conversation so far, including the system prompt and everything tools returned, is sent to the target's provider.
- **It happens between two steps**, after all tool results of the step that contained the edit are in, never in the middle of a step. A failed or denied edit does not count. Without a todo list the session stays where it is until one exists.
- **Once.** After the switch the conversation stays on the target; nothing switches it back. In the TUI, an agent you start afterwards (another agent, a restored conversation, `/auth`) is a new agent on its own model, and prewalk does not move it: Shai says so with a `prewalk is over` line.
- **If the target cannot be resolved, the session does not start.** A role that is not configured, a provider with no entry, a `prewalk` section that is invalid or written twice: each is reported as an error and Shai exits with status 2 instead of running without the handoff. The error names a target taken from the config by its key (`prewalk.into`) and does not repeat its value, unless the value is the name of a role or provider that is configured. `--prewalk-into` on a command that starts no session (`shai serve`, `shai auth`, `shai --list-tools`, ...) is an error too. HTTP server mode does not use prewalk.
- **A config file that cannot be read stops the session as well.** If `auth.config.json` (or the legacy `auth.config`) exists and does not load, Shai cannot tell whether it asks for a handoff, so the TUI and headless mode exit with status 2 and say where the file is broken, without repeating what it holds, instead of running on the built-in default model as they did before. An agent the TUI starts later in the session (agent picker, restored session, `/auth`) follows the same rule: it is not started on the built-in default. No starter config is downloaded over such a file. `shai auth` and the other commands that start no session still work, and so does a first run with no config file at all.
- **An agent that could never trigger it is not armed.** The handoff needs the built-in `todo_write` tool and at least one of `write` and `edit`. If the agent's tools leave them out (`--tools`, `--remove`, a custom agent), Shai says `prewalk not armed` with the reason, in the same place as the armed notice, and the session runs on its own model. Tools of the same names served by an MCP server do not count.
- **The configuration is followed.** Each time the TUI starts an agent (after `/auth`, when you pick another agent, when you restore a conversation), a handoff that is still to come is resolved again against the configuration as it is then. If it no longer resolves, the handoff is given up with a `prewalk disarmed` line; it is never sent to credentials or an endpoint you have just removed.
- If the target's provider rejects the request after the switch (for example because the model name is wrong, or it does not accept the conversation another provider produced), that error is shown and the session stays on the target.

## Advisor

The advisor is a second model that looks over the agent's shoulder. After some of the agent's steps it is shown what the agent just did, and it may answer with one short note rated `nit`, `concern` or `blocker`. The agent sees the note at its next step and you see it too. It is advice: the agent weighs it, and nothing is approved, blocked or changed by it.

It is off by default and always runs on the model of the role named `advisor`:

```jsonc
"roles": { "advisor": "openai/gpt-4o-mini" },
"advisor": { "enabled": true, "max_calls": 10, "cooldown_turns": 2 }
```

```bash
shai --advisor                 # for one session, with the limits from the config or the defaults
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Run the advisor in every session. `--advisor` turns it on for one |
| `max_calls` | `10` | Most reviews in one session (1 to 10000) |
| `cooldown_turns` | `2` | Steps skipped after each review, so that it does not comment on every step (1 to 10000) |

What it can and cannot do:

- **It only reads, and only the working directory.** Its tools are `read`, `ls`, `find` and `grep`. This list is fixed in the code and is not the agent's toolbox: there is no `bash`, `write`, `edit` or `fetch` for it to call, and it cannot be given more by configuration. Paths are resolved, symlinks included, and refused if they leave the directory the session runs in. A path that points outside gets the same refusal whether or not anything is there.
- **It is kept away from secrets.** Three things work together, and none of them is a guarantee:
  - *Files it may not open.* Files that usually hold credentials are refused even inside the working directory: `.env` files and `.envrc` (templates such as `.env.example` stay readable), key and certificate files, `.netrc`, `.npmrc`, Terraform state and variables, shell histories, data files named after secrets, credentials or passwords (with or without a leading dot), the backup and editor copies of all of these (`.bak`, `.old`, `.orig`, `.swp`, `~`), and the `.git`, `.shai`, `.ssh`, `.aws`, `.kube` and similar folders. Below a folder named after secrets, credentials or passwords, only source code, markup and documentation are read: a `Cargo.toml`, a `prod.kubeconfig` or a file without an extension there is refused. The places where Shai is told to keep its own records (`SHAI_*_FOLDER`, `SHAI_*_DIR`, and `SHAI_LOG_FILE` with its rotated copies) are refused whatever they are called, also when they are created after the session has started. A search says how many entries it skipped for these reasons, so that "no match" is not read as "not there". A session that asks for the advisor does not start inside one of the folders above (see below).
  - *What it is shown.* Its instructions are fixed text with nothing about your machine or environment. It sees only your latest request and the agent's steps since its previous review.
  - *Redaction.* Everything sent to it is redacted first, and redacted before the advisor's own size limits are applied, so those limits do not leave half a secret behind. (A file is read up to 256 KiB before it is redacted; what is left of a known value at that cut is removed.)
    - Replaced wherever they appear: the settings of every provider in this config file (a base URL gives up its user, password and query values and keeps its host), what the configured MCP servers are given to authenticate (access tokens, the credentials in their addresses including a token in the path, and the values of credential-named options and variables of a server started as a command), and every value of the process environment that is not plainly harmless. Kept from the environment: values shorter than 8 characters or without a letter or digit, a short list of variables such as `HOME`, `PWD`, `USER` and `LANG`, and, under a name that does not look like a credential's, locale variables, paths that exist, numbers, single plain words and parts of the working directory's path. Everything else in the environment is treated as a secret, whatever its variable is called.
    - Replaced by their shape: private key blocks, bearer and basic tokens, well-known token prefixes, the user part of URLs, the value after `--password`, `--token` and similar options.
    - Replaced by their name: the value in `NAME=value`, `name: "value"`, `name := "value"`, typed declarations and the like, when the name says password, secret, token, key or similar and the value is a literal, and the whole value of `Authorization` and `Cookie` headers.
  - *Limits.* Redaction by shape and by name is a set of rules of thumb. A value shorter than 8 characters is only caught where a shape or a name gives it away. Not caught: a secret in a file the rules above do not refuse, under a name and in a shape they do not know; under a secret-looking name, a number, a value written like an expression (with brackets, a leading `$` or `&`, a leading `*` or `!` unless it follows `name=` directly, or dots between names), a single plain word after `name = ` with blanks around the sign, and a single plain word after `name:` that does not stand alone at the start of its line; credentials given through short options such as `-pSECRET`; arguments of an MCP server started as a command, other than the ones named above. The rules lean towards removing too much, so a `[redacted]` in what the advisor reads is not always a credential, at the start of a line a value of several plain words takes the rest of the line with it, and code that names both the opening and the closing marker of a private key loses what stands between them. If the working directory holds files with secrets these rules would miss, do not use the advisor on a provider you would not show them to.
- **It cannot act on the session.** It never answers a permission prompt and is never asked whether a tool may run. Its note is not stored in the conversation or in saved sessions: it is attached once, to the end of the last tool result the agent reads at its next step, inside fixed text that says it is automated advice and not an instruction. A note is one line of at most 400 plain characters, without square brackets or invisible characters, and a character outside the allowed set shows as `?`; a reply in any other form is dropped. The note is handed over once: if the request that carries it fails or is interrupted, it is not repeated, though you have still seen it. (If you turn on request logging, the note is in those logs like the rest of the request.)
- **It is bounded.** At most `max_calls` reviews per session, with `cooldown_turns` steps skipped after each; both hold across the agents one TUI session starts. One review may take at most 90 seconds, 6 model calls (each of which the client may retry, like any request) and 8 file lookups. A review that fails or times out is dropped and the agent carries on, and the steps it was about are shown again to the next one. After two failures in a row the advisor is switched off for the rest of the session, and you are told. A review you interrupt, by typing or by stopping the agent, still counts towards `max_calls`.

If the advisor is asked for and cannot be set up, the session does not start: a missing or unresolvable `advisor` role, a limit out of range, or a working directory inside one of the folders the advisor never enters is an error (exit status 2). It never falls back to the session's own model. An `advisor` section that is invalid or written twice stops every session, asked for or not, since it cannot be read to find out. As with [prewalk](#prewalk), a config file that exists and cannot be read stops the session too.

Two cases where a session runs without an advisor that was asked for, and says so:

- **An agent that would not pass the notes on.** If the agent a session runs does not show advisor notes to its model, the advisor is not attached to it and Shai prints `advisor not attached` with the reason, instead of paying for reviews nobody reads.
- **The configuration is followed.** Each time the TUI starts an agent (after `/auth`, when you pick another agent, when you restore a conversation), the advisor is set up again from the configuration as it is then, keeping what the session has already spent: its model, its limits and the credentials it must not be sent all come from the config as it is now. If the `advisor` role no longer resolves, the advisor is switched off with an `advisor off` line; it is never left on credentials or an endpoint you have just removed. An advisor that was off when the session started is not turned on this way, and one that was switched off after failed reviews, or has used all its reviews, stays off for the agents started later, with one line that says so.

Not covered: a step in which a tool call was denied, and the agent's final answer, are not reviewed. In headless mode with both `-p` and piped input, the advisor is shown both as the request. HTTP server mode does not use the advisor.

## Management

The auth configuration is managed via the `shai auth` interactive wizard:

```bash
shai auth
```

You can also run auth from within the TUI using the `/auth` slash command — this will save your current conversation context and restart the agent with the new provider settings.
