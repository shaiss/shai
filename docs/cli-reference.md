# CLI Reference

Complete reference for all shai commands and flags.

## Global Flags

These flags work with most commands.

| Flag | Description |
|------|-------------|
| `-p`, `--prompt <text>` | Run in headless mode with the given prompt |
| `-a`, `--agent <name>` | Use a specific agent |
| `-i`, `--interactive` | Pipe input then show TUI with context |
| `-r`, `--restore [id]` | Restore a previous session by ID; without an ID, opens the session picker (TUI only) |
| `--latest` | Restore the most recent session |
| `--trace` | Dump entire trace upon completion (headless mode only) |
| `--temperature <float>` | Set the LLM sampling temperature |
| `--advisor` | Have a second model, the `advisor` role, review the agent's steps and leave short notes. Read-only. See [Advisor](configurations/auth.md#advisor) |
| `--prewalk-into <target>` | Hand the session off to another model after its first edit. `<target>` is a role name or `<provider>/<model>`; overrides `prewalk.into` from the config. See [Prewalk](configurations/auth.md#prewalk) |
| `--tools <list>` | Only allow these built-in tools (comma-separated, headless mode). With `--agent`, restricts the agent's tools: tools it does not have are not added, and its MCP tools are dropped unless listed as `<server>:<tool>`. A built-in name never matches an MCP tool that reuses it |
| `--remove <list>` | Remove specific tools (comma-separated, headless mode), also from the `--agent`'s tools. MCP tools are removed as `<server>:<tool>` |
| `--yes` | Headless mode only: allow tools that write files, run bash or use the network. Without it, headless runs only read-only tools and denies the rest (see [Headless permissions](#headless-permissions)) |
| `--list-tools` | List all available tools |
| `-v`, `--version` | Show version information |

## Commands

### `shai`

Start the interactive TUI.

```bash
shai                        # Default TUI
shai -a myagent            # TUI with a custom agent
shai --latest              # TUI restoring the most recent session
shai -r <session-id>      # TUI restoring a specific session
shai -r                   # TUI with the session picker
```

### `shai auth`

Open the auth/provider configuration TUI. Lets you add, edit, and remove LLM providers.

```bash
shai auth
```

### `shai agent`

Launch the TUI with an agent picker. Optionally specify an agent name to skip the picker.

```bash
shai agent              # Open agent picker
shai agent myagent     # Launch TUI with a specific agent
shai agent list        # List available agents
```

### `shai session`

Launch the TUI with a session picker. Optionally specify a session ID or `latest` to skip the picker.

```bash
shai session            # Open session picker
shai session <id>       # Restore a specific session
shai session latest     # Restore the most recent session
```

### `shai list`

List agents, sessions, or skills.

```bash
shai list              # List everything
shai list agent        # List agents only
shai list session      # List sessions only
shai list skills       # List skills only
```

### `shai serve`

Start the HTTP server with OpenAI-compatible APIs and SSE streaming.

```bash
shai serve                              # Default: 127.0.0.1:3000
shai serve --port 8080                  # Custom port
shai serve --host 0.0.0.0 --port 8080  # Bind to all interfaces
shai serve --ephemeral                 # New agent per request
shai serve --yes                       # Let sessions write files, run bash and use the network
shai serve -a myagent                  # Use a specific agent
```

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1` | Host to bind to |
| `-p`, `--port` | `3000` | Port to bind to |
| `--ephemeral` | `false` | Spawn new agent per request |
| `--max-sessions` | unlimited | Maximum number of concurrent sessions |
| `--yes` | `false` | Allow tools that write files, run bash or use the network in every session. Without it, sessions run only read-only tools: HTTP clients cannot answer a permission prompt, so any other tool is denied immediately |
| `-a`, `--agent` | — | Agent name to serve |

### `shai on` / `shai off` / `shai status`

Manage the shell assistant PTY session.

```bash
shai on                 # Start monitoring shell
shai off                # Stop monitoring
shai status             # Check if shai is active
```

### `shai import`

Import configuration from `.claude` or `.cursor` into `AGENTS.md`.

```bash
shai import             # Append to existing AGENTS.md
shai import --overwrite # Overwrite existing AGENTS.md
```

## Headless Mode

Run shai without the TUI for scripting and automation:

```bash
# Explicit prompt (read-only tools)
shai -p "explain what main.py does"

# Let it write files and run bash
shai --yes -p "make me a hello world in main.py"

# Piped input
echo "make me a hello world in main.py" | shai --yes

# With agent
shai -a myagent --yes -p "fix this bug"

# With temperature
shai -p "review this function" --temperature 0.5

# Let a second model review the work as it goes (needs an "advisor" role)
shai -p "migrate the config loader to the new schema" --advisor --yes

# Plan on the primary model, then continue on a cheaper one after the first edit
shai -p "add input validation to the signup form" --prewalk-into cheap --yes

# Chain commands
echo "make me a hello world in main.py" | shai --yes --trace | shai --yes -p "now run it!"
```

### Headless permissions

Headless mode has nobody to answer a permission prompt, so it never asks:

- Read-only tools (`read`, `ls`, `find`, `todo_read`, `todo_write`, `skill`) run normally.
- Any tool that writes files, runs bash or uses the network (`write`, `edit`, `bash`, `fetch`, `memory_write`, `memory_remove`, and all MCP tools) is denied immediately. The model gets a `permission denied (headless; pass --yes to allow)` tool result.
- `--yes` allows every tool, which was the headless behavior before this flag existed.

`--tools` and `--remove` still decide which tools the model sees; `--yes` only decides whether the ones it sees may write, run bash or use the network. `shai serve` follows the same rules, with its own `--yes` flag.

## Interactive Pipe Mode

Pipe content into shai and continue the conversation in the TUI:

```bash
echo "analyze this code" | shai -i
cat error.log | shai -i
git diff | shai -i
```

The piped content is sent as the first user message, and the TUI opens immediately after.
