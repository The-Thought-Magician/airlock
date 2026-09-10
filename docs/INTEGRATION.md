# Wiring Airlock into Claude Code, Codex, and other clients

Airlock is a stdio MCP server: `airlock run <name>` speaks JSON-RPC over stdio
exactly like any MCP server, so any MCP client launches it the same way it
launches a real server — you just change the command. Tool names, schemas, and
results pass through unmodified, so the client cannot tell the difference.

## 1. Make `airlock` runnable

```bash
git clone <this repo> && cd airlock
npm install          # runs the build automatically (prepare script)
npm link             # puts `airlock` on your PATH  (or: npm install -g .)
airlock --help
```

If you would rather not install anything globally, skip `npm link` and use the
absolute-path form in the configs below:

```
command = "npx"
args    = ["tsx", "/abs/path/to/airlock/src/cli.ts", "run", "<name>", ...]
```

That works with zero build, at the cost of a slightly slower startup per launch.

## 2. Point Airlock at a policy and a key

When a client launches the MCP server, its working directory is unpredictable,
so make the policy findable in one of two ways:

- **Recommended:** pass an absolute `--config` in the args (shown below), or
- put the policy at `~/.config/airlock/airlock.toml`, which Airlock finds
  automatically.

`airlock run` needs `SOLARI_API_KEY` in its environment. Both clients let you set
it per-server in an `env` block (shown below). It lives in the client's config
file then — if you would rather not put it there, export it in the environment
the client itself inherits.

## 3. Claude Code

Edit `.mcp.json` (project) or `~/.claude.json`, under `mcpServers`:

```json
{
  "mcpServers": {
    "github": {
      "command": "airlock",
      "args": ["run", "github", "--config", "/home/you/airlock.toml"],
      "env": { "SOLARI_API_KEY": "slr_live_..." }
    }
  }
}
```

Or with the CLI:

```bash
claude mcp add github \
  -e SOLARI_API_KEY=slr_live_... \
  -- airlock run github --config /home/you/airlock.toml
```

Restart Claude Code; the `github` server's tools appear exactly as before, now
jailed. `airlock log --blocked` shows anything the jail refused.

**Before / after** — the only change is the command:

```json
// before: the server runs on your laptop
{ "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] }
// after: the same server, jailed in a sandbox
{ "command": "airlock", "args": ["run", "github", "--config", "/home/you/airlock.toml"] }
```

## 4. Codex

Edit `~/.codex/config.toml` (or `.codex/config.toml` in a trusted project). Note
the snake_case `mcp_servers`:

```toml
[mcp_servers.github]
command = "airlock"
args    = ["run", "github", "--config", "/home/you/airlock.toml"]

[mcp_servers.github.env]
SOLARI_API_KEY = "slr_live_..."
```

Or with the CLI:

```bash
codex mcp add github -- airlock run github --config /home/you/airlock.toml
```

## 5. Cursor and other MCP clients

Any client that launches stdio MCP servers with `command` + `args` + `env` works
the same way. For Cursor, add the same block to `~/.cursor/mcp.json` under
`mcpServers`. The pattern is always: replace the server's command with
`airlock run <name>`.

## 6. Skills

Two ways, covered in [SKILLS.md](SKILLS.md):

- **As a jailed MCP server (structural):** add a `launcher = "skill"` block to
  your policy and wire it in exactly like any server above
  (`airlock run <skill>`). The client sees a jailed MCP server.
- **Natively discovered (Claude Code):** `airlock skill install skills/<name>`
  writes the skill into `~/.claude/skills/` so Claude Code loads it natively;
  its code stays in the sandbox and runs via `airlock exec`. (Codex skill
  discovery differs by client; the MCP-server route above is the portable one.)

## Notes and gotchas

- **Keep stdout clean.** Airlock sends only JSON-RPC to stdout and every
  diagnostic to stderr, which is what MCP clients expect. Do not wrap `airlock
  run` in anything that prints to stdout.
- **First launch is slower.** The first tool call of a session waits for the
  sandbox to provision (~11 s cold, or a few seconds from a pinned template).
  Subsequent calls are one network round trip. Pin a template with
  `airlock build <name>` to speed cold starts (best-effort; see LIMITATIONS).
- **One sandbox per running server.** They are killed on client disconnect;
  `airlock ps` / `airlock reap` clean up any that leak.
- **The key is per-launch.** Every `airlock run` needs `SOLARI_API_KEY`; set it
  in the `env` block or the client's inherited environment.
