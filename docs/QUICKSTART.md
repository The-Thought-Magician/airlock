# Quickstart — zero to a jailed server in five minutes

## 1. Get a Solari API key (1 min)

Sign up at [console.getsolari.com](https://console.getsolari.com) and generate a
key. It looks like `slr_live_…`. One key works across sandboxes, desktops, and
browsers, and bills to one balance.

Billing is per sandbox-hour; a jailed MCP server is a sandbox that lives only as
long as your client session and is killed on disconnect. Skim
[docs.getsolari.com](https://docs.getsolari.com) pricing so there are no
surprises.

## 2. Install Airlock (1 min)

```bash
git clone <this repo> && cd airlock
npm install
export SOLARI_API_KEY=slr_live_...
```

Tip: keep the key in a git-ignored `.env` and load it with
`set -a && . ./.env && set +a`.

Sanity-check that a sandbox boots and kills cleanly:

```bash
npm run probe          # boots a sandbox, prints environment facts, kills it
```

## 3. Generate a policy (1 min)

```bash
airlock init
```

This reads your existing Claude Code / Cursor MCP config and writes an
`airlock.toml` with a stub per server — `egress = []` and `mounts = []` for
each, because the safe default is nothing. Open it and grant each server only
what it needs:

```toml
[server.github]
launcher = "npx"
package  = "@modelcontextprotocol/server-github"
egress   = ["api.github.com"]     # add the hosts it legitimately needs
mounts   = []
```

Check what you've declared:

```bash
airlock policy
```

## 4. Point your client at Airlock (1 min)

In your MCP client config, replace the server's command. Before:

```json
{ "mcpServers": { "github": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] } } }
```

After:

```json
{ "mcpServers": { "github": { "command": "airlock", "args": ["run", "github"] } } }
```

Use an absolute path to `airlock` (or `npx tsx .../src/cli.ts`) if it isn't on
your client's `PATH`. Restart the client; the server's tools appear exactly as
before.

## 5. Verify the boundary (1 min)

Run the demo to see the difference between native and jailed, on the same
malicious server:

```bash
npm run demo
```

And watch the audit trail as you use a server:

```bash
airlock log                 # every session, tool call, and network attempt
airlock log --blocked       # just the network attempts that were refused
```

## Optional: pin an immutable build

By default `airlock run` provisions the server cold each time. To pin an
immutable, reproducible build (so an upstream release can't land silently):

```bash
airlock build github        # mints a tpl_… template, records it in airlock.toml
```

Subsequent runs use the pinned template when the platform can serve it, and fall
back to a cold provision — loudly — when it can't. See
[WHY-SOLARI](WHY-SOLARI.md) for why this is a template and not a snapshot, and
[LIMITATIONS](LIMITATIONS.md) for the reliability caveat.

## Housekeeping

```bash
airlock ps                  # Airlock's running sandboxes
airlock reap                # kill them (a crash can leak one; it bills until idle)
airlock templates --prune   # delete built templates no policy references
```

## If something goes wrong

- **"SOLARI_API_KEY is not set"** — export it, or load your `.env`.
- **The server's tools don't appear** — check `airlock log`; the server may have
  failed to start inside the jail. Its stderr is forwarded to your client's logs.
- **A server can't reach a host it needs** — add the host to `egress`. Remember
  node's `fetch`, curl, and python honour the proxy; a client that doesn't will
  reach nothing.
- **`No sandbox host available` / slow starts** — platform capacity; retry.
  `airlock reap` first if you suspect leaked sandboxes.
