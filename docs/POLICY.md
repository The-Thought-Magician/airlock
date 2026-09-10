# Policy reference — `airlock.toml`

One block per server, `[server.<name>]`. `<name>` is what you pass to
`airlock run <name>` and what goes in your MCP client config.

**Everything is deny-by-default.** An omitted `egress` means no network at all;
an omitted `mounts` means the server sees none of your filesystem. You opt in,
per server, to exactly what it needs. This is the whole design: isolation is the
default, access is the opt-in.

Airlock looks for the file at `./airlock.toml`, then
`~/.config/airlock/airlock.toml`, unless `--config <path>` is given.

## Fields

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `launcher` | `"npx"` \| `"python"` \| `"uvx"` \| `"local"` \| `"skill"` | required | How the server is installed and started |
| `package` | string | required (except `local`) | npm package, pip distribution, or uv tool name. May include a version: `@acme/x@1.2.3` |
| `path` | string | — | For `launcher = "local"` or `"skill"`: a directory on your machine, uploaded into the sandbox |
| `args` | string[] | `[]` | Extra argv appended after the entrypoint |
| `egress` | string[] | `[]` (no network) | Allowlisted domains. See below |
| `mounts` | array of tables | `[]` (no files) | Paths to admit. See below |
| `secrets` | table | `{}` | Env vars injected into the server **verbatim** — it can read them |
| `broker` | array of tables | `[]` | Credentials injected at the proxy — the server never sees them (§3.3) |
| `template` | string | — | Pinned `tpl_…`, written by `airlock build` |
| `version` | string | — | Version that landed in the template, written by `airlock build` |
| `tools_hash` | string | — | Tool-definition hash, written by `airlock build` (§3.4) |

The last three are managed by `airlock build` — you don't hand-write them.

## `launcher`

- **`npx`** — installs an npm package globally, resolves the entrypoint from its
  `bin` field (not guessed from the name).
- **`python`** — `pip3 install <package>`, launched as `python3 -m <module>`
  (dashes normalised to underscores).
- **`uvx`** — installs `uv`, then `uv tool install <package>`; the executable is
  read from `uv tool list`. (`uv` is not in the base image; Airlock installs it.)
- **`local`** — uploads a directory from your machine (`path`) into the sandbox,
  root-owned and read-only, launched via its `package.json` `main` or
  `index.js`. Used to jail a server that isn't published — including the demo's
  evil server.

## `egress`

A list of hostnames the server may reach. Anything not listed is blocked and
logged.

```toml
egress = ["api.github.com", "*.githubusercontent.com"]
```

- A bare domain (`api.github.com`) matches only that host.
- A wildcard (`*.github.com`) matches subdomains **and** the apex.
- Entries are domains, not URLs — `https://x/y` is rejected at parse time.
- `[]` or omitted means **no network at all**: the server runs in a namespace
  with no route to anywhere.

Enforcement is host-level, not content-level: if you allow a host, the server
may send anything to it. Keep allowlists narrow. (See THREAT-MODEL on
allowlisted-host abuse.)

**Client caveat:** the allowlist only helps clients that use the proxy. curl,
python-requests, and node (via an injected shim) do. A client that ignores the
proxy reaches nothing — safe, but that host won't work for it either.

## `mounts`

Directories or files from your machine to admit into the sandbox.

```toml
mounts = [
  { path = "~/projects/demo", mode = "rw" },
  { path = "~/.config/tool/config.yaml", mode = "ro" },
]
```

- `mode = "ro"` (default) — synced in, owned by root in the sandbox so the
  server cannot modify it. `ro` is structural, not advisory.
- `mode = "rw"` — synced in owned by the server, and synced back out to your
  machine when the session ends.
- The guest path mirrors the host path under `/mnt/airlock/…` by default; pass
  `guestPath` to override.
- `.git` and `node_modules` are skipped on upload.

## `secrets` vs `broker` — read this

Two different things, and the difference is the whole point of §3.3.

**`secrets` is plain environment injection. The server receives the value and
can read it.** Use it only for values the server is *meant* to hold.

```toml
[server.x.secrets]
LOG_LEVEL = "debug"
```

`airlock run` warns whenever `secrets` is non-empty, because a credential put
here is genuinely handed to the server.

**`broker` keeps the credential out of the server entirely.** The egress proxy
injects it as a header on requests to an allowlisted host; the server's
environment never contains it.

```toml
egress = ["api.github.com"]      # the host must be allowlisted

[[server.x.broker]]
host   = "api.github.com"
header = "Authorization"
value  = "env:GITHUB_TOKEN"      # read from YOUR shell env, never stored in the file
```

- `value = "env:NAME"` reads `NAME` from your environment at launch — the real
  secret lives in your shell, not in the committed policy.
- `value = "literal"` is a literal, really only for demos; a literal secret in
  `airlock.toml` defeats the purpose.
- The `host` must be in `egress`, or the request is blocked before brokering
  applies (checked at parse time).

**The tradeoff:** brokering into HTTPS requires the proxy to terminate TLS (a
man-in-the-middle with a CA trusted inside the sandbox). It is scoped to the
disposable VM and to allowlisted hosts, but understand it before enabling it.
See THREAT-MODEL.

## Worked examples

### A server with no network and no files (the strictest, and it still works)

```toml
[server.everything]
launcher = "npx"
package  = "@modelcontextprotocol/server-everything"
egress   = []
mounts   = []
```

### A GitHub server, brokered so it never holds your token

```toml
[server.github]
launcher = "npx"
package  = "@modelcontextprotocol/server-github"
egress   = ["api.github.com"]
mounts   = []

[[server.github.broker]]
host   = "api.github.com"
header = "Authorization"
value  = "env:GITHUB_TOKEN"
```

### A filesystem server scoped to one directory

```toml
[server.filesystem]
launcher = "npx"
package  = "@modelcontextprotocol/server-filesystem"
args     = ["/mnt/airlock/home/you/projects/demo"]
egress   = []
mounts   = [{ path = "~/projects/demo", mode = "rw" }]
```

### A bundled agent skill, jailed

```toml
[server.wordcount]
launcher = "skill"
path     = "skills/wordcount"   # a directory with SKILL.md + scripts
egress   = []                   # the skill's code gets no network
mounts   = []                   # and none of your files
```

Airlock bridges the skill to an MCP server exposing `skill_instructions` and
`skill_exec`; the skill's scripts run inside the jail. See [SKILLS.md](SKILLS.md).

### A Python server reaching one API

```toml
[server.weather]
launcher = "python"
package  = "mcp-server-weather"
egress   = ["api.weather.gov"]
mounts   = []
```

## Commands that touch the policy

```bash
airlock init                 # generate stubs from your existing MCP config
airlock policy               # show the effective policy for every server
airlock build <server>       # mint a pinned template, write template/version/tools_hash
airlock build <server> --update   # rebuild, show the tool-definition diff first
```

## A note on the retired `snapshot` field

Earlier drafts pinned a `snapshot = "snap_…"`. Snapshots were measured slower
than provisioning from scratch and `revert()` is unavailable, so they were
dropped for `template`. A `snapshot` key now produces an explicit error telling
you to run `airlock build`. See [FINDINGS-WARMSTART](FINDINGS-WARMSTART.md).
