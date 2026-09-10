# Airlock — sandboxed MCP runtime

**Run any MCP server inside a Solari sandbox instead of on your laptop, with
filesystem and network boundaries enforced structurally rather than by trust.**

![The same evil MCP server run natively (credential stolen and exfiltrated) and under Airlock (read blocked with ENOENT, egress blocked with ENETUNREACH)](demo/image.png)

_Output of `npm run demo` — the same malicious server, run two ways. Full text
in [`demo/transcript.txt`](demo/transcript.txt); how to run and record it in
[demo/README.md](demo/README.md)._

---

## The problem, in three lines

An MCP server is launched by your client as an ordinary local process:
`npx -y some-mcp-server`. That one line is arbitrary code execution on your
machine with your privileges — it can read `~/.ssh/id_rsa`, every `.env` on
disk, your git history, and post any of it anywhere. "Only install servers you
trust" is not a control; updates land silently and nobody re-reads the source on
every version bump.

**Airlock's thesis: trust should not be the control. The boundary should be
structural. A server that never had access to `~/.ssh` cannot leak it, whatever
its code says.**

## What it does

Airlock takes the MCP client's subprocess slot. Your client speaks JSON-RPC to
`airlock run <server>`; Airlock runs the real server inside a Solari cloud
sandbox and relays the protocol through, byte-for-byte. The server runs as an
unprivileged user in a network namespace with **no route to anything** except an
egress proxy you configure — and with **none of your files**, because the
sandbox has no path to your laptop's filesystem at all.

```
┌──────────────┐   stdio    ┌─────────────┐   WS/relay  ┌────────────────────┐
│ Claude Code  │◄──────────►│   airlock   │◄───────────►│  Solari sandbox     │
│ Cursor, etc. │  JSON-RPC  │   (local)   │             │  ┌───────────────┐  │
└──────────────┘            │  policy +   │             │  │ real MCP      │  │
                            │  audit      │             │  │ server, jailed│  │
                            └─────────────┘             │  └───────────────┘  │
                                                        └────────────────────┘
```

**Security eval: 9/9 attack vectors contained** — filesystem theft, raw-socket
egress, DNS exfiltration, netns escape, and rug pulls all blocked, verified live
by `npm run eval`. Full scorecard and an honest comparison against ToolHive,
Docker MCP Gateway, and nono in [docs/COMPARISON.md](docs/COMPARISON.md).

The only thing you change is the command in your MCP config.

**Before:**
```json
{ "command": "npx", "args": ["-y", "@acme/mcp-server"] }
```
**After:**
```json
{ "command": "airlock", "args": ["run", "acme"] }
```

Tool names, schemas, and results pass through unmodified — the client cannot
tell the difference.

## Install

```bash
git clone <this repo> && cd airlock
npm install                            # builds the CLI automatically
npm link                               # puts `airlock` on your PATH
export SOLARI_API_KEY=slr_live_...     # grab one at console.getsolari.com
```

To wire it into Claude Code, Codex, or Cursor, see
[docs/INTEGRATION.md](docs/INTEGRATION.md) — it is a one-line swap in the client's
MCP config (`airlock run <name>` in place of the server's command).

See [docs/QUICKSTART.md](docs/QUICKSTART.md) to get from zero to a jailed server
in five minutes.

## One-minute example

```bash
airlock init                    # generate airlock.toml from your existing MCP config
airlock run everything          # what your MCP client invokes
airlock log --blocked           # every network attempt the jail refused
```

A minimal policy (`airlock.toml`):

```toml
[server.github]
launcher = "npx"
package  = "@modelcontextprotocol/server-github"
egress   = ["api.github.com"]     # the ONLY host it can reach; omit for none
mounts   = []                     # it sees none of your filesystem
```

Everything is deny-by-default. An omitted `egress` means no network at all; an
omitted `mounts` means no filesystem access. You opt in, per server, to exactly
what a server needs. Full field reference in [docs/POLICY.md](docs/POLICY.md).

## The demo

`npm run demo` runs the same deliberately-malicious server twice — natively,
then under Airlock — and self-verifies:

```
NATIVE   add(2,3)→5, reads ~/.aws/credentials, exfiltrates it, phones home
         ✗ CREDENTIAL STOLEN

AIRLOCK  same server, same calls; read → ENOENT; raw socket → ENETUNREACH
         ✓ NOTHING STOLEN
```

The malware is inert by construction (fake credential, localhost-only target).
See [demo/README.md](demo/README.md) for the full safety statement.

## Why not just Docker?

| | Docker locally | Airlock on Solari |
|---|---|---|
| Prerequisite | Docker daemon, image builds, disk | An API key |
| Locked-down corporate laptop | Often not permitted | Works |
| Blast radius of an escape | Your machine | A disposable cloud VM |
| Local resource cost | Your CPU and RAM | None |
| Team-wide policy | Bespoke tooling | A committed config file |
| **Cost** | **Free** | **Per sandbox-hour** |
| **Offline** | **Yes** | **No — needs connectivity** |
| Per-call latency | None | One round trip to your region (~250 ms) |

Docker is free and offline; Airlock is not. It earns its place when Docker
isn't an option (locked-down machines), when you want the blast radius off your
hardware entirely, or when the policy should be a committed file the whole team
shares. Full argument, with its weaknesses, in
[docs/WHY-SOLARI.md](docs/WHY-SOLARI.md).

## What's real, and what isn't

This was built and measured against the live Solari API, and the docs try hard
to separate proven from aspirational.

**Solid, verified, load-bearing:**
- **Filesystem isolation** — the sandbox has no path to your disk; your files
  are absent by construction, not by a rule (§3.1).
- **Egress control** — a network namespace with no interfaces, bridged to a
  filtering proxy; verified to block raw-socket bypass and DNS exfiltration
  (§3.2). This is the heart of the tool and has not failed once.
- **The relay** — real third-party servers run through it unmodified.
- **Audit log**, **filesystem/network demo**, **fail-closed jail verification**.

**Built, with honest caveats:**
- **Credential brokering** (§3.3) — works, but requires TLS interception inside
  the sandbox. Understand the tradeoff before using it.
- **Version pinning** (§4) — a `tpl_…` template you build. It gives immutability
  and reproducibility, but the platform serves custom templates unreliably, so
  it is **best-effort**: `airlock run` falls back to a cold provision, loudly.
- **Tool-definition pinning** (§3.4) blocks rug pulls at runtime;
  **prompt-injection scanning** (§3.5) is warnings-only.

Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md) and
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) before relying on any of it.

## Documentation

| Doc | What's in it |
|---|---|
| [COMPARISON](docs/COMPARISON.md) | The security eval scorecard, benchmarks, and how Airlock compares to ToolHive / Docker MCP Gateway / nono |
| [SKILLS](docs/SKILLS.md) | Jailing agent skills (a SKILL.md + scripts) as sandboxed MCP tools |
| [QUICKSTART](docs/QUICKSTART.md) | Zero to a jailed server in five minutes |
| [INTEGRATION](docs/INTEGRATION.md) | Wiring Airlock into Claude Code, Codex, and Cursor |
| [THREAT-MODEL](docs/THREAT-MODEL.md) | What Airlock defends against, what it doesn't, residual risk |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | The relay, the jail, lifecycle, the mechanisms that were measured |
| [POLICY](docs/POLICY.md) | Every `airlock.toml` field, with worked examples |
| [LIMITATIONS](docs/LIMITATIONS.md) | Latency, cost, what doesn't fit, platform quirks |
| [WHY-SOLARI](docs/WHY-SOLARI.md) | The Docker comparison and the pinning story, weaknesses included |
| [FINDINGS-DAY1](docs/FINDINGS-DAY1.md) | Measured API facts that the design rests on |
| [FINDINGS-WARMSTART](docs/FINDINGS-WARMSTART.md) | Why snapshots lost to templates |
| [CONTRIBUTING](CONTRIBUTING.md) | Adding a launcher or a policy control |

## Status

Working prototype, built over a weekend against the live API. The isolation
boundary (§3.1, §3.2) is the part to trust; everything else is documented with
its real reliability. Not production-hardened.
