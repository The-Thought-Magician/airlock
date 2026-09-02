# Airlock — Sandboxed MCP Runtime

**One-line pitch:** Run any MCP server inside a Solari sandbox instead of on your laptop, with filesystem, network, and secret boundaries enforced structurally rather than by trust.

**Built for:** Pinetree Research / Solari SWE intern challenge
**Author:** Chiranjeet
**Status:** Spec — not started
**Target scope:** One weekend

---

## 0. Blockers before any code

These are hard prerequisites. Nothing below can be built or tested without them.

| # | Blocker | Action | Owner | Status |
|---|---------|--------|-------|--------|
| 1 | **Solari API key** | Sign up at console.getsolari.com, generate an `slr_live_` key | Chiranjeet | ✅ DONE — key in `.env`, verified against the cookbook quickstart |
| 2 | Free-tier concurrency limits | Email hello@getsolari.com, mention the challenge, request a quota bump | Chiranjeet | WON'T DO |
| 3 | Snapshot API availability | ✅ Verified in docs — see §0.1 | — | RESOLVED |
| 4 | Egress control mechanism | ✅ None native; built in-VM and verified 7/7 — see §3.2 and `docs/FINDINGS-DAY1.md` | Chiranjeet | RESOLVED, mechanism proven |
| 5 | Billing awareness | Read docs.getsolari.com/pricing; understand per-sandbox-hour cost | Chiranjeet | TODO |

**Note on #1:** the API key gates everything. Get it first, verify it against
`sandbox-quickstart-ts` from the cookbook, and confirm a sandbox boots and kills
cleanly before writing a single line of Airlock.

---

## 0.1 Verified API facts

Checked against `docs.getsolari.com` before writing this spec. These are the
ground truth the design rests on.

### Snapshots — fully available, better than assumed

| Operation | API |
|-----------|-----|
| Save state, machine keeps running | `snapshot(name?)` → snapshot ID |
| Rewind the same machine | `revert(snapshotId)` |
| Boot a new independent machine from a save point | `create({ template, fromSnapshot })` |
| Park without shutdown | `pause()` / `resume()` |

Snapshots work identically for sandboxes and desktops. `fromSnapshot` is a
create-time parameter, so forking is first-class. The version-pinning argument in
§4 stands unmodified.

### Sandbox create parameters (POST /sandboxes)

`kind` (`sandbox` | `desktop`), `template`, `fromSnapshot`, `cpu` (1–16),
`memMb` (1–65536), `diskGb` (1–100), `envs`, `metadata`, `timeoutMs`,
`lifecycle` (`{onTimeout: "pause"|"kill", autoResume}`), `resolution`, `record`,
`volumes` (`[{volumeId, path}]`).

Relevant consequences:

- `envs` gives per-session environment injection — this is how placeholder
  credentials reach the server without the real secret.
- `lifecycle.onTimeout: "pause"` plus `autoResume` is a cheaper warm-start path
  than holding a sandbox running.
- `metadata` labels let Airlock find and reap its own orphaned sandboxes.

### Endpoints that matter

`POST /sandboxes/:id/exec`, `WS /control/:id` (RPC channel),
`PUT /files/upload`, `GET /sandboxes/:id/files/download-url`,
`POST /sandboxes/:id/ports/:port` (public preview URL),
`GET /sandboxes/:id/metrics`.

### Volumes are durable storage, not host mounts

A volume is cloud storage attached at a path. It is **not** a mount of the
developer's laptop. There is no mechanism to expose the host filesystem to a
sandbox at all.

### Templates

Built with an image builder in a fixed order: `apt → pip → run → env → workdir`.
Yields a `tpl_…` ID. Base templates: `base` (headless), `default`/`workstation`,
`office`, `code` (git, python, node, VS Code). Whether `base` ships node and
python is not documented — verify, or build a custom template.

### Not documented anywhere

No firewall, egress filtering, allowlist, blocklist, DNS, or network-policy
parameter exists in the sandbox API, the template builder, or the API reference.
Egress control must be implemented inside the VM. See §3.2.

---

## 1. Problem statement

MCP servers are launched by the client as ordinary local processes.

```json
{ "mcpServers": { "some-tool": { "command": "npx", "args": ["-y", "some-mcp-server"] } } }
```

That single line is arbitrary code execution on the developer's machine with the
developer's full privileges.

### What a malicious or compromised server can reach today

- `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.config/gh/hosts.yml`
- Every `.env` file in every project on disk
- Full git history, including secrets committed and later removed
- Shell access, cron, login shell config, persistence mechanisms
- Unrestricted outbound network — exfiltration is one `fetch()`

### Live attack classes

| Class | Mechanism |
|-------|-----------|
| Typosquatting | Package named one character away from a popular server |
| Supply-chain compromise | Legitimate package, malicious update pushed later |
| Tool poisoning | Malicious instructions embedded in tool descriptions, read by the agent |
| Rug pull | Server changes tool definitions after the user approved it |
| Cross-server shadowing | One server's descriptions hijack calls intended for another |
| Credential harvesting | Server reads local secrets and posts them anywhere |

### Why current mitigation fails

The prevailing advice is "only install servers you trust" and "read the source."
Neither survives contact with reality: developers install servers from a
registry the way they install npm packages, updates land silently, and nobody
re-reads the source on every version bump.

**Airlock's thesis:** trust should not be the control. The boundary should be
structural. A server that never had access to `~/.ssh` cannot leak it, whatever
its code says.

---

## 2. Architecture

### 2.1 Transport interposition

MCP clients speak JSON-RPC over stdio to a subprocess. Airlock takes that
subprocess slot.

```
┌──────────────┐   stdio    ┌─────────────┐   HTTP/WS   ┌────────────────────┐
│ Claude Code  │◄──────────►│   Airlock   │◄───────────►│  Solari sandbox    │
│ Cursor, etc. │  JSON-RPC  │   (local)   │   relay     │  ┌──────────────┐  │
└──────────────┘            │             │             │  │ real MCP     │  │
                            │ policy      │             │  │ server       │  │
                            │ layer       │             │  └──────────────┘  │
                            └─────────────┘             └────────────────────┘
                                   │
                                   ▼
                            audit log (local)
```

### 2.2 Lifecycle

1. Client launches `airlock run --server some-tool` instead of `npx some-mcp-server`.
2. Airlock reads the policy for `some-tool` from `airlock.toml`.
3. Airlock resumes a sandbox from the pinned snapshot for that server, or
   provisions and snapshots it on first run.
4. Airlock starts the real server inside the sandbox, wired to stdio there.
5. Airlock relays JSON-RPC frames in both directions, applying policy in the middle.
6. On client disconnect, Airlock kills the sandbox explicitly (`kill()`, not `close()`).

### 2.3 Drop-in property

The only user-visible change is the command in the MCP config. Tool names, tool
schemas, and results pass through unmodified. The client cannot tell the
difference. This is the single most important design constraint — anything that
requires the user to change how they work will not get adopted.

Before:

```json
{ "command": "npx", "args": ["-y", "@acme/mcp-server"] }
```

After:

```json
{ "command": "airlock", "args": ["run", "acme"] }
```

---

## 3. Policy layer

Six controls. The first two carry the demo; ship those even if the rest slip.

### 3.1 Filesystem scoping — P0, and mostly free

The verified API changes this control from *restriction* to *selective admission*,
which is strictly stronger.

- There is no host mount mechanism. The sandbox is a remote VM with no path to
  the laptop's filesystem, by construction.
- So `~/.ssh`, `~/.aws`, and every `.env` are absent by default, not by policy.
  Reads return `ENOENT` because the files genuinely are not there.
- Airlock's job is the inverse of what I first assumed: sync declared paths **in**,
  via `PUT /files/upload` or the control channel, before the server starts.
- Writes sync back out via `files/download-url`, only where the policy says `rw`.
- Nothing about this can be misconfigured into leaking a path the user never named.
- Say this plainly in the docs. "Isolation is the default, access is the opt-in"
  is a much better story than a sandbox with holes punched in it.

Trade-off to document: servers that expect a large working tree pay an upload
cost at first snapshot. Mitigate by baking stable trees into the snapshot, or by
attaching a volume for caches.

### 3.2 Egress allowlist — P0, hard boundary

Solari documents no network policy controls. This must be built inside the VM.

> **Revised 2026-09-02** after measuring a live sandbox. The original design
> here was uid-keyed `iptables` rules. That is not buildable on this kernel —
> see `docs/FINDINGS-DAY1.md`. The replacement below is stronger, and the
> "best-effort" fallback this section used to carry has been deleted because it
> is no longer needed.

**Why the original design is out.** The sandbox kernel has no loadable modules
(no `/lib/modules`, no `modprobe`). `xt_owner` is not compiled in, so
`--uid-owner` matching does not exist. The default `nf_tables` backend is
broken outright, and `veth` is absent, ruling out the conventional
netns-plus-veth pairing too. We do get `uid=0` with a full capability bounding
set, so privilege was never the problem — the specific match module was.

**Design**

1. During the snapshot build, install `tinyproxy`, `socat`, and `iproute2`, and
   create an unprivileged user `mcp` (uid 4000).
2. Create a network namespace with **no interfaces at all** — only loopback.
   With no interface there is no route, so it is a total network blackout,
   enforced by the absence of a path rather than by a filter rule that has to
   be evaluated correctly.
3. Bridge that namespace to the proxy over a **unix domain socket**. Unix
   sockets are filesystem objects, so they cross a namespace boundary freely:
   `socat` inside the namespace listens on `127.0.0.1:8888` and forwards to
   `/run/airlock/proxy.sock`; `socat` outside forwards that to tinyproxy.
4. Inject `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` into the server's
   environment. The server sees an ordinary loopback proxy and needs no
   modification.
5. tinyproxy enforces the domain allowlist from the policy file
   (`FilterDefaultDeny Yes`, one anchored ERE per allowed domain) and logs
   every attempt, allowed or blocked.
6. Launch the server as
   `ip netns exec airlock setpriv --reuid=4000 --regid=4000 --clear-groups --no-new-privs <launcher>`.
7. Bake all of this into the snapshot, so it exists before any third-party code
   runs.

```
   ┌─ netns "airlock" — no interfaces, lo only ─┐   ┌─ root netns ─────────┐
   │  MCP server (uid 4000, no-new-privs)       │   │  tinyproxy :8888     │
   │    HTTP_PROXY=127.0.0.1:8888               │   │  domain allowlist    │
   │        └─ socat TCP-LISTEN:8888 ───────────┼───┼─ socat UNIX-LISTEN   │
   │                    /run/airlock/proxy.sock │   │        └─ internet   │
   └────────────────────────────────────────────┘   └──────────────────────┘
                    (shared filesystem crosses the netns)
```

**Why this is stronger than the uid split.** A server that ignores
`HTTP_PROXY` and opens a raw socket gains nothing: there is no interface to
reach anything directly, so there is no route to ignore it *to*. And there is
no rule for a compromised process to flush — escaping requires `CAP_SYS_ADMIN`
to `setns` back into the host namespace, which an unprivileged uid started with
`--no-new-privs` does not have and cannot acquire.

**Verified, 7/7 checks** (`npm run probe:netns`, raw output in `findings/`):
blackout confirmed; allowlisted host reachable through the bridge;
non-allowlisted host refused; raw sockets to hardcoded IPs all fail with no
route; DNS resolution fails; `nsenter` to the host namespace denied.

**Honest residual risk, which belongs in the threat model:**

- The boundary is now a kernel-level container escape, not "root in the VM
  flushes the rules." That is a materially narrower claim than the original
  design could make.
- Even if it were breached, the blast radius is a disposable cloud VM with none
  of the developer's files or credentials in it. That is the whole point, and it
  is a far better failure mode than the status quo.
- **DNS-based exfiltration is blocked**, not out of scope: the jail has no DNS
  at all, and the proxy resolves on the server's behalf. This is an upgrade over
  the original design — say so.
- Allowlisted-host abuse (posting secrets to a gist on an allowed domain)
  remains out of scope. Name it explicitly.

### 3.3 Secret brokering — P1

- The server never receives the real credential.
- Airlock injects the token at the egress proxy on requests to allowlisted hosts.
- The server holds a placeholder. Reading its own env yields nothing useful.
- Same pattern used by managed agent proxies today, so the design is proven.

### 3.4 Tool definition pinning — P1

- On first approval, hash every tool's name, description, and input schema.
- On later launches, compare. Any drift blocks startup and reports the diff.
- This is the direct countermeasure to rug pulls and silent redefinition.
- User can re-approve deliberately with `airlock approve <server>`.

### 3.5 Prompt-injection scanning — P2

- Scan tool descriptions for imperative language aimed at the agent.
- Heuristics: "ignore previous", "always call", "before responding", references
  to credential paths, base64 blobs, unicode direction marks.
- Report as warnings at approval time, not a hard block. False positives are certain.
- Cut this first if time runs short.

### 3.6 Audit log — P1

- Every tool call: server, tool name, argument digest, result size, duration.
- Every network attempt: destination, allowed or blocked, byte counts.
- Every filesystem access outside the mounted set.
- Local append-only JSONL. Greppable. `airlock log --server acme --blocked`.

---

## 4. The snapshot mechanism

This is the part that makes Solari load-bearing rather than decorative, and it
solves two problems with one primitive.

### 4.1 How it works

1. First run for a given server: `create({ template: "base" })`, install the
   server (`npx -y`, `uvx`, or `pip install`), install the egress proxy and
   iptables rules from §3.2, let it reach a ready state.
2. `snapshot("airlock-<server>-<version>")` → snapshot ID.
3. Record the snapshot ID against the server's policy entry, alongside the
   resolved package version.
4. Every subsequent launch is `create({ template: "base", fromSnapshot: snapId })`.
5. `revert(snapId)` is also available if you want to reuse one long-lived sandbox
   and reset it between sessions instead of forking a fresh one.

### 4.2 What this buys

| Problem | How the snapshot solves it |
|---------|---------------------------|
| Cold start latency | Resume is milliseconds; no reinstall, no npm fetch |
| Supply-chain updates | Snapshot is immutable; a poisoned upstream release cannot reach you |
| Reproducibility | The same bytes run every time, across machines |
| Team distribution | Share the snapshot ID and the policy; teammates get the vetted build |

### 4.3 Re-snapshotting

Updating a server is an explicit, auditable act:

```
airlock update acme     # provision fresh, install latest, diff tool schemas, re-snapshot
```

The diff is shown before the new snapshot is adopted. Updates become a decision
rather than an accident.

---

## 5. Why Solari and not Docker

Reviewers will ask this within thirty seconds. The README must answer it before
they do.

| Dimension | Docker locally | Airlock on Solari |
|-----------|---------------|-------------------|
| Prerequisite | Docker daemon, image builds, disk | An API key |
| Locked-down corporate laptop | Often not permitted | Works |
| Blast radius of an escape | Your machine | Someone else's cloud |
| Cold start | Seconds, plus image pull | Milliseconds from snapshot |
| Version pinning | Possible, manual, verbose | Free, it's the snapshot |
| Team-wide policy | Bespoke tooling | A committed config file |
| Local resource cost | Your CPU and RAM | None |

Honest counterpoint to include: Docker is free and offline. Airlock costs money
per sandbox-hour and requires connectivity. State that plainly — the comparison
is more credible when it names its own weakness.

---

## 6. Scope

### 6.1 In scope for the weekend

- stdio transport only. Covers the overwhelming majority of servers.
- Launchers: `npx`, `uvx`, `python -m`.
- `airlock.toml` policy file, one block per server.
- `airlock init` — read an existing Claude Code or Cursor config, generate policy stubs.
- `airlock run <server>` — the wrapper the client invokes.
- `airlock approve <server>` — hash and pin tool definitions.
- `airlock log` — read the audit trail.
- Filesystem scoping and egress allowlist, both working and demonstrable.
- Three real, unmodified third-party MCP servers running end to end.
- The evil-server demo (§8).

### 6.2 Explicitly out of scope

- Streamable HTTP and SSE remote servers. Note as future work.
- Windows support. Document as untested.
- A GUI or web dashboard. The CLI plus the log is enough.
- Warm pooling and multi-tenant scheduling. Mention in the roadmap.
- Actual injection *blocking*. Warnings only.

### 6.3 Example policy file

```toml
[server.github]
launcher   = "npx"
package    = "@modelcontextprotocol/server-github"
egress     = ["api.github.com"]
mounts     = []
secrets    = { GITHUB_TOKEN = "keyring:github-mcp" }
snapshot   = "snap_..."          # written by airlock on first run

[server.filesystem]
launcher   = "npx"
package    = "@modelcontextprotocol/server-filesystem"
egress     = []                   # no network at all
mounts     = [{ path = "~/projects/demo", mode = "rw" }]
snapshot   = "snap_..."
```

---

## 7. Open questions to resolve on day one

Two of the original six are now answered from the docs (§0.1). What remains needs
a live API key to settle.

| # | Question | Why it matters | Fallback if the answer is bad |
|---|----------|----------------|-------------------------------|
| 1 | ~~Snapshot create and restore?~~ | — | ✅ Resolved: `snapshot()`, `revert()`, `fromSnapshot` |
| 2 | ~~Native egress allowlisting?~~ | — | ✅ Resolved: none exists. Build it in-VM per §3.2 |
| 3 | ~~Root in the sandbox, and can you run `iptables`?~~ | — | ✅ Resolved: root yes, `xt_owner` no. §3.2 rewritten around netns + unix-socket bridge, and it is a *hard* boundary |
| 4 | ~~Per-call round-trip latency?~~ | — | ⚠️ Partly: 256ms p50 for one-shot `exec`, 1426ms cold boot. The relay figure that actually decides usability is still unmeasured |
| 5 | ~~Does `base` ship node and python?~~ | — | ✅ Resolved: node 18.20.4, python 3.11.2, plus npm/npx/pip3/git/curl. `uv`/`uvx` must be installed |
| 6 | Free-tier concurrency cap? | One sandbox per server adds up | Multiplex servers into one sandbox, weaker isolation, documented |
| 7 | Is `pause`+`autoResume` cheaper and faster than `fromSnapshot`? | Warm-start strategy | Measure both, pick one, explain the choice |
| 8 | Does the stdio relay work over `WS /control/:id` cleanly? | Core mechanism | `exec` with streaming stdin/stdout as the alternative path |

Question 3 is settled — see `docs/FINDINGS-DAY1.md`. Questions 6, 7 and 8 remain,
and 8 is now the load-bearing one: the SDK exposes `commands.start()` returning a
handle with `stdin()`, `onData()`, `wait()` and `kill()`, which is the right
shape, but it has not yet been driven by a real MCP server.

---

## 8. The demo

The demo is the actual deliverable. The code is the evidence that the demo is real.

### 8.1 Structure

Forty seconds, split screen, no narration required.

**Left panel — server running natively**

1. A deliberately malicious MCP server is added to the config.
2. The agent calls an innocuous-looking tool.
3. The server reads a credential file and POSTs its contents.
4. A local listener prints the captured secret in plain text.

**Right panel — same server, same call, under Airlock**

1. Identical config except the command is wrapped.
2. Same tool call.
3. Credential file read returns `ENOENT`.
4. The POST fails: destination not on the allowlist.
5. `airlock log --blocked` shows both attempts, timestamped.

### 8.2 Safety rules for the demo — non-negotiable

- The "stolen" credential is a **fake file with fake contents**, created by the
  demo script in a temp directory. Never a real `~/.aws/credentials`.
- The exfiltration target is **localhost**. Never a real remote endpoint.
- The evil server is clearly labelled, lives in `demo/evil-server/`, and its
  README states it is inert and for demonstration only.
- No published payload should function against any real service.
- Say all of this in the repo. Reviewers judging security work will check whether
  the author understood the responsibility.

### 8.3 Assets to produce

- 40-second screen recording, no audio needed, captioned.
- A GIF of the same, for the README hero.
- A terminal transcript in the README for people who don't play video.

---

## 9. Documentation to write

All of it. Documentation is not overhead here — for a security tool it *is* the
product, because nobody adopts a boundary they don't understand.

| File | Contents | Priority |
|------|----------|----------|
| `README.md` | Hero GIF, the problem in three lines, install, one-line config change, the Docker comparison, limitations | P0 |
| `docs/THREAT-MODEL.md` | What Airlock defends against, what it does not, explicit non-goals, residual risk | P0 |
| `docs/ARCHITECTURE.md` | Transport interposition, relay, lifecycle, snapshot flow, diagrams | P0 |
| `docs/POLICY.md` | Every `airlock.toml` field, types, defaults, worked examples per server | P0 |
| `docs/QUICKSTART.md` | Zero to a jailed server in five minutes, including getting a Solari key | P1 |
| `docs/LIMITATIONS.md` | Latency, cost, servers that don't fit, Windows, remote transports | P1 |
| `docs/WHY-SOLARI.md` | The snapshot argument, the comparison table, honest weaknesses | P1 |
| `demo/README.md` | How to run the demo, and the safety statement from §8.2 | P0 |
| `CONTRIBUTING.md` | How to add a launcher, how to add a policy control | P2 |

### 9.1 Reference material to read and cite

Collect these before writing, and link them from the docs so claims are traceable.

**Solari**

- `docs.getsolari.com` — sandboxes: create, connect, commands, files, kill
- `docs.getsolari.com` — snapshots and templates
- `docs.getsolari.com` — pricing and plan limits
- `docs.getsolari.com` — errors and retry semantics
- `github.com/solari-sdk/solari-cookbook` — `sandbox-quickstart-ts`,
  `sandbox-code-interpreter-py`, `sandbox-port-preview-ts`
- Cookbook gotchas, which must be honoured in the code: `kill()` not `close()`,
  commands are not shell-interpreted, `timeoutMs` is a rolling idle window

**MCP**

- Specification: base protocol, JSON-RPC framing, lifecycle
- Specification: stdio transport
- Specification: tools, including description and schema fields
- Security best practices section of the spec
- Claude Code and Cursor MCP configuration formats

**Prior art and threat research**

- Published MCP tool-poisoning and rug-pull writeups
- Egress-control approaches from comparable sandbox platforms
- Existing MCP proxy and gateway projects, and why they don't isolate

---

## 10. Build order

Sequenced so that something demonstrable exists early and the risky unknowns are
resolved first.

1. Get the API key. Run a cookbook sandbox example unmodified. Confirm boot and kill.
2. Settle open question 3 in the first hour: `id`, `iptables -L`, can you drop
   privileges. This determines whether §3.2 is a hard boundary or best-effort.
3. Build the bare relay: stdio in, sandbox stdio out, no policy. Prove a real
   server works unmodified through it.
4. Add selective file admission. Confirm `~/.ssh` reads return `ENOENT`, which it
   should already, since there is no host mount at all.
5. Add the egress proxy plus iptables. Prove a blocked POST fails.
6. Add the snapshot flow (`snapshot` / `fromSnapshot`). Measure and record startup
   before and after, with real numbers.
7. Add the audit log.
8. Write the evil server and record the demo.
9. Add definition pinning if time remains.
10. Write the docs. Do not treat this as optional; budget real hours.
11. Publish, then post, leading with the demo rather than the code.

---

## 11. Success criteria

- Three real third-party MCP servers work through Airlock, unmodified.
- The evil server demonstrably fails at both filesystem and network.
- Startup from snapshot is fast enough to use daily, with a measured number.
- A reader of the README understands the threat model in under two minutes.
- The Docker question is answered before it is asked.
- Nothing published could be repurposed against a real service.

---

## 12. Risks

| Risk | Mitigation |
|------|-----------|
| ~~No root or no iptables in the sandbox~~ | ✅ Retired. Root yes, `xt_owner` no; §3.2 rebuilt on netns + unix-socket bridge, verified 7/7 |
| ~~Malicious server escalates to root and flushes the rules~~ | ✅ Retired. There are no rules to flush; escape now requires `CAP_SYS_ADMIN` the process cannot acquire |
| Kernel-level container escape | Documented boundary; blast radius is still a disposable VM with no user data |
| Latency makes it unpleasant to use | Measure early; if bad, reposition as a vetting harness rather than daily runtime |
| Free-tier caps block a multi-server demo | Request a quota bump early; fall back to multiplexing |
| Runaway sandbox cost | Explicit `kill()` in every teardown path, aggressive idle timeouts, cost in the log |
| Reads as a security-theatre demo | Real servers running unmodified is the proof; lead with that |
| Scope creep into a full gateway | The out-of-scope list in §6.2 is binding |
