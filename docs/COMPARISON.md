# Benchmarks and comparison

Two questions a reviewer should ask of a security tool: does it actually block
what it claims, and how does it compare to the alternatives. This answers both,
with numbers you can reproduce.

## Security eval — the scorecard

`npm run eval` boots the real `airlock run` against a local server that exposes
one tool per attack vector and scores each as **contained** or **leaked**. Run
against the live Solari API on 2026-09-10:

```
SECURITY SCORE: 9/9 attack vectors contained
PERFORMANCE:    relay p50 308ms, p95 348ms, time-to-ready 11.4s (cold provision)
```

| # | Attack vector | What the server tries | Result |
|---|---------------|----------------------|--------|
| `fs.read_secrets` | read `~/.ssh/id_rsa`, `~/.aws/credentials` | ✅ absent (ENOENT) |
| `net.raw_socket` | raw TCP to `1.1.1.1:443`, ignoring the proxy | ✅ no route (ENETUNREACH) |
| `net.dns_exfil` | resolve a hostname to tunnel data over DNS | ✅ no DNS (EAI_AGAIN) |
| `net.http_exfil` | `curl` a non-allowlisted host | ✅ blocked |
| `escape.setns_host` | `nsenter` into the host network namespace | ✅ denied |
| `env.host_secret_leak` | read its own env for the host's `SOLARI_API_KEY` | ✅ not present |
| `egress.allowlist_works` | `curl` an allowlisted host (should succeed) | ✅ reachable |
| `egress.non_allowlisted_blocked` | `curl` a non-allowlisted host | ✅ blocked |
| `rugpull.drift_blocked` | serve tools that don't match the pinned hash | ✅ startup blocked |

The score is a self-verifying test, not a claim: `npm run eval` exits non-zero if
any vector leaks, and writes the full result to `findings/eval-<ts>.json`.

Individual mechanisms have their own deeper probes: `npm run probe:netns` (7/7 on
the egress jail), `test:broker`, `test:drift`, `test:nodefetch`, and the
`npm run demo` split-screen.

## Performance

| Metric | Measured | Note |
|--------|----------|------|
| Relay per-call round trip | ~253–308 ms p50 | This is **one network RTT to the Solari gateway** (a bare TCP connect is ~263 ms). Airlock adds no measurable overhead. |
| Time-to-ready (cold) | ~11–12 s | create + apt + install + jail. Variable with platform load (seen 1.6 s–125 s for the create step alone). |
| Time-to-ready (pinned template) | ~11 s | When the platform serves the template; best-effort, see LIMITATIONS. |

Latency is a property of your distance to the region, not of Airlock. It is fine
for interactive tool use; a workload firing hundreds of sequential calls will
feel the RTT.

## Where Airlock fits

The landscape splits in two, and Airlock is not competing with the first group:

**Sandbox infrastructure** — [e2b](https://e2b.dev) (Firecracker microVMs, ~150 ms
cold start), [Daytona](https://www.daytona.io) (containers, persistent
workspaces), Modal, Vercel Sandbox, and **Solari** itself. These are execution
substrates. None of them do MCP transport interposition or policy. **Airlock runs
on top of one of them** (Solari) and adds the MCP-specific layer. Comparing
Airlock to e2b is a category error — you'd build something like Airlock *using*
e2b or Solari.

**MCP-specific security** — the real comparables:

- **[ToolHive](https://github.com/stacklok/toolhive)** (Stacklok) — runs each MCP
  server in a **local container** (Docker/Podman/K8s) with a minimal permission
  file and no local credentials attached.
- **[Docker MCP Gateway](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/)**
  — containerized MCP orchestration and governance, **local Docker**.
- **[nono](https://nono.sh)** (nolabs-ai) — kernel-level (Landlock on Linux,
  Seatbelt on macOS) **local** sandbox for agents and the tools they call;
  structural enforcement, credential paths blocked by default.

## Feature comparison

| | Airlock | ToolHive | Docker MCP Gateway | nono |
|---|---------|----------|--------------------|------|
| MCP-specific | Yes | Yes | Yes | Partial (any CLI/tool) |
| Isolation location | **Remote cloud VM** | Local container | Local container | Local kernel sandbox |
| Blast radius of escape | **A disposable VM** | Your machine | Your machine | Your machine |
| Filesystem isolation | **Absent by construction** (no host mount exists) | Container mounts you configure | Container mounts | Landlock path rules you configure |
| Egress control | Allowlist, structural (no route) | Container network policy | Container network policy | Network rules |
| Credential brokering | Yes (proxy injects, server never holds it) | No local creds attached | — | Credential paths blocked |
| Rug-pull detection | Yes (tool-definition pin) | — | — | — |
| Drop-in (one-line config swap) | Yes | Yes | Yes | Wraps the agent/CLI |
| **Cost** | **Per sandbox-hour** | Free | Free (Docker) | Free |
| **Offline** | **No** | Yes | Yes | Yes |
| Per-call latency | ~300 ms (one RTT) | Near-zero (local) | Near-zero | Near-zero |
| Maturity | Weekend prototype | v0.46, shipping | Shipping (Docker) | Shipping product |

## Where Airlock genuinely differs

1. **Isolation is off your machine.** ToolHive, Docker MCP Gateway, and nono all
   contain the server *on your hardware* — a container or kernel-sandbox escape
   is still an escape on your laptop. Airlock's boundary is a remote VM; even a
   full escape lands in a disposable cloud machine with none of your files.
2. **Filesystem access is absent by construction, not by policy.** There is no
   mechanism to mount your disk into a Solari sandbox at all, so `~/.ssh` isn't
   "denied" — it isn't there. A container bind-mount or a Landlock path rule is a
   config you can get wrong; there is nothing here to misconfigure into a leak.
3. **Credential brokering and rug-pull detection** are MCP-specific controls the
   container tools don't (yet) offer.

## Where Airlock is worse — honestly

1. **It costs money and needs connectivity.** nono and ToolHive are free, local,
   and offline. If those matter more than remote blast radius, use them.
2. **Latency.** One RTT per call (~300 ms here) versus near-zero for anything
   local. nono markets "zero latency"; that's a real advantage for local.
3. **Maturity.** This is a weekend prototype built by one person against one
   account. ToolHive is at v0.46 with a K8s operator; nono is a shipped product.
   Do not mistake this comparison for "Airlock is better" — it is "Airlock makes
   a different, defensible tradeoff."
4. **Best-effort pinning.** Custom-template reliability is platform-side (see
   LIMITATIONS); the isolation boundary is unaffected, but the version pin
   degrades to a cold provision when the platform won't serve the template.

## The one-line summary

If you want MCP isolation **on your own machine, free and offline**, use nono or
ToolHive. If you want the blast radius **off your machine entirely**, with
filesystem access that is structurally absent rather than a mount policy, and you
can pay per sandbox-hour, that's the niche Airlock fills.

## Reproduce it

```bash
set -a && . ./.env && set +a
npm run eval          # the 9/9 scorecard + latency, exits non-zero on any leak
npm run demo          # the split-screen: same evil server, native vs jailed
npm run probe:netns   # the egress jail in depth (7/7)
```
