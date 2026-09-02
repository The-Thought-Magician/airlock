# Day-one findings

Measured against a live Solari sandbox on 2026-09-02, using the probes in
`scripts/`. Every number and claim here is reproducible with `npm run probe*`;
raw output is in `findings/*.json`.

This document settles the open questions in `SPEC.md` §7 and **supersedes the
mechanism described in §3.2**.

---

## Summary

| # | Question (SPEC §7) | Answer |
|---|--------------------|--------|
| 3 | Root in the sandbox? `iptables`? | **Root yes, iptables partly** — see below. The spec's uid-keyed design is not buildable; a stronger one is. |
| 4 | Per-call round-trip latency | **253ms p50**, which is one network RTT to the gateway. Airlock adds ~0. |
| 5 | Does `base` ship node and python? | **Yes.** node v18.20.4, python 3.11.2, npm, npx, pip3, git, curl. |
| 8 | Does the stdio relay work over the control channel? | **Yes, proven** — a real unmodified MCP server runs end to end through it. |

Still open: Q6 (concurrency cap), Q7 (`pause`+`autoResume` vs `fromSnapshot`).

---

## 1. The sandbox environment

Debian 12 (bookworm), kernel 6.6.30, `x86_64`.

- **We are `uid=0(root)`** with the full capability bounding set, including
  `cap_net_admin`, `cap_net_raw`, and `cap_sys_admin`.
- `no-new-privs=0`, so we can set it ourselves on child processes.
- No passwordless `sudo` — irrelevant, we start as root.
- **The kernel has no loadable modules**: no `/lib/modules`, no `modprobe`,
  no `lsmod`. Whatever is compiled in is all there is. This is the single fact
  that breaks the spec's §3.2 design.

Preinstalled: `node v18.20.4`, `npm`, `npx`, `python3 3.11.2`, `pip3`, `git`,
`curl`, `unshare`, `nsenter`, `setpriv`.
Absent but `apt-get`-installable: `iptables`, `iproute2`, `socat`, `tinyproxy`,
`uv`/`uvx`, `wget`.

Note for §6.1: the `npx` and `python -m` launchers work out of the box. The
`uvx` launcher needs `uv` installed at snapshot-build time. Node 18 is old
enough that some MCP servers will want a newer one baked into the snapshot.

**Egress is unrestricted by default.** A fresh sandbox reaches the whole
internet. This is exactly what §3.2 has to fix.

---

## 2. Why SPEC §3.2 does not work as written

The spec proposed: run the server as an unprivileged uid, then
`iptables -m owner --uid-owner <mcp> -j DROP` everything except the loopback
proxy. Three separate parts of that fail:

| Component | Result |
|-----------|--------|
| `xt_owner` (the `--uid-owner` match) | **Absent.** `Extension owner revision 0 not supported, missing kernel module` — and there are no modules to load. |
| `nf_tables` backend (default `iptables`) | **Broken.** `Could not fetch rule set generation id: Invalid argument`. Even the `REJECT` target is unavailable. |
| `veth` (for the usual netns pairing) | **Absent.** `ip link add … type veth` → `Unknown device type`. |

What *does* work:

- `iptables-legacy` with plain destination rules. Installing
  `iptables-legacy -A OUTPUT -d 1.1.1.1 -j REJECT` succeeds and genuinely
  blocks (curl exit 7).
- `ip netns add` — namespace creation works fine.

So the uid-keyed boundary is off the table. But the fallback the spec braced
for ("proxy-only enforcement, relabelled best-effort") is **not** needed,
because a stronger mechanism is available.

---

## 3. The mechanism that replaces it: netns blackout + unix-socket bridge

A network namespace with **no interfaces at all** is a total network blackout —
enforced by the absence of a route, not by a match rule that has to be
evaluated correctly. Unix domain sockets are filesystem objects, so they cross
a namespace boundary freely. That gives a bridge with no bypass:

```
   ┌─ netns "airlock" — no interfaces, lo only ─┐   ┌─ root netns ─────────┐
   │                                            │   │                      │
   │  MCP server (uid 4000 mcp, no-new-privs)   │   │  tinyproxy :8888     │
   │    HTTP_PROXY=127.0.0.1:8888               │   │  domain allowlist    │
   │        │                                   │   │        ▲             │
   │        ▼                                   │   │        │             │
   │  socat TCP-LISTEN:8888 ────────────────────┼───┼─ socat UNIX-LISTEN   │
   │                    /run/airlock/proxy.sock │   │                      │
   └────────────────────────────────────────────┘   └──────────────────────┘
                    (shared filesystem crosses the netns)
```

The server sees an ordinary HTTP proxy on loopback and needs no modification.

### Why this is stronger than the spec's design

The spec's own honest-residual-risk note said a server reaching root could
flush the iptables rules. Here there is no rule to flush. Escaping requires
`CAP_SYS_ADMIN` to `setns` back into the host namespace, which an unprivileged
uid started with `--no-new-privs` does not have and cannot acquire.

Ignoring `HTTP_PROXY` also buys an attacker nothing: there is no interface to
reach anything directly, so there is no route to ignore it *to*.

### Verified — 7/7 checks, `npm run probe:netns`

| Check | Result |
|-------|--------|
| Bare netns is a total network blackout | PASS — curl exit 6 |
| Proxy allows allowlisted host, refuses others | PASS — 200 / refused |
| Jailed `mcp` reaches allowlisted host through the bridge | PASS — HTTP 200 |
| Jailed `mcp` refused for non-allowlisted host | PASS — curl exit 56 |
| Raw socket to hardcoded IPs (ignoring `HTTP_PROXY`) | PASS — all `OSError`, no route |
| DNS from the jail | PASS — `gaierror`, kills DNS-tunnel exfil |
| `nsenter` back to the host namespace | PASS — `Permission denied` |

Two consequences for the spec's threat model:

- **DNS-based exfiltration moves from "out of scope" to "blocked."** The jail
  has no DNS at all; the proxy resolves on the server's behalf.
- Allowlisted-host abuse (posting a secret to a gist on an allowed domain)
  remains out of scope and must stay named as such.

The residual risk to document is now narrower: a kernel-level container escape,
rather than "root in the VM flushes the rules."

### The audit source

tinyproxy logs every decision, which is exactly what §3.6 needs:

```
CONNECT  Request (file descriptor 2): CONNECT api.github.com:443 HTTP/1.1
CONNECT  Established connection to host "api.github.com" using fd 3.
CONNECT  Request (file descriptor 2): CONNECT example.com:443 HTTP/1.1
NOTICE   Proxying refused on filtered domain "example.com"
```

`airlock.toml`'s `egress` list compiles to one anchored ERE per line in the
tinyproxy filter file, with `FilterDefaultDeny Yes`.

---

## 4. Latency (Q4) — answered, and the answer is "it's your RTT"

I expected the relay to be much faster than the one-shot `exec` path, on the
grounds that `exec` pays for a process spawn each call while the relay reuses a
live process on an open WebSocket. **That hypothesis was wrong**, and the way it
was wrong is the useful finding.

| Path | mean | p50 | p95 | min |
|------|------|-----|-----|-----|
| One-shot `exec` (`probe.ts`) | 285 ms | 256 ms | 515 ms | — |
| **Live relay, `tools/list`** (`relay-e2e.ts`) | **266 ms** | **253 ms** | 397 ms | **250 ms** |

The two are the same, and the relay has a hard floor at 250ms. Measuring the
raw network path explains why:

```
$ curl -w 'connect=%{time_connect}s' https://api.getsolari.com/
connect=0.263s    connect=0.275s    connect=0.263s
```

**A bare TCP connect to the gateway is ~263ms.** The entire per-call latency is
one network round trip between the developer's machine and the Solari gateway.
Airlock's relay adds no measurable overhead on top of it, and neither does the
process spawn — the `exec` path was never the bottleneck.

What to publish, then, is not "Airlock costs 253ms" but:

> Airlock adds no measurable latency of its own. Per-call cost is one round trip
> to your nearest Solari region — 253 ms p50 from the machine these numbers were
> taken on, where a bare TCP connect to the gateway is 263 ms. Closer to the
> region, it is proportionally less.

That framing is both honest and more useful, because it tells a reader the
number is a property of their network rather than of the tool. It also means the
"reposition as a vetting harness if latency is bad" fallback in §7 is not needed
for architectural reasons — there is nothing to optimise away.

Other measurements:

- Cold boot of a `base` sandbox: **1223–1426 ms**
- `npm install -g` of a real MCP server: **4.0 s** (this is what §4 snapshots away)
- Server process start once installed: **414 ms**
- MCP `initialize` handshake: **466 ms**

---

## 4b. The relay works (Q8)

`scripts/relay-e2e.ts` drives `@modelcontextprotocol/server-everything`,
unmodified, inside a sandbox:

```
sandbox up in 1223ms
installed in 4.0s
server process started in 414ms
initialize  466ms  →  mcp-servers/everything 2.0.0
tools/list  260ms  →  13 tools: echo, get-annotated-message, get-env, …
tools/call  334ms  →  "Echo: airlock"
```

`commands.start()` is the right primitive: frames arriving before `onData` is
attached are buffered by the SDK, so there is no startup race, and `stdin()` /
`wait()` / `kill()` cover the rest of the lifecycle. Q8 is settled.

### One caveat found by reading the SDK

`cmd.data` frames are base64 on the wire, but the SDK decodes each frame with a
fresh `new TextDecoder()` and no `{ stream: true }`. A multi-byte UTF-8
character split across two frames will therefore be corrupted into replacement
characters before Airlock ever sees it.

This has not been observed in practice and needs a chunk boundary to land
mid-character, but it is a real defect on a path that carries arbitrary tool
output. It belongs in `docs/LIMITATIONS.md`. The fix, if it bites, is to wrap
the server in the guest so its stdout is base64-framed per line, which keeps the
transport pure ASCII — that wrapper is also the natural place to hook the §3.6
audit log.

---

## 5. What this changes in the build

- §3.2 needs rewriting around netns + unix-socket bridge. The "best-effort
  fallback" paragraph can be deleted; the control is a hard boundary.
- The snapshot build (§4.1) additionally installs `socat`, `tinyproxy`,
  `iproute2`, creates the `mcp` user, and pre-creates the namespace and bridge
  units, so all of it exists before any third-party code runs.
- `iptables` is not needed at all in the final design. Keep
  `iptables-legacy` in mind only as a belt-and-braces extra.
- Server launch becomes:
  `ip netns exec airlock setpriv --reuid=4000 --regid=4000 --clear-groups --no-new-privs <launcher>`
- Q7 (`pause`+`autoResume` vs `fromSnapshot`) is still unmeasured and should be
  settled when the snapshot flow is built.

---

## Addendum (2026-09-02, later): egress relies on the client honouring HTTP_PROXY

Found while building credential brokering. The jail forces traffic through the
proxy by having no route to anything else, and injects `HTTP_PROXY` /
`HTTPS_PROXY` so proxy-aware clients use it. But **Node's built-in `fetch`
(undici) ignores those variables.** A server that uses global `fetch` therefore
cannot reach anything at all — it fails closed with a connection error rather
than leaking, so it is *safe*, but the allowlisted host does not work either.

- `curl`, `python-requests`, and most language HTTP stacks honour the proxy
  variables and work, brokering included (`npm run test:broker` passes 3/3
  through curl).
- Node `fetch` needs an explicit `ProxyAgent`; the server would have to opt in.
- This is a usability limitation, not a security hole — the failure mode is "no
  network" not "unfiltered network". It belongs in `docs/LIMITATIONS.md`, and a
  future mitigation is to inject a `NODE_OPTIONS` shim that installs a global
  undici dispatcher pointed at the proxy.

## Reproducing

```bash
set -a && . ./.env && set +a
npm run probe            # environment, privileges, runtimes, latency
npm run probe:egress     # the spec's original §3.2 design (fails, kept as evidence)
npm run probe:netfilter  # why it fails: modules, backends, veth
npm run probe:netns      # the replacement mechanism (7/7)
npm run relay:e2e        # a real MCP server end to end, and the honest latency
```

Each writes a timestamped JSON to `findings/`.
