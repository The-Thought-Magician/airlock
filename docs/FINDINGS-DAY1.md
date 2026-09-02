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
| 4 | Per-call round-trip latency | **256ms p50** for one-shot `exec`. Not yet the relay number — see caveat. |
| 5 | Does `base` ship node and python? | **Yes.** node v18.20.4, python 3.11.2, npm, npx, pip3, git, curl. |
| 8 | Does the stdio relay work over the control channel? | **Looks yes** — `commands.start()` returns a handle with `stdin()`, `onData()`, `wait()`, `kill()`. Not yet exercised against a real server. |

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

## 4. Latency (Q4) — with a caveat that matters

Measured over 20 sequential trivial commands:

| Metric | One-shot `exec` |
|--------|-----------------|
| mean | 285 ms |
| p50 | 256 ms |
| p95 | 515 ms |

Cold boot of a `base` sandbox: **1426 ms**. Control-channel connect: sub-second.

**This is not yet the number that decides daily usability.** It measures a
process spawn over the one-shot REST path — a fresh command each time. The
Airlock relay keeps one long-lived process and pushes JSON-RPC frames over the
already-open control WebSocket via `commands.start()`, which should be far
cheaper. The honest per-tool-call figure has to be measured against the real
relay, and that number is what belongs in the README.

Do not publish 256ms as "Airlock's latency" — it is the ceiling, not the
measurement.

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

## Reproducing

```bash
set -a && . ./.env && set +a
npm run probe            # environment, privileges, runtimes, latency
npm run probe:egress     # the spec's original §3.2 design (fails, kept as evidence)
npm run probe:netfilter  # why it fails: modules, backends, veth
npm run probe:netns      # the replacement mechanism (7/7)
```

Each writes a timestamped JSON to `findings/`.
