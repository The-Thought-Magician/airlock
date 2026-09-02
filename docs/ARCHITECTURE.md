# Architecture

How Airlock actually works, and the measurements the design rests on. Where the
implementation departs from the original spec, this says why — every departure
was driven by something measured against the live API, recorded in
[FINDINGS-DAY1](FINDINGS-DAY1.md) and [FINDINGS-WARMSTART](FINDINGS-WARMSTART.md).

## 1. Transport interposition

MCP clients speak newline-delimited JSON-RPC over stdio to a subprocess. Airlock
takes that subprocess slot:

```
┌──────────────┐   stdio    ┌─────────────┐   WS/relay  ┌────────────────────┐
│ MCP client   │◄──────────►│   airlock   │◄───────────►│  Solari sandbox     │
│              │  JSON-RPC  │   (local)   │             │  ┌───────────────┐  │
└──────────────┘            │  policy     │             │  │ real MCP      │  │
                            │  layer      │             │  │ server (jailed)│ │
                            └──────┬──────┘             │  └───────────────┘  │
                                   ▼                    └────────────────────┘
                            audit log (local JSONL)
```

The **drop-in property** is the binding constraint: tool names, schemas, and
results arrive at the client byte-identical, and **nothing but protocol ever
reaches stdout**. Every diagnostic Airlock emits goes to stderr, which MCP
clients treat as logs. The e2e suite asserts this by checking that every stdout
line parses as JSON.

## 2. The relay

`src/relay.ts`. Airlock reads the client's stdin, forwards each JSON-RPC line to
the server running in the sandbox via `commands.start()` (a long-lived process
on the control WebSocket), and forwards the server's replies back to stdout. It
parses frames only to feed the audit log and to gate `tools/list`; a parse
failure never stops a frame reaching the client.

**Latency.** Measured per-call round trip is ~253 ms p50 — which turned out to
be *exactly one network round trip to the Solari gateway* (a bare TCP connect is
~263 ms). Airlock's relay adds no measurable overhead. The honest framing is
"you pay one RTT to your nearest region", not "Airlock costs 253 ms". See
FINDINGS-DAY1 §4.

**The UTF-8 wrapper.** The Solari SDK decodes each stdout frame with a fresh
`TextDecoder`, so a multi-byte UTF-8 character split across two frames corrupts
(confirmed live: 30 replacement chars in a 624 KB emoji payload). Airlock runs
the server through a small guest wrapper (`WRAP_PATH`) that base64-encodes each
stdout line — pure ASCII, immune to the split — and decodes it on the Airlock
side. `npm run test:utf8` now round-trips byte-for-byte.

## 3. Lifecycle

1. Client launches `airlock run <server>`.
2. Airlock reads the policy for `<server>` from `airlock.toml`.
3. Airlock creates a sandbox — from the pinned template if there is one, else
   from `base` (provisioning cold). If a pinned template can't be created, it
   falls back to cold, loudly (see §6).
4. As root, with the network up, Airlock installs the jail dependencies and the
   server, then **closes the jail around the launch** — nothing third-party runs
   before the boundary exists.
5. `verifyJail()` proves the boundary (see §5) and **fails closed** if it can't.
6. Airlock starts the server jailed and relays JSON-RPC both ways.
7. On client disconnect, Airlock **kills the sandbox explicitly** (`kill()`, not
   `close()` — `close()` would leave the VM billing until its idle timeout).

Every sandbox carries an `airlock` metadata label so `airlock ps` / `airlock
reap` can find and kill leaks (e.g. from a crash before teardown).

## 4. The jail (this is the core)

`src/jail.ts`. Two boundaries.

### 4.1 Filesystem — selective admission

There is no host-mount mechanism in Solari at all, so your filesystem is absent
by construction. Airlock's job is the inverse of a traditional sandbox: it syncs
*declared* paths **in** (`mounts`), read-only ones owned by root so the server
can't rewrite them, read-write ones synced back out on exit. Nothing you didn't
name can appear.

### 4.2 Egress — netns blackout + unix-socket bridge

The original spec called for `iptables -m owner --uid-owner` DROP rules. **That
is unbuildable on the sandbox kernel**: `xt_owner` is not compiled in, there are
no loadable modules, the `nf_tables` backend is broken, and `veth` is absent
(FINDINGS-DAY1 §2). The replacement is stronger:

```
   ┌─ netns "airlock" — no interfaces, lo only ─┐   ┌─ root netns ─────────┐
   │  MCP server (uid 4000, --no-new-privs)     │   │  filtering proxy     │
   │    HTTP_PROXY=127.0.0.1:8888               │   │  (tinyproxy/mitmproxy)│
   │        └─ socat TCP-LISTEN:8888 ───────────┼───┼─ socat UNIX-LISTEN   │
   │                    /run/airlock/proxy.sock │   │        └─ internet   │
   └────────────────────────────────────────────┘   └──────────────────────┘
                    (shared filesystem crosses the netns)
```

A network namespace with **no interfaces** is a total blackout — enforced by the
absence of a route, not a rule. Unix domain sockets are filesystem objects, so
they cross the namespace boundary; that is the one channel out, and it lands on
the proxy. The server sees an ordinary loopback proxy and needs no modification.

Why this is stronger than the uid-keyed design: there is no rule for a
compromised process to flush, and ignoring `HTTP_PROXY` buys nothing because
there is no route to reach anything directly. Escaping needs `CAP_SYS_ADMIN` to
`setns` back to the host namespace, which an unprivileged uid with
`--no-new-privs` cannot acquire.

**Proxy backends.** With a plain allowlist, `tinyproxy` tunnels HTTPS and
enforces the domain filter. With `broker` rules, `mitmproxy` replaces it: it
terminates TLS (CA trusted in the sandbox), injects the configured credential
per host, and enforces the same allowlist. Both listen on the same port and log
to the same file, so the audit layer treats them identically.

**Node's fetch.** Node's built-in `fetch` (undici) ignores `HTTP_PROXY`, so a
jailed node server using `fetch` would reach nothing. For node launchers with an
egress allowlist, Airlock installs `undici@5` and injects a
`NODE_OPTIONS=--require` shim that points undici's global dispatcher at the
proxy. Verified end to end (`npm run test:nodefetch`). The shim is silent on
failure, so if it can't load, fetch stays direct and fails closed.

### 4.3 Launch

```
ip netns exec airlock \
  setpriv --reuid=4000 --regid=4000 --clear-groups --no-new-privs \
  node /opt/airlock-wrap.cjs <server-entrypoint>
```

## 5. Fail-closed verification

`verifyJail()` runs before the server gets any traffic and refuses to start if
the boundary doesn't hold: it checks the process is uid 4000 (not root), that
its network-namespace inode differs from the host's, and that with `egress = []`
there are zero routes. A boundary that is assumed rather than checked is the
failure mode this project argues against, so Airlock checks its own on every
launch. Live output:

```
jail verified: uid=4000, netns=net:[4026532162] (host is net:[4026531840]), routes=0
```

## 6. Pinning: templates, not snapshots

The spec pinned a snapshot for fast warm starts and reproducibility. **Snapshots
lost on measurement** (FINDINGS-WARMSTART): `create({ fromSnapshot })` averaged
46.8 s against 12.3 s for a cold create-plus-provision, `revert()` is
unavailable on this plan, and `pause()/resume()` ranged 3.4 s–54.5 s.

A **custom template** keeps what actually mattered — immutability (an upstream
release published after the build can't reach you), reproducibility, and team
distribution (a `tpl_…` id is an org artifact, committable in the policy) — and
creates in ~11 s. So `airlock build`:

1. compiles an `Image` from `base` with the jail deps + `mcp` user + the server
   at a pinned version,
2. builds a `tpl_…` template,
3. **verifies it** by running the server and completing an MCP handshake (a
   template that builds but can't start a server would otherwise fail far from
   its cause),
4. records the tool-definition hash for §3.4,
5. writes `template`, `version`, `tools_hash` back into `airlock.toml` — a
   surgical text edit that preserves comments.

**But custom templates proved unreliable to create** (0/4 in a later run). So
pinning is best-effort: `airlock run` tries the template, and on failure falls
back to a cold provision with a loud warning and an audit event. The isolation
boundary is identical either way; only the version pin is lost.

## 7. Audit log

`src/audit.ts`. Append-only JSONL at `~/.local/state/airlock/audit.jsonl`.
Records session start/end, every tool call (arguments as a digest, so the log
isn't itself where secrets accumulate), tool results (size, duration, error),
and every network attempt with its verdict — parsed from the proxy's own log.
`airlock log --blocked` shows the refusals.

## Component map

| File | Responsibility |
|------|----------------|
| `src/cli.ts` | `run`, `build`, `init`, `log`, `policy`, `ps`, `reap`, `templates` |
| `src/relay.ts` | Bidirectional JSON-RPC pump, drift gate, teardown |
| `src/jail.ts` | netns + proxy bridge, filesystem sync, launch, `verifyJail`, node shim |
| `src/broker.ts` | mitmproxy-based credential injection (§3.3) |
| `src/template.ts` | `airlock build` — template mint + verify |
| `src/config.ts` | `airlock.toml` parsing, deny-by-default |
| `src/audit.ts` | JSONL audit log + proxy-log parsing |
| `src/tools-hash.ts` | Order-independent tool hashing + diff (§3.4) |
| `src/inject-scan.ts` | Prompt-injection heuristics (§3.5) |
| `src/mcp.ts` | Minimal MCP client (used by `build`) |
| `src/jsonrpc.ts` | Line framing |
| `src/toml-edit.ts` | Comment-preserving policy writes |
