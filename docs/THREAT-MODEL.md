# Threat model

Airlock is a security tool, so this document is part of the product. It states
what Airlock defends against, what it explicitly does not, and the residual risk
that remains even when it works as designed. Nothing here is aspirational —
where a claim rests on a measurement, the measurement is named.

## The threat

An MCP server is code you did not write, launched by your client as a local
process with your full privileges. The realistic attack classes:

| Class | Mechanism |
|-------|-----------|
| Typosquatting | A package one character from a popular server |
| Supply-chain compromise | A legitimate package, malicious update pushed later |
| Tool poisoning | Malicious instructions hidden in tool descriptions the agent reads |
| Rug pull | A server changes its tool definitions after you approved it |
| Credential harvesting | The server reads local secrets and posts them anywhere |

The status-quo mitigation — "only install servers you trust, and read the
source" — fails in practice: servers are installed from registries like any npm
package, updates land silently, and nobody re-audits on each bump.

## What Airlock defends against

### 1. Local filesystem theft — defended structurally

The sandbox is a remote VM with **no mechanism to reach your laptop's
filesystem**. `~/.ssh`, `~/.aws`, every `.env` — none of it is present, so a
read returns `ENOENT`. This is not a rule that could be misconfigured; the files
are absent by construction. You opt specific paths *in* via `mounts`; nothing is
admitted that you did not name.

*Verified:* the demo (`npm run demo`) shows a server reading a credential file
natively, then getting `ENOENT` for the same read under Airlock.

### 2. Network exfiltration — defended structurally

The server runs in a network namespace with **no interfaces at all** — a total
blackout, enforced by the absence of a route, not by a filter rule that has to
be evaluated correctly. Its only path out is a filtering proxy reachable over a
unix socket, which enforces a domain allowlist. Consequences, all verified
(`npm run probe:netns`, 7/7):

- A server that ignores the injected `HTTP_PROXY` and opens a **raw socket**
  reaches nothing — there is no route to ignore the proxy *to*.
- **DNS is dead** inside the jail, so DNS-tunnel exfiltration fails. (This is an
  upgrade over the original spec, which listed DNS exfil as out of scope.)
- A non-allowlisted host is refused and logged.

### 3. Rug pulls — detected and blocked at runtime

`airlock build` records a hash over every tool's name, description, and input
schema. On each `airlock run`, the live `tools/list` is hashed and compared
*before* it reaches the client. On drift, the response is replaced with an error
so the poisoned definitions never reach the agent — startup is effectively
blocked. `AIRLOCK_ALLOW_DRIFT=1` bypasses deliberately. (`npm run test:drift`.)

### 4. Credential harvesting — mitigated by brokering

With a `broker` rule, the real credential is injected by the egress proxy on
requests to an allowlisted host; the server holds nothing. Reading its own
environment yields no secret. (`npm run test:broker`, verified: the endpoint
received the injected header, the server's env never contained it.) See the
caveat in §"Residual risk" below — this requires TLS interception.

### 5. Blast radius — reduced to a disposable VM

Even in the worst case where an attacker breaks a boundary, what they are inside
is a throwaway cloud VM with none of your files or credentials. That is a far
better failure mode than the status quo, where the same code already had your
whole machine.

## What Airlock does NOT defend against — explicit non-goals

State these plainly; a security tool that overclaims is worse than one that is
honest about its edges.

- **Allowlisted-host abuse.** If you allow `github.com` and the server posts
  your data to an attacker-controlled gist on `github.com`, Airlock permits it —
  the destination is on your allowlist. Egress allowlisting is host-level, not
  content-level. Choose allowlists narrowly.
- **Prompt injection is warned, not blocked.** The §3.5 scanner flags
  suspicious tool descriptions at build time, but false positives are certain,
  so it informs you rather than refusing. A cleverly-worded description can pass
  it. The agent still reads descriptions; Airlock does not sanitize them.
- **Malicious behaviour within granted access.** A filesystem server you gave
  `rw` on `~/projects/demo` can corrupt files in `~/projects/demo`. Airlock
  scopes access; it does not judge what a server does with access you granted.
- **The server's own correctness or supply chain upstream of the pin.** If you
  `airlock build` a compromised version, you pinned a compromised version. The
  pin makes updates a decision, not an audit of the current release.
- **Anything requiring the client to change how it works** beyond the one-line
  command swap. Airlock is a drop-in or it is nothing.

## Residual risk (present even when Airlock works)

- **The boundary is a kernel-level container escape.** The egress jail is a
  network namespace the server cannot leave without `CAP_SYS_ADMIN`, which an
  unprivileged uid started with `--no-new-privs` cannot acquire. A kernel/
  container-runtime escape would defeat it. That is a materially narrower claim
  than the original spec's design could make (it conceded "root in the VM can
  flush the iptables rules"), but it is not zero. The blast radius even then is
  the disposable VM.

- **Credential brokering is real TLS interception.** To inject a header into an
  HTTPS request, the proxy terminates TLS with a CA trusted inside the sandbox,
  reads the request, and re-encrypts to the origin. Inside the disposable VM,
  scoped to allowlisted hosts, this is acceptable — but it *is* a
  man-in-the-middle, and it is a stronger mechanism than the plain proxy.
  Understand it before enabling `broker` rules. Plain `secrets` (env injection)
  does not do this, but then the server *does* receive the value.

- **Version pinning is best-effort.** Custom templates were measured failing to
  create (0/4 in one run, `No sandbox host available`, on a template whose
  status was `ready`). When a pinned template can't be created, `airlock run`
  falls back to a cold provision — the isolation boundary is unaffected, but the
  version pin is lost and the server is installed as published right now. This
  is announced loudly on stderr and in the audit log, never silently.

- **Egress relies on the client honouring the proxy.** Traffic is forced through
  the proxy by having no other route, and proxy-aware clients (curl, python,
  and node via an injected shim) use it. A client that ignores the proxy simply
  reaches nothing — it fails closed, which is safe, not a leak.

## Reproducing the claims

Every defensive claim above has a script:

```bash
npm run probe:netns    # the egress jail: raw-socket bypass, DNS, escape — 7/7
npm run test:broker    # credential brokering: injected, absent from env, egress held
npm run test:drift     # rug-pull detection: blocked by default
npm run demo           # filesystem + network, native vs jailed, self-verifying
```
