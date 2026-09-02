# Limitations

The honest list. For a security tool, knowing the edges is part of using it
safely. Everything here is measured or observed, not hypothetical.

## Latency

Every tool call is one network round trip to the Solari gateway. Measured ~253
ms p50 from the machine these numbers were taken on, where a bare TCP connect to
the gateway is ~263 ms — so **Airlock itself adds no measurable overhead**; you
are paying your distance to the region. Closer to the region, less. This is fine
for interactive tool use but is not zero, and a latency-sensitive workload that
makes hundreds of sequential calls will feel it. (FINDINGS-DAY1 §4.)

## Startup time is variable

Cold provisioning a server (create + apt + install + jail) was ~12 s in a good
run, but the underlying `create` ranged from **1.6 s to 125 s** under differing
platform load, and one provision took 385 s. No startup number here is a
constant; treat them as order-of-magnitude. A pinned template creates in ~11 s
when the platform serves it — but see the next point.

## Version pinning is best-effort

Custom templates (`airlock build`) are the pinning mechanism. They were measured
**failing to create 0/4 times** in one run — `No sandbox host available`, on a
template whose own status was `ready`, while `base` succeeded 4/4 in the same
run. This is platform-side and outside Airlock's control.

The mitigation is a loud fallback: when a pinned template can't be created,
`airlock run` provisions cold instead, warns three times on stderr, and writes
an audit event. **The isolation boundary is unaffected** — the jail is rebuilt
either way — but the version pin is lost, so the server is installed as published
right now rather than the build you vetted. Never silent. (FINDINGS-WARMSTART.)

## Cost and connectivity

Airlock runs servers on paid cloud sandboxes and needs connectivity. It is not
free and not offline — the two things Docker is. If those matter more than
blast-radius-off-your-machine or a committed team policy, use Docker. (WHY-SOLARI.)

## Egress needs a proxy-aware client

Traffic is forced through the proxy by giving the server no other route. Clients
that honour `HTTP_PROXY` — curl, python-requests, and node's `fetch` via an
injected shim — work. A client that ignores the proxy reaches **nothing**: it
fails closed, which is safe, but that host won't work for it. If you write or
choose a server that uses an exotic HTTP stack, test that it honours the proxy.

## Credential brokering is TLS interception

`broker` rules work by terminating TLS at the proxy with a CA trusted inside the
sandbox, injecting the header, and re-encrypting to the origin. Scoped to the
disposable VM and to allowlisted hosts, but it is a real man-in-the-middle and a
stronger mechanism than the plain proxy. If that tradeoff is unacceptable for a
given host, use `secrets` (env injection) instead and accept that the server
then holds the value. (THREAT-MODEL.)

## Prompt-injection scanning is warnings-only

The §3.5 scanner flags suspicious tool descriptions at build time but does not
block — false positives are certain. A carefully-worded poisoned description can
pass it. It is an aid to a human reviewer, not a filter.

## Allowlisting is host-level

If you allow a host, the server may send anything to it, including your data to
an attacker-controlled resource on that host (a gist on an allowed domain, say).
Airlock does not inspect content. Keep allowlists narrow.

## Scope not covered

- **Transports:** stdio only. Streamable-HTTP and SSE remote MCP servers are not
  supported. Future work.
- **Launchers:** `npx`, `python`, `uvx`, and `local`. Others would need a new
  launcher (see CONTRIBUTING).
- **Windows:** untested. The CLI is developed on Linux; the sandbox side is
  Linux regardless, but the local client-side path handling is unverified on
  Windows.
- **Large working trees:** `mounts` uploads files over the control channel, one
  by one. A big tree is slow to sync in; bake stable trees into a template or
  attach a volume instead.
- **Warm pooling / multi-tenant scheduling:** not implemented. One sandbox per
  running server; they add up against the free-tier concurrency cap.

## A known upstream quirk, worked around

The Solari SDK decodes each stdout frame with a fresh `TextDecoder`, which
corrupts a multi-byte UTF-8 character split across two frames. Airlock works
around it with a base64-framing guest wrapper (ARCHITECTURE §2), so tool output
round-trips intact — but the underlying SDK behaviour is worth knowing if you
build directly against it.

## Reliability posture

This is a weekend prototype built against the live API. The isolation boundary
(§3.1, §3.2) is the part to trust and has not failed across every run. The
convenience layers on top of it (pinning, brokering) are documented with their
real reliability. It is not production-hardened, has no test coverage beyond the
end-to-end scripts, and has been exercised by one person against one account.
