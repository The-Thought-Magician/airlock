# Why Solari, and not Docker

Reviewers ask this within thirty seconds, so here is the answer with its own
weaknesses named — the comparison is more credible when it does that.

## The comparison

| Dimension | Docker locally | Airlock on Solari |
|-----------|----------------|-------------------|
| Prerequisite | Docker daemon, image builds, disk | An API key |
| Locked-down corporate laptop | Often not permitted | Works |
| Blast radius of an escape | Your machine | A disposable cloud VM |
| Local resource cost | Your CPU and RAM | None |
| Team-wide policy | Bespoke tooling | A committed config file |
| Version pinning | Manual, verbose | A committed `tpl_…` (best-effort, see below) |
| **Cost** | **Free** | **Per sandbox-hour** |
| **Offline** | **Yes** | **No — needs connectivity** |
| Per-call latency | None | One round trip to your region (~250 ms) |

## The honest counterpoint

**Docker is free and offline. Airlock is neither.** If you already run Docker,
your machine isn't locked down, and you don't mind the blast radius being your
own hardware, Docker is a perfectly good way to sandbox an MCP server and costs
nothing.

Airlock earns its place in three situations:

1. **The machine won't allow Docker.** Locked-down corporate laptops frequently
   forbid the daemon. An API key needs no admin rights.
2. **You want the blast radius off your hardware.** Even a contained escape in
   Docker is an escape *on your machine*. On Solari it's someone else's
   disposable VM with none of your files or credentials in it.
3. **The policy should be a shared, committed artifact.** `airlock.toml` — with
   its egress allowlists and mounts — lives in the repo and is reviewed like any
   other config. Docker equivalents tend to be bespoke per-developer tooling.

## The pinning story — snapshots, and why they lost

The original design pinned a **snapshot** for two reasons: fast warm starts, and
an immutable/reproducible build. Measured against the live API, the speed
argument collapsed (full numbers in [FINDINGS-WARMSTART](FINDINGS-WARMSTART.md)):

| Path | Time |
|------|------|
| Cold `base` create + full provision | **12.3 s** |
| Create from a **custom template** | **11.4 s** |
| `create({ fromSnapshot })` | **46.8 s** (3.8× slower than cold) |
| `pause()` → `resume()` | 3.4 s, then 54.5 s |
| `revert(snapshotId)` | unavailable (`409 Not revertable`) |

Snapshot restore is *slower* than reinstalling from scratch, with no warm-up
across repeats. So the "milliseconds from snapshot" claim was wrong by two
orders of magnitude, and snapshots were dropped.

What survived was never really speed — provisioning is only ~9 s. It was that a
pinned build is **immutable** (a poisoned upstream release published after the
build can't reach you), **reproducible** (same bytes every launch), and
**shareable** (a `tpl_…` id is an org artifact, not one machine's save point). A
custom template delivers all three, at ~11 s.

### The caveat that keeps this honest

Custom templates proved **unreliable to create** — 0/4 in a later run,
`No sandbox host available` on a `ready` template, while `base` was 4/4. So
pinning is best-effort: `airlock run` uses the template when the platform serves
it and falls back to a cold provision, loudly, when it doesn't. The isolation
boundary is identical either way; only the version pin is lost. If reproducible
pinning is a hard requirement for you, this is the weakest part of the tool
today, and it is platform-side.

## Where this leaves the argument

Solari is **load-bearing for the isolation story** (§3) — a remote VM with no
path to your filesystem is exactly what makes filesystem isolation structural
rather than a rule, and it is what puts the blast radius somewhere disposable.
That part is solid and measured.

Solari is **convenient but not yet dependable for the pinning story** (§4) — the
mechanism works when the platform cooperates, and degrades safely when it
doesn't. Lead with the isolation; treat the pin as a best-effort bonus.
