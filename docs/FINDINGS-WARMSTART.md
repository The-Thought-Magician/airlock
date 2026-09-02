# Warm-start findings — snapshots lose, and templates are flaky

Measured 2026-09-02 against live sandboxes. Reproduce with
`npm run probe:warmstart2` and `npm run probe:template`; raw output in
`findings/warmstart2-*.json` and `findings/template-*.json`.

**This supersedes `SPEC.md` §4 and the "Cold start" row of §5.** The spec's
claim that snapshot restore is "milliseconds" and that this is what makes
Solari load-bearing is not what the API does.

> **Read the "Update, ~90 minutes later" section before acting on the
> recommendation.** Custom templates looked like the answer at 3/3 successes,
> then went 0/4. Cold provisioning from `base` is the dependable path.

---

## The numbers

| Path | Time | Verdict |
|------|------|---------|
| Cold `base` create + full provision | **12.32 s** (create 3.0 s + provision 9.3 s) | the baseline, and it is fast |
| Create from a **custom template** | **11.40 s** (10.9 / 11.3 / 11.9) | consistent; deps and server pre-baked |
| `create({ fromSnapshot })` | **46.81 s** (57.6 / 24.5 / 58.3) | **3.8× slower than cold** |
| `pause()` → `resume()` | 3.40 s, then **54.54 s** | unusably variable |
| `revert(snapshotId)` | — | **unavailable**: `409 Not revertable` |

One-off costs: `snapshot()` 11.03 s, template build 22.5 s.

Provision breakdown, which is why the baseline is so cheap: `apt-get` 5.0 s,
`npm install -g` 3.8 s, jail setup 4.2 s. The base image has a warm apt cache
and the test server is small.

---

## What this means

### Snapshots are counterproductive for cold start

Restoring a snapshot costs ~47 s to avoid ~9 s of provisioning. Three restores
of the *same* snapshot showed no warm-up (57.6 / 24.5 / 58.3 s), so this is not
a first-fetch effect — it is the cost of the operation.

`SPEC.md` §4.2 says "Resume is milliseconds; no reinstall, no npm fetch" and §5
contrasts Docker's "seconds, plus image pull" with Airlock's "milliseconds from
snapshot". Both are wrong by two orders of magnitude, and in the wrong
direction. Publishing them would have been the most easily falsified claim in
the README — any reviewer with an API key would have found it in a minute.

### `revert()` and `pause()/resume()` are not dependable

- `revert()` returns `409 Not revertable` on every attempt, including on a
  machine that had only been snapshotted. Whatever gates it, we do not have it.
- A **failed `revert()` appears to invalidate the session**: the run that
  called `revert()` first then got `Not found` from `pause()`. Worth knowing
  before putting `revert()` in a teardown path.
- `pause()/resume()` works but is wildly variable — 3.40 s then 54.54 s on the
  same machine, with `pause()` itself costing 11–12 s. A warm-start strategy
  cannot be built on a 16× spread.

### But snapshots were carrying more than speed

§4.2 lists four benefits, and speed was only one:

| Benefit | Survives? |
|---------|-----------|
| Cold start latency | **No** — it was never true |
| Supply-chain immutability | Yes, and it matters most |
| Reproducibility | Yes |
| Team distribution | Yes |

The three that survive are the security properties, not the performance one.
For a tool whose whole argument is "trust should not be the control", that is
the better half to keep.

---

## Update, ~90 minutes later: custom templates are not dependable

The recommendation below was written on 3/3 successful creates from a custom
template at 11.4s. It did not survive the afternoon.

The same template, status still `ready`, then failed **0/4** while `base`
succeeded **4/4** in the same alternating run
(`findings/template-reliability-*.json`):

```
round 1  ok    base                   1.59s
round 1  FAIL  tpl_6c4dedb93a204a0e   28.27s  No sandbox host available
round 2  ok    base                  63.05s
round 2  FAIL  tpl_6c4dedb93a204a0e   14.15s  No sandbox host available
round 3  ok    base                   2.22s
round 3  FAIL  tpl_6c4dedb93a204a0e   12.66s  No sandbox host available
round 4  ok    base                 125.48s
round 4  FAIL  tpl_6c4dedb93a204a0e   12.98s  No sandbox host available
```

Alternating the two was the point: if both failed together it would be a
platform-wide capacity dip. Only the custom template failed, so it is specific
to custom templates — a `ready` template can be uncreatable.

Two consequences:

1. **Cold provisioning from `base` is the only dependable path**, and stays the
   default. `airlock build` is implemented and works when the platform serves
   the template, but it cannot be presented as the happy path.
2. **`airlock run` falls back**, loudly. If a pinned template cannot be
   created it provisions cold, warns three times on stderr, and writes a `warn`
   event to the audit log. The isolation boundary is unaffected — the jail is
   rebuilt either way — but the *version pin* is lost, meaning the server is
   installed as published right now rather than as vetted. Silently degrading a
   supply-chain guarantee would be worse than not offering one.

Verified: with the template uncreatable, the end-to-end suite still passes
12/12 through the fallback.

### And the timings are not stable either

Those same four rounds put `base` create at 1.59s, 63.05s, 2.22s and 125.48s.
One cold provision in the e2e run took 385s. The 12.32s baseline in the table
above was real when measured, but platform load moves it by an order of
magnitude, so no number here should be quoted as a constant.

**What this means for the project's story.** The security value is in §3 — the
netns jail, which is built inside a sandbox we control and has not failed once
across every run. §4 was always the weaker claim, and it is weaker still: it is
a supply-chain nicety the platform does not reliably support. The README should
lead with isolation and mention pinning as best-effort, not the reverse.

---

## Recommendation as originally written: custom templates instead of snapshots

*(Kept for the reasoning; superseded on reliability by the update above.)*

A custom template delivers all three surviving benefits and is *also*
marginally faster than provisioning:

- **Immutable.** Built once, then the same bytes every launch. A poisoned
  upstream release published after the build cannot reach you — which is what
  §4 actually wanted from pinning.
- **Shareable.** A `tpl_…` id committed in `airlock.toml` gives a team the
  vetted build. A snapshot is one machine's save point; a template is an org
  artifact.
- **Fast enough.** 11.40 s consistently, versus 12.32 s cold and 46.81 s from a
  snapshot.
- Side benefit: baking `procps` in fixes a real trap — the base image has no
  `pgrep`, so any liveness check written with it silently reports every process
  as dead. That cost me one round of misleading measurements.

Proposed shape, replacing §4.3's `airlock update`:

```
airlock build <server>     # build a pinned template, write tpl_… to airlock.toml
airlock run <server>       # uses the pinned template, else provisions cold
```

`airlock.toml` gains `template = "tpl_…"` where the spec had
`snapshot = "snap_…"`. The version-diffing idea from §4.3 (show what changed
before adopting a new build) still applies, just against a template.

### Where snapshots would still win

Our provision is 9.3 s because the test server is small and apt is cached. A
server with a heavy dependency tree — compiled Python extensions, a large model
download — could take minutes, and then a fixed restore cost would pay for
itself. The crossover on these measurements is roughly 45 s of provisioning.

But a custom template beats a snapshot at *both* ends of that range, so there
is no regime where snapshots are the right answer here. They stay out of the
design, and the reason is recorded rather than assumed.

---

## Honest caveat on all of it

Every number is from one machine, one region, one afternoon, with a small test
server. The gateway RTT from here is ~263 ms (see `FINDINGS-DAY1.md` §4), so
someone closer to the region will see different absolute figures. What should
generalise is the *ordering* — template ≈ cold ≪ snapshot — because that gap is
35 s wide, far too large to be noise.
