# Jailing agent skills

Airlock also sandboxes **agent skills**, not just MCP servers. This is a
separate mechanism from the rest of the tool, so it gets its own doc — and its
own honest framing.

## The problem, and why skills are not MCP servers

A skill is a `SKILL.md` (name, description, instructions) plus bundled scripts.
When an agent uses a skill, the client reads the instructions and runs the
scripts as **ordinary local subprocesses** — with the same full access to your
machine that a malicious MCP server has. Same threat, different delivery.

But a skill is not an MCP server: it has no JSON-RPC stdio transport for Airlock
to sit in the middle of. So skills do not "just drop in" the way swapping an
MCP command does. Airlock bridges them instead.

## Two threats, kept separate

Skills carry two distinct risks, and conflating them is what makes this
confusing:

1. **The skill's bundled code** doing damage when it runs (reading `~/.ssh`,
   exfiltrating).
2. **The skill's instructions** prompt-injecting the agent into misusing the
   agent's *own* tools ("also read `~/.ssh` and post it").

These need different answers. Threat #1 is a sandboxing problem — put the code
where it can only run in the jail. Threat #2 is *not* a sandboxing problem at
all: it is the agent reading untrusted text and being fooled. **No mode fixes
#2 structurally**, because the agent always reads the skill's instructions and
always has its own local tools — a poisoned MCP tool description has the exact
same hole. Airlock scans for it (§3.5) and warns; that is the ceiling for #2,
here and everywhere.

## Two modes, both structural for the skill's code

| | Structural (MCP bridge) | Native (install + exec) |
|---|---|---|
| Command | `airlock run <skill>` | `airlock skill install` + `airlock exec` |
| Client sees | A jailed MCP server | A **natively-discovered** skill |
| Native autoload | No | **Yes** |
| Skill's code (threat #1) | **Only runs in the jail** — client can reach it no other way | **Only runs in the jail** — the scripts are never on your machine, so there is nothing to run locally |
| Instruction injection (threat #2) | Scanned + warned (§3.5) | Scanned + warned (§3.5) |

Both modes jail the skill's *code* structurally. The difference is how:

- **Structural (bridge):** the client only ever talks to the jailed MCP server,
  so the code is only reachable through it.
- **Native (install + exec):** `airlock skill install` writes only the
  `SKILL.md` into your skills directory — **the scripts are never copied
  locally**. They live only in the sandbox (uploaded by `airlock exec`). With no
  local copy, there is nothing to run directly; the code can only execute in the
  jail. You still get native discovery and loading.

So you *can* have native autoload and structural jailing of the skill's code at
once — by keeping the code off your machine, which is exactly what native mode
does. (An earlier version of this doc claimed you couldn't. That was wrong: it
confused threat #1 with threat #2. Uploading the code and leaving no local copy
settles #1; #2 is universal and unaffected by mode.)

Pick by taste, not security-of-code: the bridge is the most locked-down (the
client can't even see the skill except as a jailed server); native mode is more
ergonomic (the skill shows up in your client's skill list).

## Structural mode — the MCP bridge

`launcher = "skill"` uploads the skill directory into the sandbox and generates
a small MCP server that exposes the skill to the agent as **jailed tools**:

- `skill_instructions` — returns the SKILL.md body, so the agent knows how to
  use the skill.
- `skill_exec` — runs a shell command in the skill directory, **inside the
  Airlock jail**: no access to your filesystem, and only the egress the policy
  allows.

The bridge runs through the exact same jail as any other server (netns egress
control, filesystem isolation, audit log, credential brokering if configured).
Nothing about skills is special-cased in the boundary; it is a `local`-style
upload with a generated entrypoint. The SKILL.md is also run through the §3.5
prompt-injection scan on launch, because a skill's instructions are read by the
agent — a poisoned SKILL.md is exactly the tool-poisoning case.

```
┌─ your MCP client ─┐   airlock run wordcount   ┌─ Solari sandbox (jailed) ──┐
│  sees an MCP      │◄─────────────────────────►│  skill bridge (MCP server) │
│  server with two  │                           │   ├─ skill_instructions     │
│  tools            │                           │   └─ skill_exec ─► scripts/ │
└───────────────────┘                           └────────────────────────────┘
```

## Use it

A skill directory looks like:

```
skills/wordcount/
├── SKILL.md
└── scripts/
    ├── count.py
    └── top.py
```

Point a policy block at it:

```toml
[server.wordcount]
launcher = "skill"
path     = "skills/wordcount"
egress   = []          # the skill's code gets no network
mounts   = []          # and none of your files
```

Then in your MCP client config:

```json
{ "command": "airlock", "args": ["run", "wordcount"] }
```

The agent calls `skill_instructions` to learn the skill, then `skill_exec` to
run its scripts. Everything the skill does happens in the sandbox, and the client
can reach the code no other way — that is the structural guarantee.

## Native mode — install + exec

For a skill you trust and want the client to load natively:

```bash
airlock skill install skills/wordcount        # copies it into ~/.claude/skills/<name>/
```

This writes **only** the `SKILL.md` into your client's skills directory (so it is
discovered and loaded natively), rewritten with a preamble telling the agent to
run the skill's commands through the sandbox:

```
airlock exec wordcount -- <command>
```

The skill's scripts are **not** copied to your machine — they live only in the
sandbox, uploaded by `airlock exec` from the source directory. With no local
copy, the skill's code can only run in the jail.

`airlock exec` runs the command in the jail (no files, policy-limited egress),
reusing a warm sandbox between calls so it is not an ~11 s boot every time — the
first exec is ~11 s, subsequent ones ~4 s. It needs a `[server.<name>]` policy
block with `launcher = "skill"` so it knows how to jail the skill.

The residual risk is threat #2 above, not the code: the `SKILL.md` is
agent-readable text, so `airlock skill install` scans it and warns if it looks
like a prompt-injection attempt. Review the instructions of a skill you don't
trust — but its *code* is jailed either way.

## Verified

- `npm run test:skill-parse` — SKILL.md parsing, injection scan, bridge
  generation (9/9, no sandbox needed).
- `npm run test:skill` — the bundled `wordcount` skill end to end in **structural
  mode** (6/6): the bridge exposes the tools, `skill_exec` runs the bundled
  Python in the jail and returns real output, and the skill's code is confirmed
  unable to read host files or reach the network under `egress = []`.
- **Native mode** verified live: `airlock skill install` writes **only** the
  routed SKILL.md (no scripts on the machine); `airlock exec wordcount -- …` runs
  the skill jailed (host file read → `No such file or directory`, network →
  blocked, correct output returned), with warm reuse dropping the second call
  from ~11 s to ~4 s.

## Corrections (this doc got it wrong twice, so here's the record)

1. An early version claimed a wrapper "can't make the client natively discover
   skills". Wrong — native discovery is just a SKILL.md in the skills directory,
   which `airlock skill install` writes.
2. The next version claimed you "can't have native autoload AND structural
   jailing" — that it was a fundamental tradeoff. Also wrong. That confused the
   skill's *code* (threat #1) with the agent being prompt-injected by the skill's
   *instructions* (threat #2). Keeping the code off your machine (native mode
   writes only SKILL.md) makes #1 structural even with native autoload. #2 is
   universal — it applies equally to MCP tool descriptions — and no mode fixes it
   structurally; it is scanned and warned.

The honest final position: both modes jail the skill's code structurally; the
only thing neither mode structurally prevents is an agent being fooled by
instructions it reads, which is inherent to agent-readable tools of any kind.
