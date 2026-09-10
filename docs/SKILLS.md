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

## Two modes, and the tradeoff between them

There are two ways to run a skill under Airlock, and they make **different
security guarantees**. Pick deliberately.

| | Structural (MCP bridge) | Native (routed) |
|---|---|---|
| Command | `airlock run <skill>` | `airlock skill install` + `airlock exec` |
| Client sees | A jailed MCP server | A natively-discovered skill |
| Native autoload | No | **Yes** |
| Jailing guarantee | **Structural** — the client can only reach the skill's code through the jail | **Cooperative** — the SKILL.md tells the agent to route through the jail |
| Use for | **Untrusted** skills | Skills you wrote and want sandboxed |

The honest distinction: in **structural** mode the client literally cannot run
the skill's code except through the sandbox, so a malicious skill is contained
no matter what. In **native** mode the skill is discovered and loaded like any
other, and its instructions ask the agent to run commands via `airlock exec` —
which a cooperating skill does, but a malicious one could simply not. Native
mode buys you real native autoloading at the cost of the structural guarantee.

There is no way to have both native autoloading *and* structural jailing for a
skill that bundles local scripts: native execution is the client running local
code, and only the MCP-bridge path removes that local execution entirely. That
is a fundamental tradeoff, not a missing feature.

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

This copies the skill into your client's skills directory (so it is discovered
and loaded natively) and rewrites its `SKILL.md` with a preamble telling the
agent to run the skill's commands through the sandbox:

```
airlock exec wordcount -- <command>
```

`airlock exec` runs the command in the jail (no files, policy-limited egress),
reusing a warm sandbox between calls so it is not an ~11 s boot every time — the
first exec is ~11 s, subsequent ones ~4 s. It needs a `[server.<name>]` policy
block with `launcher = "skill"` so it knows how to jail the skill.

The catch, stated in the installed SKILL.md itself: this is **cooperative**. The
agent follows the instruction to route through `airlock exec`; nothing structural
forces it to. A skill you wrote gets native loading and off-machine execution; an
untrusted skill should use structural mode instead.

## Verified

- `npm run test:skill-parse` — SKILL.md parsing, injection scan, bridge
  generation (9/9, no sandbox needed).
- `npm run test:skill` — the bundled `wordcount` skill end to end in **structural
  mode** (6/6): the bridge exposes the tools, `skill_exec` runs the bundled
  Python in the jail and returns real output, and the skill's code is confirmed
  unable to read host files or reach the network under `egress = []`.
- **Native mode** verified live: `airlock skill install` writes the routed
  SKILL.md and copies the scripts; `airlock exec wordcount -- …` runs the skill
  jailed (host file read → `No such file or directory`, network → blocked,
  correct output returned), with warm reuse dropping the second call from ~11 s
  to ~4 s.

## A correction

An earlier version of this doc claimed a wrapper "can't make the client natively
discover skills". That was too strong: native discovery is just a SKILL.md in the
skills directory, which `airlock skill install` writes. What a wrapper genuinely
cannot do is make a *natively-executed* skill's code run in the sandbox by force
— hence native mode's cooperative routing versus structural mode's guarantee.
