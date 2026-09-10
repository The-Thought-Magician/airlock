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

## How Airlock jails a skill

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
run its scripts. Everything the skill does happens in the sandbox.

## Honest framing

This is **not native skill loading**. Your client does not load the skill as a
first-class Claude skill; it sees a jailed MCP server that fronts the skill. The
useful thing Airlock provides is that the skill's *code runs in the sandbox*
rather than on your laptop. The convenience of the client discovering and
loading the skill natively is out of scope — that would require the client to
support it, which is not something a wrapper can add.

What you get:

- A skill's scripts execute with no access to `~/.ssh`, `~/.aws`, or any of your
  files (they are absent by construction).
- The skill's network is limited to the policy's `egress` allowlist, or nothing.
- A poisoned SKILL.md is flagged before the skill runs.

What you do not get:

- Native skill autoloading by the client.
- Zero-config: you write a policy block, same as any other server.

## Verified

- `npm run test:skill-parse` — SKILL.md parsing, injection scan, bridge
  generation (9/9, no sandbox needed).
- `npm run test:skill` — the bundled `wordcount` skill end to end (6/6): the
  bridge exposes the tools, `skill_exec` runs the bundled Python in the jail and
  returns real output, and the skill's code is confirmed unable to read host
  files or reach the network under `egress = []`.
