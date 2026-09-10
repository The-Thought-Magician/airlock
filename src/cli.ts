#!/usr/bin/env node
/**
 * airlock — sandboxed MCP runtime.
 *
 * `airlock run <server>` is what an MCP client invokes in place of the real
 * server command, so it must keep stdout clean for protocol traffic only.
 * Every other subcommand is an ordinary CLI and prints to stdout normally.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs"
import { homedir } from "node:os"
import { resolve } from "node:path"
import { loadConfig, type ServerPolicy } from "./config.js"
import { AuditLog, defaultLogPath, type AuditEvent } from "./audit.js"
import { runRelay } from "./relay.js"
import { buildTemplate, readToolsFromTemplate } from "./template.js"
import { diffTools, renderToolDiff } from "./tools-hash.js"
import { setServerKeys } from "./toml-edit.js"
import { execInSession } from "./exec.js"
import { installSkill } from "./skill-install.js"
import { scanTools, renderInjectionFindings } from "./inject-scan.js"

const USAGE = `airlock — run MCP servers inside a Solari sandbox

usage:
  airlock run <server> [--config <path>]   relay a server (what your MCP client invokes)
  airlock exec <server> [--fresh] -- <cmd> run one command for a skill/local server in the jail
  airlock skill install <path> [--client claude] [--force]
                                           install a skill natively, routed through the jail
  airlock build <server> [--update]        mint a pinned template and record it in the policy
  airlock init [--config <path>]           generate policy stubs from an existing MCP config
  airlock log [--server <name>] [--blocked] [--limit <n>]
  airlock policy [--config <path>]         show the effective policy
  airlock ps                               list Airlock's running sandboxes
  airlock reap                             kill them (leaked sandboxes bill until idle timeout)
  airlock templates [--prune]              list pinned/unused templates, delete the unused
  airlock metrics                          live cpu/mem/disk of running sandboxes

env:
  SOLARI_API_KEY   required by \`run\`, \`build\`, and \`exec\`
  AIRLOCK_LOG      audit log path (default ${defaultLogPath()})
`

function flag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`)
  return i !== -1 ? argv[i + 1] : undefined
}
function has(argv: string[], name: string): boolean {
  return argv.includes(`--${name}`)
}

function describe(p: ServerPolicy): string {
  const egress = p.egress.length === 0 ? "none (no network at all)" : p.egress.join(", ")
  const mounts = p.mounts.length === 0 ? "none" : p.mounts.map((m) => `${m.path} (${m.mode})`).join(", ")
  return [
    `  launcher : ${p.launcher}`,
    `  package  : ${p.package}`,
    `  egress   : ${egress}`,
    `  mounts   : ${mounts}`,
    `  secrets  : ${Object.keys(p.secrets).length === 0 ? "none" : Object.keys(p.secrets).join(", ")}`,
    `  broker   : ${p.broker.length === 0 ? "none" : p.broker.map((b) => `${b.header}→${b.host}`).join(", ")}`,
    `  tool acl : ${
      p.allowTools.length === 0 && p.denyTools.length === 0
        ? "all tools"
        : [p.allowTools.length ? `allow=[${p.allowTools.join(",")}]` : "", p.denyTools.length ? `deny=[${p.denyTools.join(",")}]` : ""].filter(Boolean).join(" ")
    }`,
    `  resources: ${[p.cpu && `cpu=${p.cpu}`, p.memMb && `mem=${p.memMb}MB`, p.diskGb && `disk=${p.diskGb}GB`, p.idleMs && `idle=${p.idleMs}ms`].filter(Boolean).join(" ") || "platform default"}`,
    `  template : ${p.template ?? "(none — `airlock build` to pin one; run provisions cold meanwhile)"}`,
    `  version  : ${p.version ?? "(unpinned)"}`,
    `  tools    : ${p.toolsHash ?? "(not pinned)"}`,
  ].join("\n")
}

async function cmdRun(argv: string[]): Promise<number> {
  const name = argv[0]
  if (!name || name.startsWith("--")) {
    process.stderr.write("airlock run: a server name is required\n")
    return 2
  }
  const apiKey = process.env.SOLARI_API_KEY
  if (!apiKey) {
    process.stderr.write("airlock: SOLARI_API_KEY is not set\n")
    return 2
  }
  const config = loadConfig(flag(argv, "config"))
  const policy = config.servers[name]
  if (!policy) {
    const known = Object.keys(config.servers).join(", ") || "(none)"
    process.stderr.write(`airlock: no [server.${name}] in ${config.path}. Known servers: ${known}\n`)
    return 2
  }
  const audit = new AuditLog(process.env.AIRLOCK_LOG ?? defaultLogPath())
  return runRelay({ policy, apiKey, audit })
}

/**
 * `airlock exec <server> [--fresh] -- <command>` — run one command for a
 * skill/local server inside the jail, reusing a warm sandbox. This is the
 * execution path a natively-installed skill routes through (see SKILLS.md).
 */
async function cmdExec(argv: string[]): Promise<number> {
  const name = argv[0]
  if (!name || name.startsWith("--")) {
    process.stderr.write("airlock exec: a server name is required\n")
    return 2
  }
  const sep = argv.indexOf("--")
  if (sep === -1 || sep === argv.length - 1) {
    process.stderr.write("airlock exec: expected `airlock exec <server> [--fresh] -- <command>`\n")
    return 2
  }
  const command = argv.slice(sep + 1).join(" ")
  const optsBefore = argv.slice(1, sep)
  const apiKey = process.env.SOLARI_API_KEY
  if (!apiKey) {
    process.stderr.write("airlock: SOLARI_API_KEY is not set\n")
    return 2
  }
  const config = loadConfig(flag(argv, "config"))
  const policy = config.servers[name]
  if (!policy) {
    process.stderr.write(`airlock: no [server.${name}] in ${config.path}\n`)
    return 2
  }
  if (policy.launcher !== "skill" && policy.launcher !== "local") {
    process.stderr.write(`airlock exec: only skill/local servers support exec (${name} is ${policy.launcher})\n`)
    return 2
  }
  // Diagnostics to stderr; the command's own output goes to stdout.
  const result = await execInSession(
    policy,
    apiKey,
    command,
    (msg) => process.stderr.write(`airlock: ${msg}\n`),
    optsBefore.includes("--fresh"),
  )
  process.stdout.write(result.stdout)
  if (result.stderr) process.stderr.write(result.stderr)
  return result.exitCode
}

/**
 * `airlock skill install <path> [--client claude] [--force]` — install a skill
 * natively so the client discovers it, with its commands routed through the jail.
 */
async function cmdSkillInstall(argv: string[]): Promise<number> {
  const skillPath = argv[0]
  if (!skillPath || skillPath.startsWith("--")) {
    process.stderr.write("airlock skill install: a skill directory path is required\n")
    return 2
  }
  const client = flag(argv, "client") ?? "claude"
  try {
    const { name, dest, injectionFindings } = installSkill(resolve(skillPath), client, has(argv, "force"))
    process.stdout.write(
      `installed skill "${name}" → ${dest}\n` +
        `(only SKILL.md was written; the skill's scripts stay off your machine)\n\n` +
        `Your ${client} client will discover it natively. Its SKILL.md routes commands\n` +
        `through \`airlock exec ${name} -- <cmd>\`, so the code runs only in the sandbox.\n\n` +
        `Add a policy block so \`airlock exec\` knows how to jail it:\n\n` +
        `  [server.${name}]\n  launcher = "skill"\n  path     = ${JSON.stringify(skillPath)}\n  egress   = []\n  mounts   = []\n`,
    )
    if (injectionFindings > 0) {
      process.stdout.write(
        `\n⚠ the SKILL.md contains ${injectionFindings} prompt-injection pattern(s). The code is\n` +
          `  jailed, but the instructions are read by the agent — review them. See docs/SKILLS.md.\n`,
      )
    }
    return 0
  } catch (err) {
    process.stderr.write(`airlock skill install: ${err instanceof Error ? err.message : String(err)}\n`)
    return 1
  }
}

/**
 * `airlock build <server>` — mint a pinned template (SPEC §4).
 *
 * On a rebuild of an already-pinned server, the new tool definitions are
 * diffed against the recorded ones and the diff is shown before the template
 * is adopted. That is §4.3's promise: updates become a decision rather than an
 * accident, and a rug pull surfaces here instead of silently at runtime.
 */
async function cmdBuild(argv: string[]): Promise<number> {
  const name = argv[0]
  if (!name || name.startsWith("--")) {
    process.stderr.write("airlock build: a server name is required\n")
    return 2
  }
  const apiKey = process.env.SOLARI_API_KEY
  if (!apiKey) {
    process.stderr.write("airlock: SOLARI_API_KEY is not set\n")
    return 2
  }

  const config = loadConfig(flag(argv, "config"))
  const policy = config.servers[name]
  if (!policy) {
    const known = Object.keys(config.servers).join(", ") || "(none)"
    process.stderr.write(`airlock: no [server.${name}] in ${config.path}. Known servers: ${known}\n`)
    return 2
  }

  if (policy.template && !has(argv, "update")) {
    process.stdout.write(
      `[server.${name}] is already pinned to ${policy.template}` +
        (policy.version ? ` (${policy.package}@${policy.version})` : "") +
        `\n\nRebuild with:  airlock build ${name} --update\n`,
    )
    return 0
  }

  const log = (msg: string) => process.stdout.write(`${msg}\n`)
  const result = await buildTemplate(apiKey, policy, log)

  // ---- §4.3: diff before adopting ---------------------------------------
  if (policy.template && policy.toolsHash) {
    if (policy.toolsHash === result.toolsHash) {
      process.stdout.write("\ntool definitions are unchanged since the last build\n")
    } else {
      process.stdout.write(
        `\nTool definitions CHANGED since the pinned build.\n` +
          `  was: ${policy.toolsHash}\n  now: ${result.toolsHash}\n\n`,
      )
      let previous: Awaited<ReturnType<typeof readToolsFromTemplate>> = []
      try {
        previous = await readToolsFromTemplate(apiKey, policy, policy.template, () => {})
      } catch (err) {
        process.stdout.write(
          `(could not read the previous template to show a field-level diff: ` +
            `${err instanceof Error ? err.message : String(err)})\n`,
        )
      }
      if (previous.length > 0) {
        process.stdout.write(renderToolDiff(diffTools(previous, result.tools)) + "\n")
      }
      process.stdout.write(
        "\nReview the above. A changed description is the tool-poisoning case:\n" +
          "the agent reads descriptions, so new imperative text there can redirect it.\n",
      )
    }
  }

  // ---- §3.5: scan tool descriptions for prompt injection ----------------
  // Warnings only, at approval time — false positives are certain, so this
  // informs the human rather than blocking.
  const findings = scanTools(result.tools)
  process.stdout.write("\nprompt-injection scan (§3.5, warnings only):\n")
  process.stdout.write(renderInjectionFindings(findings) + "\n")
  if (findings.length > 0) {
    process.stdout.write("  review these before trusting the server; a description is what the agent reads.\n")
  }

  // ---- Record the pin ----------------------------------------------------
  const before = readFileSync(config.path, "utf8")
  const keys: Record<string, string> = { template: result.templateId, tools_hash: result.toolsHash }
  if (result.version) keys.version = result.version
  writeFileSync(config.path, setServerKeys(before, name, keys))

  process.stdout.write(
    `\nrecorded in ${config.path}:\n` +
      `  template   = ${JSON.stringify(result.templateId)}\n` +
      (result.version ? `  version    = ${JSON.stringify(result.version)}\n` : "") +
      `  tools_hash = ${JSON.stringify(result.toolsHash)}\n` +
      `\n${result.tools.length} tools pinned. \`airlock run ${name}\` will now use this template.\n`,
  )
  return 0
}

/**
 * `airlock ps` / `airlock reap` — find and kill Airlock's own sandboxes.
 *
 * SPEC §12 lists runaway sandbox cost as a risk, mitigated by "explicit kill()
 * in every teardown path". That covers the paths that reach teardown; a crash
 * between create and the finally block does not, and a leaked sandbox bills
 * until its idle timeout. Every sandbox Airlock creates carries an `airlock`
 * metadata label (§0.1) precisely so it can be found again.
 *
 * This also unblocks the concurrency cap (§7 Q6), which is easy to hit while
 * iterating: a template build plus a verify sandbox plus a leaked one from a
 * failed run is enough.
 */
async function cmdPs(argv: string[], kill: boolean): Promise<number> {
  const apiKey = process.env.SOLARI_API_KEY
  if (!apiKey) {
    process.stderr.write("airlock: SOLARI_API_KEY is not set\n")
    return 2
  }
  const { SolariClient } = await import("@solarisdk/sdk")
  const solari = new SolariClient({ apiKey })

  const all: { sandboxId: string; state: string; metadata: Record<string, string>; expiresAt: string }[] = []
  for await (const s of solari.sandboxes.listAll({})) {
    all.push(s)
  }
  // Only ever touch our own. Someone else's sandbox in this account is not
  // ours to reap, and a label filter is the only thing separating them.
  const ours = all.filter((s) => s.metadata?.airlock !== undefined)
  const others = all.length - ours.length

  if (ours.length === 0) {
    process.stdout.write(`no Airlock sandboxes running${others > 0 ? ` (${others} other sandbox(es) left alone)` : ""}\n`)
    return 0
  }

  for (const s of ours) {
    const label = [s.metadata.airlock, s.metadata.server].filter(Boolean).join("/")
    process.stdout.write(`${s.sandboxId.slice(0, 20)}…  ${s.state.padEnd(9)}  ${label.padEnd(22)}  expires ${s.expiresAt}\n`)
  }

  if (!kill) {
    process.stdout.write(`\n${ours.length} Airlock sandbox(es). Kill them with: airlock reap\n`)
    return 0
  }

  let killed = 0
  for (const s of ours) {
    try {
      await solari.sandboxes.kill(s.sandboxId)
      killed++
    } catch (err) {
      process.stderr.write(`  failed to kill ${s.sandboxId.slice(0, 20)}…: ${err instanceof Error ? err.message : err}\n`)
    }
  }
  process.stdout.write(`\nkilled ${killed}/${ours.length}${others > 0 ? ` (${others} non-Airlock sandbox(es) left alone)` : ""}\n`)
  return 0
}

/**
 * `airlock metrics` — live CPU/memory/disk of Airlock's running sandboxes.
 * The visibility the sandbox platforms (e2b, Daytona) offer, for the jails.
 */
async function cmdMetrics(): Promise<number> {
  const apiKey = process.env.SOLARI_API_KEY
  if (!apiKey) {
    process.stderr.write("airlock: SOLARI_API_KEY is not set\n")
    return 2
  }
  const { SolariClient } = await import("@solarisdk/sdk")
  const solari = new SolariClient({ apiKey })

  const ours: { sandboxId: string; metadata: Record<string, string> }[] = []
  for await (const s of solari.sandboxes.listAll({})) {
    if (s.metadata?.airlock !== undefined) ours.push(s)
  }
  if (ours.length === 0) {
    process.stdout.write("no Airlock sandboxes running\n")
    return 0
  }
  const mb = (bytes: number) => `${(bytes / 1024 / 1024).toFixed(0)}MB`
  for (const s of ours) {
    const label = [s.metadata.airlock, s.metadata.server].filter(Boolean).join("/")
    try {
      const handle = await solari.sandboxes.connect(s.sandboxId)
      const m = await handle.metrics()
      process.stdout.write(
        `${s.sandboxId.slice(0, 18)}…  ${label.padEnd(20)}  ` +
          `cpu ${m.cpuPct.toFixed(0)}%  mem ${mb(m.memBytes)}/${mb(m.memTotalBytes)}  disk ${mb(m.diskBytes)}\n`,
      )
    } catch (err) {
      process.stdout.write(`${s.sandboxId.slice(0, 18)}…  ${label.padEnd(20)}  (metrics unavailable)\n`)
    }
  }
  return 0
}

/**
 * `airlock templates [--prune]` — list Airlock's templates, and garbage-collect
 * the ones no policy references.
 *
 * Every `airlock build` mints a new immutable template, and a failed build
 * still leaves one behind. Without a way to see and prune them they accumulate
 * silently. `--prune` only ever deletes templates whose name Airlock minted
 * *and* which no `[server.*]` block currently pins, so a template a teammate's
 * committed policy depends on is never touched.
 */
async function cmdTemplates(argv: string[]): Promise<number> {
  const apiKey = process.env.SOLARI_API_KEY
  if (!apiKey) {
    process.stderr.write("airlock: SOLARI_API_KEY is not set\n")
    return 2
  }
  const { SolariClient } = await import("@solarisdk/sdk")
  const solari = new SolariClient({ apiKey })

  // Which templates are in use, according to the policy file.
  let pinned = new Set<string>()
  try {
    const config = loadConfig(flag(argv, "config"))
    pinned = new Set(
      Object.values(config.servers)
        .map((s) => s.template)
        .filter((t): t is string => t !== undefined),
    )
  } catch {
    process.stderr.write("airlock: no readable policy file, so nothing is considered pinned\n")
  }

  const all = await solari.templates.list()
  const ours = all.filter((t) => !t.builtin && t.name.startsWith("airlock-"))
  const foreign = all.filter((t) => !t.builtin && !t.name.startsWith("airlock-"))

  if (ours.length === 0) {
    process.stdout.write("no Airlock templates\n")
    return 0
  }

  for (const t of ours) {
    const state = pinned.has(t.templateId) ? "PINNED" : "unused"
    process.stdout.write(`${t.templateId}  ${state.padEnd(7)}  ${t.status.padEnd(9)}  ${t.name}\n`)
  }
  if (foreign.length > 0) {
    process.stdout.write(`\n(${foreign.length} non-Airlock custom template(s) not listed and never pruned)\n`)
  }

  const unused = ours.filter((t) => !pinned.has(t.templateId))
  if (!has(argv, "prune")) {
    process.stdout.write(
      `\n${pinned.size} pinned, ${unused.length} unused.` +
        (unused.length > 0 ? ` Delete the unused ones with: airlock templates --prune\n` : "\n"),
    )
    return 0
  }

  let deleted = 0
  for (const t of unused) {
    try {
      await solari.templates.delete(t.templateId)
      deleted++
      process.stdout.write(`deleted ${t.templateId}\n`)
    } catch (err) {
      // A template with live sessions is refused; that is correct behaviour.
      process.stderr.write(`  could not delete ${t.templateId}: ${err instanceof Error ? err.message : err}\n`)
    }
  }
  process.stdout.write(`\ndeleted ${deleted}/${unused.length} unused template(s); ${pinned.size} pinned left alone\n`)
  return 0
}

/**
 * Read an existing Claude Code / Cursor MCP config and emit policy stubs
 * (SPEC §6.1). Egress and mounts are deliberately left empty: the safe default
 * is nothing, and the user opts in per server.
 */
async function cmdInit(argv: string[]): Promise<number> {
  const configPath = resolve(flag(argv, "config") ?? "airlock.toml")
  if (existsSync(configPath) && !has(argv, "force")) {
    process.stderr.write(`airlock init: ${configPath} already exists (use --force to overwrite)\n`)
    return 1
  }

  const candidates = [
    resolve(homedir(), ".claude.json"),
    resolve(homedir(), ".config/claude/mcp.json"),
    resolve(homedir(), ".cursor/mcp.json"),
    resolve(".mcp.json"),
  ]
  type McpEntry = { command?: string; args?: string[] }
  const discovered: Record<string, McpEntry> = {}
  const sources: string[] = []

  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue
    try {
      const parsed = JSON.parse(readFileSync(candidate, "utf8")) as {
        mcpServers?: Record<string, McpEntry>
        projects?: Record<string, { mcpServers?: Record<string, McpEntry> }>
      }
      const found = { ...parsed.mcpServers }
      for (const project of Object.values(parsed.projects ?? {})) {
        Object.assign(found, project.mcpServers)
      }
      if (Object.keys(found).length > 0) {
        Object.assign(discovered, found)
        sources.push(candidate)
      }
    } catch {
      process.stderr.write(`airlock init: could not parse ${candidate}, skipping\n`)
    }
  }

  const blocks: string[] = [
    "# Generated by `airlock init`.",
    "#",
    "# Isolation is the default; access is the opt-in. An omitted `egress` means",
    "# no network at all, and an omitted `mounts` means the server sees none of",
    "# your filesystem. Add only what a server genuinely needs.",
    "",
  ]
  if (sources.length > 0) blocks.push(`# Discovered from: ${sources.join(", ")}`, "")

  for (const [name, entry] of Object.entries(discovered)) {
    const args = entry.args ?? []
    // `npx -y <pkg>` → package is the first non-flag argument.
    const pkg = args.find((a) => !a.startsWith("-")) ?? ""
    const launcher = entry.command === "npx" ? "npx" : entry.command?.includes("python") ? "python" : "npx"
    blocks.push(
      `[server.${name}]`,
      `launcher = ${JSON.stringify(launcher)}`,
      `package  = ${JSON.stringify(pkg)}`,
      `egress   = []   # e.g. ["api.github.com"]`,
      `mounts   = []   # e.g. [{ path = "~/projects/demo", mode = "rw" }]`,
      "",
    )
  }

  if (Object.keys(discovered).length === 0) {
    blocks.push(
      "# No existing MCP config found. Here is a starting point:",
      "#",
      '# [server.everything]',
      '# launcher = "npx"',
      '# package  = "@modelcontextprotocol/server-everything"',
      "# egress   = []",
      "# mounts   = []",
      "",
    )
  }

  writeFileSync(configPath, blocks.join("\n"))
  process.stdout.write(`wrote ${configPath}\n`)
  if (Object.keys(discovered).length > 0) {
    process.stdout.write(`found ${Object.keys(discovered).length} server(s): ${Object.keys(discovered).join(", ")}\n`)
    process.stdout.write("\nReview the egress and mounts for each, then point your MCP client at:\n")
    const first = Object.keys(discovered)[0]
    process.stdout.write(`  { "command": "airlock", "args": ["run", "${first}"] }\n`)
  }
  return 0
}

function cmdLog(argv: string[]): number {
  const events = AuditLog.read(process.env.AIRLOCK_LOG ?? defaultLogPath())
  const server = flag(argv, "server")
  const blockedOnly = has(argv, "blocked")
  const limit = Number(flag(argv, "limit") ?? 50)

  let filtered = events
  if (server) filtered = filtered.filter((e) => e.server === server)
  if (blockedOnly) filtered = filtered.filter((e) => e.kind === "net.attempt" && !e.allowed)

  if (filtered.length === 0) {
    process.stdout.write("no matching audit events\n")
    return 0
  }

  for (const e of filtered.slice(-limit)) {
    process.stdout.write(render(e) + "\n")
  }
  return 0
}

function render(e: AuditEvent): string {
  const ts = e.at.replace("T", " ").replace(/\.\d+Z$/, "")
  switch (e.kind) {
    case "session.start":
      return `${ts}  ${e.server}  session.start  egress=[${e.egress.join(",")}] mounts=[${e.mounts.join(",")}]`
    case "session.end":
      return `${ts}  ${e.server}  session.end    ${e.durationMs}ms exit=${e.exitCode ?? "?"}`
    case "tool.call":
      return `${ts}  ${e.server}  tool.call      ${e.tool} args=${e.argsDigest} (${e.argsBytes}B)`
    case "tool.result":
      return `${ts}  ${e.server}  tool.result    ${e.tool} ${e.durationMs}ms ${e.resultBytes}B${e.isError ? " ERROR" : ""}`
    case "net.attempt":
      return `${ts}  ${e.server}  net.${e.allowed ? "allow " : "BLOCK "}    ${e.host}`
    case "rpc":
      return `${ts}  ${e.server}  rpc            ${e.direction} ${e.method} ${e.bytes}B`
    case "warn":
      return `${ts}  ${e.server}  warn           ${e.message}`
  }
}

function cmdPolicy(argv: string[]): number {
  const config = loadConfig(flag(argv, "config"))
  process.stdout.write(`${config.path}\n\n`)
  for (const [name, policy] of Object.entries(config.servers)) {
    process.stdout.write(`[server.${name}]\n${describe(policy)}\n\n`)
  }
  return 0
}

async function main(): Promise<number> {
  const [, , command, ...rest] = process.argv
  switch (command) {
    case "run":
      return cmdRun(rest)
    case "exec":
      return cmdExec(rest)
    case "skill":
      if (rest[0] === "install") return cmdSkillInstall(rest.slice(1))
      process.stderr.write(`airlock skill: unknown subcommand ${JSON.stringify(rest[0])} (known: install)\n`)
      return 2
    case "build":
      return cmdBuild(rest)
    case "ps":
      return cmdPs(rest, false)
    case "reap":
      return cmdPs(rest, true)
    case "templates":
      return cmdTemplates(rest)
    case "metrics":
      return cmdMetrics()
    case "init":
      return cmdInit(rest)
    case "log":
      return cmdLog(rest)
    case "policy":
      return cmdPolicy(rest)
    case undefined:
    case "-h":
    case "--help":
      process.stdout.write(USAGE)
      return 0
    default:
      process.stderr.write(`airlock: unknown command ${JSON.stringify(command)}\n\n${USAGE}`)
      return 2
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`airlock: ${err instanceof Error ? err.message : String(err)}\n`)
    process.exit(1)
  })
