/**
 * Skill launcher — jail a Claude/agent skill by bridging it to an MCP server.
 *
 * A skill (a `SKILL.md` plus bundled scripts) is not an MCP server: the client
 * loads the instructions and runs the scripts as ordinary local subprocesses,
 * with all the local access that implies. There is no JSON-RPC transport for
 * Airlock to interpose on the way there is for an MCP server.
 *
 * So Airlock bridges it: `launcher = "skill"` uploads the skill directory into
 * the jail and generates a tiny MCP server that exposes two tools —
 * `skill_instructions` (returns the SKILL.md body so the agent knows how to use
 * it) and `skill_exec` (runs a command inside the skill directory). The bridge
 * runs through the exact same jail as any other server, so the skill's scripts
 * execute with no access to your filesystem and only the egress the policy
 * allows. Nothing about the skill machinery is special-cased in the jail; it is
 * just a `local`-style upload with a generated entrypoint.
 *
 * Honest framing: this is not native skill loading. It is "run a skill's code
 * in the sandbox, exposed to the agent as a jailed tool". That is the useful
 * security primitive; the convenience of native loading is out of scope.
 */
import type { Sandbox } from "@solarisdk/core"
import { readFileSync, readdirSync, statSync } from "node:fs"
import { join, relative } from "node:path"

export const SKILL_DIR = "/opt/airlock-skill"
export const SKILL_BRIDGE = `${SKILL_DIR}/__airlock_skill_bridge.cjs`

export interface SkillMeta {
  name: string
  description: string
  /** Full SKILL.md text (frontmatter included), for the injection scan. */
  raw: string
  /** SKILL.md body with the YAML frontmatter stripped, for the agent. */
  body: string
}

/**
 * Parse the minimal SKILL.md frontmatter. Skills use a small YAML block
 * delimited by `---`; we only need `name` and `description`, and we do not pull
 * in a YAML dependency for two scalar fields.
 */
export function parseSkillMd(text: string): { name?: string; description?: string; body: string } {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text)
  if (!m) return { body: text }
  const [, front, body] = m
  const field = (key: string): string | undefined => {
    // key: value  OR  key: "value". Single-line scalars only, which is all the
    // skill spec uses for name/description.
    const re = new RegExp(`^${key}\\s*:\\s*(.+?)\\s*$`, "mi")
    const fm = re.exec(front)
    if (!fm) return undefined
    return fm[1].replace(/^["']|["']$/g, "")
  }
  return { name: field("name"), description: field("description"), body: body.trim() }
}

/** Read and validate a skill directory on the local machine. */
export function readSkill(dir: string): SkillMeta {
  let stat
  try {
    stat = statSync(dir)
  } catch {
    throw new Error(`skill path not found: ${dir}`)
  }
  if (!stat.isDirectory()) throw new Error(`skill path must be a directory: ${dir}`)

  let raw: string
  try {
    raw = readFileSync(join(dir, "SKILL.md"), "utf8")
  } catch {
    throw new Error(`no SKILL.md in ${dir} — a skill directory must contain SKILL.md`)
  }
  const parsed = parseSkillMd(raw)
  return {
    name: parsed.name ?? "skill",
    description: parsed.description ?? "A bundled skill, run inside the Airlock jail.",
    raw,
    body: parsed.body,
  }
}

/**
 * The bridge MCP server, generated per skill. It reads SKILL.md from its own
 * directory at runtime and exposes the skill to the agent as jailed tools.
 * The skill's name and description are baked into the tool metadata so the
 * §3.5 injection scan sees them at build time.
 */
export function skillBridgeSource(meta: SkillMeta): string {
  const safe = (s: string) => JSON.stringify(s)
  return `#!/usr/bin/env node
// Airlock skill bridge. Generated; do not edit in the guest.
"use strict"
const { execFile } = require("child_process")
const fs = require("fs")
const path = require("path")
const SKILL_NAME = ${safe(meta.name)}
const SKILL_DESC = ${safe(meta.description)}
const DIR = __dirname
function send(m){ process.stdout.write(JSON.stringify(m) + "\\n") }
function instructions(){
  try {
    const raw = fs.readFileSync(path.join(DIR, "SKILL.md"), "utf8")
    const m = /^---\\r?\\n[\\s\\S]*?\\r?\\n---\\r?\\n?([\\s\\S]*)$/.exec(raw)
    return (m ? m[1] : raw).trim()
  } catch (e) { return "SKILL.md unreadable: " + e.message }
}
function exec(args){
  const command = (args && args.command) || ""
  if (!command) return Promise.resolve("no command given")
  return new Promise((resolve) => {
    // Run in the skill directory, jailed. cwd is the skill so its bundled
    // scripts are reachable by relative path, as the SKILL.md expects.
    execFile("sh", ["-c", command], { cwd: DIR, timeout: 120000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      const out = (stdout || "") + (stderr || "")
      resolve(err ? ("[exit " + (err.code == null ? 1 : err.code) + "] " + out) : (out || "[no output]"))
    })
  })
}
const TOOLS = {
  skill_instructions: {
    def: { name: "skill_instructions", description: "Read the instructions for the '" + SKILL_NAME + "' skill: " + SKILL_DESC, inputSchema: { type: "object", properties: {} } },
    run: async () => instructions(),
  },
  skill_exec: {
    def: { name: "skill_exec", description: "Run a shell command for the '" + SKILL_NAME + "' skill, inside the Airlock sandbox (no access to your files, egress limited by policy).", inputSchema: { type: "object", properties: { command: { type: "string", description: "The shell command to run in the skill directory." } }, required: ["command"] } },
    run: (a) => exec(a),
  },
}
let buf = ""
process.stdin.setEncoding("utf8")
process.stdin.on("data", async (c) => {
  buf += c; let nl
  while ((nl = buf.indexOf("\\n")) !== -1) {
    const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1)
    if (!line) continue
    let m; try { m = JSON.parse(line) } catch { continue }
    if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: (m.params && m.params.protocolVersion) || "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "airlock-skill:" + SKILL_NAME, version: "1.0.0" } } })
    else if (m.method === "notifications/initialized") {}
    else if (m.method === "tools/list") send({ jsonrpc: "2.0", id: m.id, result: { tools: Object.values(TOOLS).map((t) => t.def) } })
    else if (m.method === "tools/call") {
      const t = TOOLS[m.params && m.params.name]
      if (!t) { send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "unknown tool" } }); continue }
      const text = await t.run(m.params.arguments || {})
      send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: String(text) }] } })
    } else if (m.id !== undefined) send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "method not found: " + m.method } })
  }
})
`
}

/**
 * Upload a skill directory into the jail and install the generated bridge.
 * Runs as root before the jail closes, mirroring uploadLocalServer. Returns the
 * skill metadata so the caller can scan SKILL.md for prompt injection.
 */
export async function uploadSkill(
  sandbox: Sandbox,
  dir: string,
  log: (msg: string) => void,
): Promise<SkillMeta> {
  const meta = readSkill(dir)

  const files: string[] = []
  const walk = (d: string) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === ".git") continue
      const full = join(d, entry.name)
      if (entry.isDirectory()) walk(full)
      else if (entry.isFile()) files.push(full)
    }
  }
  walk(dir)

  log(`uploading skill "${meta.name}" (${files.length} file(s)) → ${SKILL_DIR}`)
  await sandbox.commands.run("sh", { args: ["-c", `rm -rf ${SKILL_DIR} && mkdir -p ${SKILL_DIR}`], timeoutMs: 60_000 })
  for (const file of files) {
    await sandbox.files.write(`${SKILL_DIR}/${relative(dir, file)}`, readFileSync(file))
  }
  await sandbox.files.write(SKILL_BRIDGE, skillBridgeSource(meta))
  // The skill's own scripts stay executable by the mcp user; only the tree is
  // owned by root so a compromised run cannot rewrite the skill for next time.
  await sandbox.commands.run("sh", {
    args: ["-c", `chown -R root:root ${SKILL_DIR} && chmod -R a+rX ${SKILL_DIR}`],
    timeoutMs: 60_000,
  })
  return meta
}
