/**
 * `airlock skill install` — install a skill into the client's skills directory
 * so it is discovered and loaded NATIVELY, while its code runs jailed.
 *
 * The installed SKILL.md keeps the original name/description (so the client
 * lists it normally) but its body is prefixed with a routing preamble telling
 * the agent to run the skill's commands through `airlock exec <name> -- <cmd>`.
 * That is what sends the skill's execution into the sandbox.
 *
 * Honest note, repeated in the preamble and the docs: this jailing is
 * cooperative. The agent follows the SKILL.md; a skill that wants to run its
 * code directly can. For a skill you wrote and want sandboxed, it gives native
 * autoload plus off-machine execution. For an untrusted skill, prefer the
 * structural MCP-bridge mode (`launcher = "skill"` + `airlock run`).
 */
import { cpSync, mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs"
import { resolve } from "node:path"
import { homedir } from "node:os"
import { readSkill } from "./skill.js"

/** Where a given client discovers personal skills. */
export function clientSkillsDir(client: string): string {
  switch (client) {
    case "claude":
    case "claude-code":
      return resolve(homedir(), ".claude/skills")
    case "cursor":
      return resolve(homedir(), ".cursor/skills")
    default:
      throw new Error(`unknown client ${JSON.stringify(client)} (known: claude, cursor)`)
  }
}

function routingPreamble(name: string, originalBody: string): string {
  return [
    "> **Sandboxed by Airlock.** Do not run this skill's scripts directly.",
    `> Run every command for this skill through the sandbox, like this:`,
    ">",
    "> ```",
    `> airlock exec ${name} -- <the command>`,
    "> ```",
    ">",
    "> This runs the command inside an Airlock sandbox with no access to the",
    "> machine's files and only the network the policy allows. Running the",
    "> scripts directly would defeat the sandbox.",
    "",
    "---",
    "",
    originalBody,
  ].join("\n")
}

export interface InstallResult {
  name: string
  dest: string
}

/**
 * Copy the skill into the client's skills dir, rewriting SKILL.md with the
 * routing preamble. The original body is preserved after the preamble so the
 * agent still has the skill's real instructions.
 */
export function installSkill(skillPath: string, client: string, force: boolean): InstallResult {
  const meta = readSkill(skillPath)
  const baseDir = clientSkillsDir(client)
  const dest = resolve(baseDir, meta.name)

  if (existsSync(dest) && !force) {
    throw new Error(`${dest} already exists (use --force to overwrite)`)
  }

  mkdirSync(dest, { recursive: true })
  // Copy everything except SKILL.md (which we rewrite) and the usual noise.
  cpSync(skillPath, dest, {
    recursive: true,
    force: true,
    filter: (src) => !src.endsWith("/SKILL.md") && !src.includes("/node_modules") && !src.includes("/.git"),
  })

  const original = readSkill(skillPath) // body already stripped of frontmatter
  const frontmatter = `---\nname: ${meta.name}\ndescription: ${meta.description}\n---\n\n`
  writeFileSync(resolve(dest, "SKILL.md"), frontmatter + routingPreamble(meta.name, original.body))

  return { name: meta.name, dest }
}
