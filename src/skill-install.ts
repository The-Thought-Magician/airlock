/**
 * `airlock skill install` — install a skill into the client's skills directory
 * so it is discovered and loaded NATIVELY, while its code runs jailed.
 *
 * Only the rewritten SKILL.md is written locally. **The skill's scripts are NOT
 * copied to your machine** — they live only in the sandbox (uploaded by
 * `airlock exec` from the source directory). This is what makes native mode
 * structural for the skill's *code*: with no local copy, there is nothing to
 * run directly; the code can only execute inside the jail via `airlock exec`.
 *
 * The one thing this does NOT prevent — and neither does the MCP-bridge mode —
 * is the SKILL.md instructions prompt-injecting the agent into misusing its own
 * tools. That is inherent to any agent-readable text (a poisoned MCP tool
 * description has the same hole) and is only mitigated by the §3.5 scan, which
 * runs over the SKILL.md at install and launch.
 */
import { mkdirSync, writeFileSync, existsSync } from "node:fs"
import { resolve } from "node:path"
import { homedir } from "node:os"
import { readSkill } from "./skill.js"
import { scanText } from "./inject-scan.js"

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
    "> **Sandboxed by Airlock.** This skill's scripts are NOT on this machine —",
    "> they exist only inside the Airlock sandbox. There is nothing to run",
    "> locally. Run every command for this skill through the sandbox:",
    ">",
    "> ```",
    `> airlock exec ${name} -- <the command>`,
    "> ```",
    ">",
    "> That runs the command inside the sandbox, with no access to your files",
    "> and only the network the policy allows. Do not attempt to reconstruct or",
    "> run the skill's code outside `airlock exec`.",
    "",
    "---",
    "",
    originalBody,
  ].join("\n")
}

export interface InstallResult {
  name: string
  dest: string
  injectionFindings: number
}

/**
 * Install the skill's rewritten SKILL.md into the client's skills dir. The
 * skill's scripts are deliberately NOT copied — see the module comment. Returns
 * the count of §3.5 injection patterns found in the SKILL.md, so the caller can
 * warn (the SKILL.md is agent-readable text and is the remaining attack surface).
 */
export function installSkill(skillPath: string, client: string, force: boolean): InstallResult {
  const meta = readSkill(skillPath)
  const baseDir = clientSkillsDir(client)
  const dest = resolve(baseDir, meta.name)

  if (existsSync(dest) && !force) {
    throw new Error(`${dest} already exists (use --force to overwrite)`)
  }

  mkdirSync(dest, { recursive: true })
  // Only the rewritten SKILL.md is written locally. No scripts: the code lives
  // only in the sandbox, so it can only execute there.
  const frontmatter = `---\nname: ${meta.name}\ndescription: ${meta.description}\n---\n\n`
  writeFileSync(resolve(dest, "SKILL.md"), frontmatter + routingPreamble(meta.name, meta.body))

  return { name: meta.name, dest, injectionFindings: scanText(meta.raw).length }
}
