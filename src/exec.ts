/**
 * `airlock exec` — run a one-shot command for a skill/local server inside the
 * jail, reusing a warm sandbox across invocations.
 *
 * This is what makes native skill autoloading possible (see docs/SKILLS.md):
 * a skill installed into the client's skills directory is discovered and loaded
 * natively, and its SKILL.md routes each command through `airlock exec`, which
 * runs it in the sandbox. The jailing here is cooperative — the skill has to
 * route through us — which is a weaker guarantee than the structural MCP bridge,
 * and the docs say so plainly.
 *
 * A sandbox is kept warm between calls (keyed by server name in a local state
 * file) so an interactive skill does not pay an ~11s boot per command. It
 * idle-times-out on its own, and `airlock reap` kills it.
 */
import { SolariClient } from "@solarisdk/sdk"
import type { Sandbox } from "@solarisdk/core"
import { readFileSync, writeFileSync, mkdirSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { homedir } from "node:os"
import type { ServerPolicy } from "./config.js"
import {
  buildNetworkJail,
  installJailDependencies,
  installNodeProxyShim,
  installServer,
  jailCommand,
  verifyJail,
  LOCAL_SERVER_DIR,
  WORKDIR,
  type Logger,
} from "./jail.js"
import { SKILL_DIR } from "./skill.js"

interface Session {
  sandboxId: string
  env: Record<string, string>
}

function sessionFilePath(): string {
  return resolve(homedir(), ".local/state/airlock/exec-sessions.json")
}
function loadSessions(): Record<string, Session> {
  try {
    return JSON.parse(readFileSync(sessionFilePath(), "utf8")) as Record<string, Session>
  } catch {
    return {}
  }
}
function saveSessions(s: Record<string, Session>): void {
  mkdirSync(dirname(sessionFilePath()), { recursive: true })
  writeFileSync(sessionFilePath(), JSON.stringify(s, null, 2))
}

export interface ExecResult {
  stdout: string
  stderr: string
  exitCode: number
}

/**
 * Provision (or reuse) a warm jailed sandbox for `policy` and run `command` in
 * the server's working directory as the unprivileged user. `fresh` forces a new
 * sandbox even if a warm one exists (use it after editing the skill's code).
 */
export async function execInSession(
  policy: ServerPolicy,
  apiKey: string,
  command: string,
  log: Logger,
  fresh = false,
): Promise<ExecResult> {
  const solari = new SolariClient({ apiKey })
  const sessions = loadSessions()
  const workDir = policy.launcher === "skill" ? SKILL_DIR : policy.launcher === "local" ? LOCAL_SERVER_DIR : WORKDIR

  let sandbox: Sandbox | undefined
  let env: Record<string, string> | undefined

  const existing = sessions[policy.name]
  if (existing && !fresh) {
    try {
      const s = await solari.sandboxes.connect(existing.sandboxId)
      // Open the control channel: commands that carry `env` (as ours do) go over
      // the WS, not the one-shot REST path, so the channel must be open.
      await s.connect()
      // Confirm it is actually alive, not just that we have an id for it.
      const alive = await s.commands.run("true", { args: [], timeoutMs: 30_000 })
      if (alive.exitCode === 0) {
        sandbox = s
        env = existing.env
        log(`reusing warm sandbox ${existing.sandboxId.slice(0, 16)}…`)
      }
    } catch {
      /* dead or unreachable; boot a fresh one below */
    }
  }

  if (!sandbox) {
    log("booting a jailed session (first exec; subsequent ones reuse it)…")
    sandbox = await solari.sandboxes.create({
      template: "base",
      timeoutMs: policy.idleMs ?? 15 * 60_000,
      metadata: { airlock: "exec", server: policy.name },
      ...(policy.cpu !== undefined ? { cpu: policy.cpu } : {}),
      ...(policy.memMb !== undefined ? { memMb: policy.memMb } : {}),
      ...(policy.diskGb !== undefined ? { diskGb: policy.diskGb } : {}),
    })
    await sandbox.connect()
    await installJailDependencies(sandbox, log)
    await installServer(sandbox, policy, log) // uploads the skill/local dir
    const proxyEnv = await buildNetworkJail(sandbox, policy, log)
    let nodeEnv: Record<string, string> = {}
    const nodeLauncher = policy.launcher === "skill" || policy.launcher === "local" || policy.launcher === "npx"
    if (nodeLauncher && policy.egress.length > 0) {
      nodeEnv = await installNodeProxyShim(sandbox, log)
    }
    env = { ...policy.secrets, ...proxyEnv, ...nodeEnv, HOME: "/home/mcp", PATH: "/usr/local/bin:/usr/bin:/bin" }
    sessions[policy.name] = { sandboxId: sandbox.sandboxId, env }
    saveSessions(sessions)
  }

  // Fail closed on every exec, not just at boot — the boundary is verified
  // before the command runs, reused session or not.
  await verifyJail(sandbox, policy, log)

  const jailed = jailCommand({ cmd: "sh", args: ["-c", `cd ${workDir} && ${command}`] })
  const out = await sandbox.commands.run(jailed.cmd, { args: jailed.args, env: env ?? {}, timeoutMs: 300_000 })
  return { stdout: out.stdout, stderr: out.stderr, exitCode: out.exitCode }
}

/** Drop the cached session for a server (does not kill the sandbox; use reap). */
export function forgetSession(server: string): void {
  const s = loadSessions()
  if (s[server]) {
    delete s[server]
    saveSessions(s)
  }
}
