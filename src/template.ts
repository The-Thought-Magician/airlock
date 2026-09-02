/**
 * `airlock build` — mint a pinned template for a server (SPEC §4).
 *
 * This replaces the snapshot flow the spec originally specified. Snapshots lost
 * on measurement: `create({ fromSnapshot })` averages 46.8s against 12.3s for a
 * cold create plus provision, and `revert()` is unavailable on this plan. See
 * `docs/FINDINGS-WARMSTART.md`.
 *
 * A template keeps what actually mattered:
 *   - immutable: the same bytes every launch, so an upstream release published
 *     after the build cannot reach you
 *   - shareable: a `tpl_…` id committed in the policy is an org artifact, where
 *     a snapshot was one machine's save point
 *   - fast enough: 11.4s to create, versus 12.3s provisioning cold
 *
 * The build also records the server's tool definitions, which gives §3.4
 * definition pinning its baseline and makes §4.3's rebuild diff possible.
 */
import { SolariClient, Image } from "@solarisdk/sdk"
import type { Sandbox } from "@solarisdk/core"
import {
  buildNetworkJail,
  installCommand,
  installedVersion,
  jailCommand,
  MCP_GID,
  MCP_UID,
  resolveEntrypoint,
  verifyJail,
  WORKDIR,
} from "./jail.js"
import { McpSession, type ToolDefinition } from "./mcp.js"
import type { ServerPolicy } from "./config.js"
import { hashToolSet } from "./tools-hash.js"

export type Logger = (msg: string) => void

export interface BuildResult {
  templateId: string
  templateName: string
  version?: string
  tools: ToolDefinition[]
  toolsHash: string
  serverInfo: { name?: string; version?: string }
  buildMs: number
  verifyMs: number
}

/** apt packages the jail needs. `procps` is included deliberately — see below. */
const JAIL_APT = [
  "socat",
  "tinyproxy",
  "iproute2",
  "util-linux",
  // The base image ships no pgrep/pkill. Absent, any liveness check written
  // with them reports every process as dead — a false negative that cost a
  // full round of misleading measurements while probing.
  "procps",
]

/**
 * Build the image recipe. Separated out so it can be inspected and diffed
 * without touching the network.
 */
export function jailImage(policy: ServerPolicy): Image {
  return Image.fromTemplate("base")
    .kind("sandbox")
    .aptInstall(JAIL_APT)
    .runCommands(
      `useradd -m -u ${MCP_UID} -s /bin/sh mcp`,
      `mkdir -p /run/airlock /var/log/tinyproxy ${WORKDIR}`,
      "chown tinyproxy:tinyproxy /var/log/tinyproxy",
      `chown -R ${MCP_UID}:${MCP_GID} ${WORKDIR}`,
      // The server itself, baked in. This is the pin.
      installCommand(policy),
    )
}

/**
 * Build a template for `policy`, then verify it by actually running the server
 * inside the jail and completing an MCP handshake.
 *
 * Verification is not optional. A template that builds but produces a server
 * that cannot start would otherwise be written into the policy file and fail on
 * every subsequent launch, at which point the cause is far away from the effect.
 */
export async function buildTemplate(
  apiKey: string,
  policy: ServerPolicy,
  log: Logger,
): Promise<BuildResult> {
  const solari = new SolariClient({ apiKey })
  const templateName = `airlock-${policy.name}-${Date.now().toString(36)}`

  log(`building template ${templateName}`)
  log(`  base     : base`)
  log(`  apt      : ${JAIL_APT.join(", ")}`)
  log(`  package  : ${policy.package} (${policy.launcher})`)

  const tBuild = performance.now()
  const template = await solari.templates.build(jailImage(policy), {
    name: templateName,
    kind: "sandbox",
    timeoutMs: 900_000,
    onLog: (line) => log(`  [build] ${line}`),
  })
  const buildMs = performance.now() - tBuild

  if (template.status !== "ready") {
    throw new Error(`template build finished with status ${template.status}: ${template.error ?? "no error given"}`)
  }
  log(`built in ${(buildMs / 1000).toFixed(1)}s → ${template.templateId}`)

  // ---- Verify: create from it and run the server for real ---------------
  log("verifying the template by running the server inside the jail…")
  const tVerify = performance.now()
  const sandbox: Sandbox = await solari.sandboxes.create({
    template: template.templateId,
    timeoutMs: 10 * 60_000,
    metadata: { airlock: "build-verify", server: policy.name },
  })

  try {
    await sandbox.connect()

    const version = await installedVersion(sandbox, policy)
    if (version) log(`installed version: ${version}`)

    const entry = await resolveEntrypoint(sandbox, policy)
    const proxyEnv = await buildNetworkJail(sandbox, policy, log)
    await verifyJail(sandbox, policy, log)

    const jailed = jailCommand(entry)
    let session!: McpSession
    const proc = await sandbox.commands.start(jailed.cmd, {
      args: jailed.args,
      cwd: WORKDIR,
      env: { ...policy.secrets, ...proxyEnv, HOME: "/home/mcp", PATH: "/usr/local/bin:/usr/bin:/bin" },
      onStdout: (data) => session.push(data),
      onStderr: (data) => process.stderr.write(`  [server] ${data}`),
    })
    session = new McpSession(proc)

    const serverInfo = await session.initialize("airlock-build")
    const tools = await session.listTools()
    const toolsHash = hashToolSet(tools)
    await proc.kill().catch(() => {})

    const verifyMs = performance.now() - tVerify
    log(`verified in ${(verifyMs / 1000).toFixed(1)}s: ${serverInfo.name} ${serverInfo.version}, ${tools.length} tools`)

    return {
      templateId: template.templateId,
      templateName,
      version,
      tools,
      toolsHash,
      serverInfo,
      buildMs,
      verifyMs,
    }
  } finally {
    await sandbox.kill().catch(() => {})
  }
}

/**
 * Read the current tool definitions from an already-pinned template, without
 * building anything. Used to diff before adopting a rebuild (§4.3).
 */
export async function readToolsFromTemplate(
  apiKey: string,
  policy: ServerPolicy,
  templateId: string,
  log: Logger,
): Promise<ToolDefinition[]> {
  const solari = new SolariClient({ apiKey })
  const sandbox = await solari.sandboxes.create({
    template: templateId,
    timeoutMs: 10 * 60_000,
    metadata: { airlock: "build-diff", server: policy.name },
  })
  try {
    await sandbox.connect()
    const entry = await resolveEntrypoint(sandbox, policy)
    const proxyEnv = await buildNetworkJail(sandbox, policy, log)
    const jailed = jailCommand(entry)
    let session!: McpSession
    const proc = await sandbox.commands.start(jailed.cmd, {
      args: jailed.args,
      cwd: WORKDIR,
      env: { ...policy.secrets, ...proxyEnv, HOME: "/home/mcp", PATH: "/usr/local/bin:/usr/bin:/bin" },
      onStdout: (data) => session.push(data),
      onStderr: () => {},
    })
    session = new McpSession(proc)
    await session.initialize("airlock-build-diff")
    const tools = await session.listTools()
    await proc.kill().catch(() => {})
    return tools
  } finally {
    await sandbox.kill().catch(() => {})
  }
}
