/**
 * The relay (SPEC §2.1, §2.2) — Airlock takes the MCP client's subprocess slot.
 *
 * The client speaks JSON-RPC over our stdio; we speak it to a real server
 * running jailed inside a Solari sandbox, and pass frames through untouched.
 *
 * The drop-in property (§2.3) is the binding constraint: tool names, schemas
 * and results must arrive byte-identical, and **nothing but protocol may ever
 * reach stdout**. Every diagnostic in this file goes to stderr, which MCP
 * clients treat as log output.
 */
import { SolariClient } from "@solarisdk/sdk"
import type { Sandbox } from "@solarisdk/core"
import { LineReader } from "./jsonrpc.js"
import { AuditLog, digest, parseProxyLog, type AuditEvent } from "./audit.js"
import {
  buildNetworkJail,
  installJailDependencies,
  installServer,
  jailCommand,
  readProxyLog,
  resolveEntrypoint,
  syncMountsIn,
  syncMountsOut,
  verifyJail,
  WORKDIR,
} from "./jail.js"
import type { ServerPolicy } from "./config.js"

export interface RelayOptions {
  policy: ServerPolicy
  apiKey: string
  audit: AuditLog
  /** Diagnostics sink. Defaults to stderr; never stdout. */
  log?: (msg: string) => void
  /** Idle window for the sandbox. */
  timeoutMs?: number
}

/** Tracks in-flight requests so results can be paired with their calls. */
interface InFlight {
  method: string
  tool?: string
  startedAt: number
}

export async function runRelay(opts: RelayOptions): Promise<number> {
  const { policy, apiKey, audit } = opts
  const log = opts.log ?? ((msg: string) => process.stderr.write(`airlock: ${msg}\n`))
  const startedAt = Date.now()

  if (Object.keys(policy.secrets).length > 0) {
    // §3.3 is not built. Say so rather than letting the user assume the
    // credential is being brokered when it is being handed over.
    const names = Object.keys(policy.secrets).join(", ")
    log(
      `WARNING: secrets (${names}) are passed through to the server verbatim. ` +
        `Credential brokering (SPEC §3.3) is not implemented yet.`,
    )
    audit.write({
      kind: "warn",
      at: new Date().toISOString(),
      server: policy.name,
      message: `secrets passed through unbrokered: ${names}`,
    })
  }

  const solari = new SolariClient({ apiKey })
  const bootStart = Date.now()
  const createOpts = {
    timeoutMs: opts.timeoutMs ?? 10 * 60_000,
    metadata: { airlock: "run", server: policy.name },
  }

  // A pinned template contains the jail dependencies and the server at a fixed
  // version (§4). Without one we use `base` and provision cold, so Airlock
  // works before anything has been built.
  //
  // Custom templates have proven unreliable: measured 0/4 successes with
  // `No sandbox host available` on a template whose own status was `ready`,
  // while `base` was 4/4 in the same run (findings/template-reliability-*.json).
  // So the pin is best-effort, and losing it must not take the user's editor
  // down with it.
  let pinned = policy.template !== undefined
  let sandbox: Sandbox
  try {
    sandbox = await solari.sandboxes.create({ template: policy.template ?? "base", ...createOpts })
  } catch (err) {
    if (!pinned) throw err
    const reason = err instanceof Error ? err.message : String(err)
    // Loud, not silent. The isolation boundary is unaffected — the jail is
    // rebuilt either way — but the supply-chain guarantee is: we are now
    // running whatever the registry serves today, not the build that was
    // vetted. That is a real downgrade and the user has to be told.
    log(`WARNING: pinned template ${policy.template} could not be created (${reason}).`)
    log(`WARNING: falling back to a cold provision. Isolation is unchanged, but the version pin is LOST —`)
    log(`WARNING: this installs ${policy.package} as published right now, not the build you vetted.`)
    audit.write({
      kind: "warn",
      at: new Date().toISOString(),
      server: policy.name,
      message: `pinned template ${policy.template} unavailable (${reason}); provisioned cold, version pin lost`,
    })
    pinned = false
    sandbox = await solari.sandboxes.create({ template: "base", ...createOpts })
  }

  log(
    `sandbox ${sandbox.sandboxId.slice(0, 16)}… up in ${Date.now() - bootStart}ms` +
      (pinned ? ` from pinned template ${policy.template}` : " (provisioning cold)"),
  )
  if (!pinned && policy.template === undefined) {
    log(`hint: \`airlock build ${policy.name}\` pins an immutable build, so upstream changes cannot land silently`)
  }

  let exitCode = 0
  let killed = false
  /** Teardown must be idempotent: it runs from the finally block and from signals. */
  const teardown = async () => {
    if (killed) return
    killed = true

    // Harvest the proxy's decisions before the VM goes away — this is the
    // evidence behind `airlock log --blocked`.
    try {
      const at = new Date().toISOString()
      for (const ev of parseProxyLog(await readProxyLog(sandbox), policy.name, at)) audit.write(ev)
    } catch {
      /* the VM may already be gone */
    }
    try {
      await syncMountsOut(sandbox, policy, log)
    } catch (err) {
      log(`warning: syncing writable mounts back failed: ${err instanceof Error ? err.message : String(err)}`)
    }
    audit.write({
      kind: "session.end",
      at: new Date().toISOString(),
      server: policy.name,
      sandboxId: sandbox.sandboxId,
      durationMs: Date.now() - startedAt,
      exitCode,
    })
    // kill(), never close(): close() only drops our channel and leaves the VM
    // billing until its idle timeout.
    await sandbox.kill().catch(() => {})
    log("sandbox killed")
  }

  const onSignal = () => {
    void teardown().finally(() => process.exit(exitCode))
  }
  process.once("SIGINT", onSignal)
  process.once("SIGTERM", onSignal)

  try {
    await sandbox.connect()

    // Order matters: the jail's dependencies and the server itself are put in
    // place as root with the network up, and only then is the jail closed
    // around the launch. Nothing third-party runs before the boundary exists.
    //
    // With a pinned template both are already baked in, so we only need to
    // resolve the entrypoint — one round trip instead of an apt and an install.
    let entry
    if (pinned) {
      entry = await resolveEntrypoint(sandbox, policy)
    } else {
      await installJailDependencies(sandbox, log)
      entry = await installServer(sandbox, policy, log)
    }
    await syncMountsIn(sandbox, policy, log)
    const proxyEnv = await buildNetworkJail(sandbox, policy, log)
    // Fail closed: never hand traffic to a server whose jail did not verify.
    await verifyJail(sandbox, policy, log)

    audit.write({
      kind: "session.start",
      at: new Date().toISOString(),
      server: policy.name,
      sandboxId: sandbox.sandboxId,
      egress: policy.egress,
      mounts: policy.mounts.map((m) => `${m.guestPath}:${m.mode}`),
    })

    const jailed = jailCommand(entry)
    log(`starting ${policy.package} inside the jail`)

    const inFlight = new Map<string | number, InFlight>()

    // ---- server → client -------------------------------------------------
    const fromServer = new LineReader((line) => {
      // Pass through byte-identical. Parsing is for the audit trail only, and
      // a parse failure must never stop a frame reaching the client.
      process.stdout.write(line + "\n")
      try {
        const msg = JSON.parse(line) as {
          id?: string | number
          method?: string
          result?: { isError?: boolean }
          error?: unknown
        }
        if (msg.id !== undefined && (msg.result !== undefined || msg.error !== undefined)) {
          const pending = inFlight.get(msg.id)
          if (pending) {
            inFlight.delete(msg.id)
            if (pending.tool) {
              audit.write({
                kind: "tool.result",
                at: new Date().toISOString(),
                server: policy.name,
                tool: pending.tool,
                durationMs: Date.now() - pending.startedAt,
                resultBytes: Buffer.byteLength(line, "utf8"),
                isError: msg.error !== undefined || msg.result?.isError === true,
              })
            }
          }
        }
      } catch {
        /* not our business — the client is the one that has to parse it */
      }
    })

    const proc = await sandbox.commands.start(jailed.cmd, {
      args: jailed.args,
      cwd: WORKDIR,
      env: { ...policy.secrets, ...proxyEnv, HOME: "/home/mcp", PATH: "/usr/local/bin:/usr/bin:/bin" },
      onStdout: (data) => fromServer.push(data),
      // The server's stderr is its log, not protocol. Forward it so the client
      // can surface it, prefixed so it is distinguishable from Airlock's own.
      onStderr: (data) => process.stderr.write(data),
    })

    // ---- client → server -------------------------------------------------
    const fromClient = new LineReader((line) => {
      try {
        const msg = JSON.parse(line) as { id?: string | number; method?: string; params?: { name?: string } }
        if (msg.method !== undefined) {
          const isToolCall = msg.method === "tools/call"
          if (msg.id !== undefined) {
            inFlight.set(msg.id, {
              method: msg.method,
              tool: isToolCall ? msg.params?.name : undefined,
              startedAt: Date.now(),
            })
          }
          if (isToolCall && msg.params?.name) {
            const d = digest(msg.params)
            audit.write({
              kind: "tool.call",
              at: new Date().toISOString(),
              server: policy.name,
              tool: msg.params.name,
              ...d,
            })
          }
        }
      } catch {
        /* forward it anyway; the server decides what is valid */
      }
      void proc.stdin(line + "\n").catch((err) => {
        log(`failed to forward a frame to the server: ${err instanceof Error ? err.message : String(err)}`)
      })
    })

    process.stdin.setEncoding("utf8")
    process.stdin.on("data", (chunk: string) => fromClient.push(chunk))

    // Client hung up (§2.2 step 6) — tear the sandbox down rather than let it
    // idle out on the clock.
    const clientClosed = new Promise<void>((resolve) => process.stdin.once("end", () => resolve()))

    exitCode = await Promise.race([
      proc.wait(),
      clientClosed.then(async () => {
        log("client disconnected")
        await proc.kill().catch(() => {})
        return 0
      }),
    ])
  } finally {
    process.off("SIGINT", onSignal)
    process.off("SIGTERM", onSignal)
    await teardown()
  }

  return exitCode
}

/** Re-export so the CLI can render events without importing audit internals. */
export type { AuditEvent }
