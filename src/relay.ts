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
  installNodeProxyShim,
  installRelayWrapper,
  jailCommand,
  readProxyLog,
  resolveEntrypoint,
  syncMountsIn,
  syncMountsOut,
  verifyJail,
  WORKDIR,
  WRAP_PREFIX,
} from "./jail.js"
import type { ServerPolicy } from "./config.js"
import { hashToolSet } from "./tools-hash.js"
import type { ToolDefinition } from "./mcp.js"

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
    // `secrets` is plain env injection — the server really receives these. The
    // brokered alternative (§3.3, the `broker` field) keeps the credential out
    // of the server entirely; point at it rather than let the user assume these
    // are protected.
    const names = Object.keys(policy.secrets).join(", ")
    log(
      `WARNING: secrets (${names}) are injected into the server's environment verbatim — it can read them. ` +
        `For a credential the server should never see, use a \`broker\` rule instead (SPEC §3.3).`,
    )
    audit.write({
      kind: "warn",
      at: new Date().toISOString(),
      server: policy.name,
      message: `secrets passed through as env (not brokered): ${names}`,
    })
  }
  if (policy.broker.length > 0) {
    log(`brokering ${policy.broker.length} credential(s) at the proxy — the server never receives them`)
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
    // Keeps the guest's stdout pure ASCII so multi-byte UTF-8 survives the SDK's
    // per-frame decode (see WRAP_PATH). Cheap; installed on every launch.
    await installRelayWrapper(sandbox)

    // Node's built-in fetch ignores HTTP_PROXY, so without this a node server
    // using fetch would reach nothing through the jail. Only bother when there
    // is actually a proxy to point it at (an egress allowlist).
    let nodeProxyEnv: Record<string, string> = {}
    if ((policy.launcher === "npx" || policy.launcher === "local") && policy.egress.length > 0) {
      nodeProxyEnv = await installNodeProxyShim(sandbox, log)
    }

    audit.write({
      kind: "session.start",
      at: new Date().toISOString(),
      server: policy.name,
      sandboxId: sandbox.sandboxId,
      egress: policy.egress,
      mounts: policy.mounts.map((m) => `${m.guestPath}:${m.mode}`),
    })

    const jailed = jailCommand(entry, { frame: true })
    log(`starting ${policy.package} inside the jail`)

    const inFlight = new Map<string | number, InFlight>()
    // Drift is checked once, on the first tools/list result to come back.
    let driftChecked = false

    // The server's stdout is base64-framed by the guest wrapper (WRAP_PREFIX).
    // Decode each framed line back to the exact JSON bytes before handling it;
    // this is what makes multi-byte UTF-8 survive. A line without the prefix is
    // unexpected (a server writing straight to fd 1, say) — pass it through raw
    // rather than mangle it.
    const decodeFramed = (line: string): string =>
      line.startsWith(WRAP_PREFIX) ? Buffer.from(line.slice(WRAP_PREFIX.length), "base64").toString("utf8") : line

    // ---- server → client -------------------------------------------------
    const handleServerLine = (line: string) => {
      // §3.4: gate tools/list against the pinned definitions BEFORE forwarding.
      // Everything else is passed through byte-identical; parsing it is for the
      // audit trail only and must never stop a frame reaching the client.
      let msg:
        | {
            id?: string | number
            method?: string
            result?: { isError?: boolean; tools?: ToolDefinition[] }
            error?: unknown
          }
        | undefined
      try {
        msg = JSON.parse(line)
      } catch {
        msg = undefined
      }

      // Tool-definition drift check. A rug pull changes the tools after you
      // approved them; the jail contains exfiltration, but a poisoned tool
      // *description* attacks the agent, not the sandbox, so it has to be caught
      // here rather than trusted. If it drifts we replace the result with an
      // error, so the client sees no tools rather than poisoned ones — the
      // "block startup" behaviour §3.4 asks for. AIRLOCK_ALLOW_DRIFT=1 downgrades
      // this to a warning for the case where the change was expected.
      if (
        !driftChecked &&
        msg?.result?.tools !== undefined &&
        typeof msg.id !== "undefined" &&
        inFlight.get(msg.id)?.method === "tools/list"
      ) {
        driftChecked = true
        if (policy.toolsHash) {
          const liveHash = hashToolSet(msg.result.tools)
          if (liveHash !== policy.toolsHash) {
            const allow = process.env.AIRLOCK_ALLOW_DRIFT === "1"
            log(`${allow ? "WARNING" : "BLOCKED"}: tool definitions have drifted from the pinned set.`)
            log(`  pinned: ${policy.toolsHash}`)
            log(`  live  : ${liveHash}`)
            log(`  this is the rug-pull / tool-poisoning signature. Re-approve with \`airlock build ${policy.name} --update\`.`)
            audit.write({
              kind: "warn",
              at: new Date().toISOString(),
              server: policy.name,
              message: `tool-definition drift: pinned ${policy.toolsHash}, live ${liveHash}${allow ? " (allowed)" : " (blocked)"}`,
            })
            if (!allow) {
              // Substitute an error for this response; the original poisoned
              // result never reaches the client.
              const errorLine = JSON.stringify({
                jsonrpc: "2.0",
                id: msg.id,
                error: {
                  code: -32001,
                  message:
                    `airlock: tool definitions for "${policy.name}" changed since you approved them. ` +
                    `Startup blocked to prevent a rug pull. Run \`airlock build ${policy.name} --update\` to review and re-approve, ` +
                    `or set AIRLOCK_ALLOW_DRIFT=1 to bypass.`,
                },
              })
              process.stdout.write(errorLine + "\n")
              inFlight.delete(msg.id)
              return
            }
          } else {
            log("tool definitions match the pinned set")
          }
        }
      }

      process.stdout.write(line + "\n")
      if (msg && msg.id !== undefined && (msg.result !== undefined || msg.error !== undefined)) {
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
    }

    // The wrapper's own lines are pure ASCII, so this LineReader never splits a
    // multi-byte character; decoding happens per whole line, after reassembly.
    const fromServer = new LineReader((framed) => handleServerLine(decodeFramed(framed)))

    const proc = await sandbox.commands.start(jailed.cmd, {
      args: jailed.args,
      cwd: WORKDIR,
      env: { ...policy.secrets, ...proxyEnv, ...nodeProxyEnv, HOME: "/home/mcp", PATH: "/usr/local/bin:/usr/bin:/bin" },
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
