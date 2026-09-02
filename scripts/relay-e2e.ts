/**
 * Build step 3 — the bare relay.
 *
 * Drives a real, unmodified third-party MCP server running inside a Solari
 * sandbox, speaking JSON-RPC over the control channel's streamed stdio. No
 * policy layer yet; the point is to prove the core mechanism works and to get
 * the honest per-call latency number that SPEC §7 Q4 asks for.
 *
 * Settles Q8 (does the stdio relay work over the control channel cleanly) and
 * replaces the misleading one-shot `exec` figure from probe.ts with the number
 * that actually decides daily usability.
 *
 * Usage: npm run relay:e2e
 */
import { SolariClient } from "@solarisdk/sdk"
import { mkdirSync, writeFileSync } from "node:fs"
import { LineReader, encode, isResponse, type JsonRpcMessage, type JsonRpcResponse } from "../src/jsonrpc.js"

const apiKey = process.env.SOLARI_API_KEY
if (!apiKey) {
  console.error("SOLARI_API_KEY is not set. Run: set -a && . ./.env && set +a")
  process.exit(1)
}

const PACKAGE = process.env.AIRLOCK_TEST_SERVER ?? "@modelcontextprotocol/server-everything"
const PROTOCOL_VERSION = "2025-06-18"

async function main() {
  const solari = new SolariClient({ apiKey })
  const t0 = performance.now()
  const sandbox = await solari.sandboxes.create({
    template: "base",
    timeoutMs: 15 * 60_000,
    metadata: { airlock: "relay-e2e" },
  })
  console.log(`sandbox up in ${(performance.now() - t0).toFixed(0)}ms\n`)

  const timings: Record<string, number> = {}
  let toolNames: string[] = []

  try {
    await sandbox.connect()

    // ---- Install the server. This is the cost the snapshot eliminates. ----
    console.log(`installing ${PACKAGE} (one-off; §4 snapshots this away)…`)
    const tInstall = performance.now()
    const install = await sandbox.commands.run("npm", {
      args: ["install", "-g", PACKAGE, "--silent", "--no-fund", "--no-audit"],
      timeoutMs: 300_000,
    })
    timings.installMs = performance.now() - tInstall
    if (install.exitCode !== 0) {
      console.error("install failed:", install.stderr.slice(-2000))
      throw new Error(`npm install exited ${install.exitCode}`)
    }
    console.log(`installed in ${(timings.installMs / 1000).toFixed(1)}s\n`)

    const which = await sandbox.commands.run("sh", {
      args: ["-c", "ls /usr/lib/node_modules/@modelcontextprotocol/*/dist/index.js 2>/dev/null | head -1; command -v mcp-server-everything"],
    })
    const bin = which.stdout.trim().split("\n").filter(Boolean).pop()
    console.log(`server entrypoint: ${bin}\n`)
    if (!bin) throw new Error("could not locate the installed server binary")

    // ---- Start the server and wire up the relay --------------------------
    // This is the core mechanism: one long-lived process, JSON-RPC frames
    // pushed over the already-open control WebSocket.
    const pending = new Map<number | string, (r: JsonRpcResponse) => void>()
    const reader = new LineReader((line) => {
      let msg: JsonRpcMessage
      try {
        msg = JSON.parse(line)
      } catch {
        console.error(`  [unparseable line] ${line.slice(0, 200)}`)
        return
      }
      if (isResponse(msg)) {
        const resolve = pending.get(msg.id)
        if (resolve) {
          pending.delete(msg.id)
          resolve(msg)
        }
      } else {
        // Server-initiated notification — a real client would surface these.
        console.log(`  [notification] ${"method" in msg ? msg.method : "?"}`)
      }
    })

    const tStart = performance.now()
    const proc = await sandbox.commands.start("node", {
      args: [bin],
      env: { NODE_ENV: "production" },
      onStdout: (data) => reader.push(data),
      // MCP servers log to stderr; keep it off the protocol stream.
      onStderr: (data) => process.stderr.write(`  [server stderr] ${data}`),
    })
    timings.processStartMs = performance.now() - tStart
    console.log(`server process started in ${timings.processStartMs.toFixed(0)}ms\n`)

    let nextId = 1
    const call = async (method: string, params?: unknown): Promise<{ res: JsonRpcResponse; ms: number }> => {
      const id = nextId++
      const t = performance.now()
      const done = new Promise<JsonRpcResponse>((resolve, reject) => {
        pending.set(id, resolve)
        setTimeout(() => {
          if (pending.delete(id)) reject(new Error(`${method} timed out after 30s`))
        }, 30_000)
      })
      await proc.stdin(encode({ jsonrpc: "2.0", id, method, params }))
      const res = await done
      return { res, ms: performance.now() - t }
    }
    const notify = (method: string, params?: unknown) =>
      proc.stdin(encode({ jsonrpc: "2.0", method, params }))

    // ---- The MCP handshake ------------------------------------------------
    const init = await call("initialize", {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "airlock-relay-e2e", version: "0.0.0" },
    })
    timings.initializeMs = init.ms
    const initResult = init.res.result as { serverInfo?: { name?: string; version?: string } } | undefined
    console.log(
      `initialize  ${init.ms.toFixed(0)}ms  →  ${initResult?.serverInfo?.name} ${initResult?.serverInfo?.version}`,
    )
    await notify("notifications/initialized")

    // ---- tools/list — the drop-in property depends on this passing through -
    const list = await call("tools/list")
    timings.toolsListMs = list.ms
    const tools = (list.res.result as { tools?: { name: string }[] } | undefined)?.tools ?? []
    toolNames = tools.map((t) => t.name)
    console.log(`tools/list  ${list.ms.toFixed(0)}ms  →  ${tools.length} tools: ${toolNames.slice(0, 8).join(", ")}`)

    // ---- an actual tool call ---------------------------------------------
    if (toolNames.includes("echo")) {
      const echo = await call("tools/call", { name: "echo", arguments: { message: "airlock" } })
      timings.toolCallMs = echo.ms
      const content = (echo.res.result as { content?: { text?: string }[] } | undefined)?.content?.[0]?.text
      console.log(`tools/call  ${echo.ms.toFixed(0)}ms  →  ${JSON.stringify(content)}`)
    }

    // ---- Q4, properly: steady-state round-trip over the live relay --------
    const N = 20
    const samples: number[] = []
    for (let i = 0; i < N; i++) {
      const r = await call("tools/list")
      samples.push(r.ms)
    }
    const sorted = [...samples].sort((a, b) => a - b)
    const stats = {
      mean: samples.reduce((a, b) => a + b, 0) / N,
      p50: sorted[Math.floor(N * 0.5)],
      p95: sorted[Math.floor(N * 0.95)],
      min: sorted[0],
      max: sorted[N - 1],
    }
    Object.assign(timings, {
      relayMeanMs: stats.mean,
      relayP50Ms: stats.p50,
      relayP95Ms: stats.p95,
      relayMinMs: stats.min,
      relayMaxMs: stats.max,
    })
    console.log(
      `\nrelay round-trip over ${N} calls: mean ${stats.mean.toFixed(1)}ms  ` +
        `p50 ${stats.p50.toFixed(1)}ms  p95 ${stats.p95.toFixed(1)}ms  ` +
        `(min ${stats.min.toFixed(1)} / max ${stats.max.toFixed(1)})`,
    )

    // ---- Clean shutdown ---------------------------------------------------
    await proc.kill()
  } finally {
    await sandbox.kill()
    console.log("\nsandbox killed")
  }

  mkdirSync("findings", { recursive: true })
  const path = `findings/relay-${Date.now()}.json`
  writeFileSync(path, JSON.stringify({ at: new Date().toISOString(), package: PACKAGE, toolNames, timings }, null, 2))
  console.log(`findings written to ${path}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
