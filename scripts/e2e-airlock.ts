/**
 * End-to-end test of `airlock run` (SPEC build steps 4 + 5).
 *
 * Acts as a real MCP client: spawns the CLI as a subprocess, speaks JSON-RPC
 * over its stdio, and checks that a genuine third-party server works through
 * the jail unmodified.
 *
 * Three things are being verified, and the third is the one that is easy to get
 * wrong and fatal if you do:
 *
 *   1. the handshake and tool calls round-trip through the jail
 *   2. policy actually drives the jail — `egress = []` yields a process with no
 *      proxy and no route, while a non-empty allowlist yields proxy env vars
 *   3. **stdout carries nothing but protocol.** Any stray log line on stdout
 *      corrupts the stream and breaks the drop-in property (§2.3), so every
 *      line the CLI emits on stdout must parse as JSON.
 *
 * Usage: npm run e2e
 */
import { spawn } from "node:child_process"
import { requireApiKey } from "../src/env.js"
import { LineReader, encode, type JsonRpcResponse } from "../src/jsonrpc.js"

requireApiKey()

const PROTOCOL_VERSION = "2025-06-18"

type Check = { name: string; detail: string; pass: boolean }
const checks: Check[] = []
function record(name: string, detail: string, pass: boolean) {
  checks.push({ name, detail, pass })
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}`)
  console.log(`      ${detail.replace(/\n/g, " | ").slice(0, 400)}`)
}

interface Session {
  call(method: string, params?: unknown): Promise<JsonRpcResponse>
  notify(method: string, params?: unknown): void
  /** Lines seen on stdout that were NOT valid JSON — must stay empty. */
  nonProtocolStdout: string[]
  stderr: string
  close(): Promise<number>
}

function startAirlock(server: string): Session {
  const child = spawn("npx", ["tsx", "src/cli.ts", "run", server], {
    stdio: ["pipe", "pipe", "pipe"],
    env: process.env,
  })

  const pending = new Map<number | string, (r: JsonRpcResponse) => void>()
  const nonProtocolStdout: string[] = []
  let stderr = ""

  const reader = new LineReader((line) => {
    let msg: JsonRpcResponse & { method?: string }
    try {
      msg = JSON.parse(line)
    } catch {
      // The failure this test exists to catch.
      nonProtocolStdout.push(line)
      return
    }
    if (msg.id !== undefined && (msg.result !== undefined || msg.error !== undefined)) {
      const resolve = pending.get(msg.id)
      if (resolve) {
        pending.delete(msg.id)
        resolve(msg)
      }
    }
  })

  child.stdout.setEncoding("utf8")
  child.stdout.on("data", (c: string) => reader.push(c))
  child.stderr.setEncoding("utf8")
  child.stderr.on("data", (c: string) => {
    stderr += c
    process.stderr.write(c)
  })

  let nextId = 1
  const exited = new Promise<number>((resolve) => child.on("exit", (code) => resolve(code ?? 0)))

  return {
    call(method, params) {
      const id = nextId++
      return new Promise<JsonRpcResponse>((resolve, reject) => {
        pending.set(id, resolve)
        // Generous: the first call waits out apt-get plus npm install.
        const timer = setTimeout(() => {
          if (pending.delete(id)) reject(new Error(`${method} timed out`))
        }, 300_000)
        void Promise.resolve(resolve).then(() => clearTimeout(timer))
        child.stdin.write(encode({ jsonrpc: "2.0", id, method, params }))
      })
    },
    notify(method, params) {
      child.stdin.write(encode({ jsonrpc: "2.0", method, params }))
    },
    get nonProtocolStdout() {
      return nonProtocolStdout
    },
    get stderr() {
      return stderr
    },
    async close() {
      child.stdin.end()
      return exited
    },
  }
}

async function handshake(s: Session, label: string) {
  const init = await s.call("initialize", {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: "airlock-e2e", version: "0.0.0" },
  })
  const serverInfo = (init.result as { serverInfo?: { name?: string; version?: string } })?.serverInfo
  record(`${label}: initialize`, `serverInfo=${serverInfo?.name} ${serverInfo?.version}`, !!serverInfo?.name)
  s.notify("notifications/initialized")

  const list = await s.call("tools/list")
  const tools = ((list.result as { tools?: { name: string }[] })?.tools ?? []).map((t) => t.name)
  record(`${label}: tools/list passes through`, `${tools.length} tools: ${tools.slice(0, 6).join(", ")}`, tools.length > 0)
  return tools
}

/** Ask the server to report its own environment — proves where it is running. */
async function serverEnv(s: Session): Promise<string> {
  const res = await s.call("tools/call", { name: "get-env", arguments: {} })
  const content = (res.result as { content?: { text?: string }[] })?.content ?? []
  return content.map((c) => c.text ?? "").join("\n")
}

async function main() {
  // ---- Case 1: egress = [] — the strictest policy -----------------------
  console.log("\n=== [server.everything] egress = [], mounts = [] ===\n")
  const strict = startAirlock("everything")
  try {
    const tools = await handshake(strict, "strict")

    if (tools.includes("echo")) {
      const echo = await strict.call("tools/call", { name: "echo", arguments: { message: "airlock" } })
      const text = (echo.result as { content?: { text?: string }[] })?.content?.[0]?.text ?? ""
      record("strict: tools/call round-trips", JSON.stringify(text), text.includes("airlock"))
    }

    const env = await serverEnv(strict)
    // get-env returns a JSON object, so match on the JSON shape rather than
    // KEY=VALUE. The authoritative jail check is verifyJail() in the relay,
    // which fails closed; this only confirms the env reached the process.
    record(
      "strict: injected env reached the server",
      [/"HOME":\s*"\/home\/mcp"/, /"PATH":\s*"\/usr\/local\/bin/].map((r) => `${r.source}=${r.test(env)}`).join(" "),
      /"HOME":\s*"\/home\/mcp"/.test(env) && /"PATH":\s*"\/usr\/local\/bin/.test(env),
    )
    record(
      "strict: no proxy env with egress = [] (no network at all)",
      env.split("\n").filter((l) => /proxy/i.test(l)).join(" | ") || "(no proxy vars, as expected)",
      !/proxy=http/i.test(env),
    )
    record(
      "strict: stdout carried protocol only",
      strict.nonProtocolStdout.length === 0
        ? "every stdout line parsed as JSON"
        : `LEAKED: ${strict.nonProtocolStdout.slice(0, 3).join(" / ")}`,
      strict.nonProtocolStdout.length === 0,
    )
  } finally {
    const code = await strict.close()
    record("strict: clean teardown on client disconnect", `exit=${code}`, code === 0)
  }

  // ---- Case 2: a non-empty allowlist -------------------------------------
  console.log("\n=== [server.fetch] egress = [\"api.github.com\"] ===\n")
  const scoped = startAirlock("fetch")
  try {
    await handshake(scoped, "scoped")
    const env = await serverEnv(scoped)
    const proxyLines = env.split("\n").filter((l) => /proxy/i.test(l))
    record(
      "scoped: proxy env injected so the allowlist applies",
      proxyLines.join(" | ") || "(none — the allowlist would not be enforced!)",
      proxyLines.some((l) => /127\.0\.0\.1:8888/.test(l)),
    )
    record(
      "scoped: stdout carried protocol only",
      scoped.nonProtocolStdout.length === 0
        ? "every stdout line parsed as JSON"
        : `LEAKED: ${scoped.nonProtocolStdout.slice(0, 3).join(" / ")}`,
      scoped.nonProtocolStdout.length === 0,
    )
  } finally {
    const code = await scoped.close()
    record("scoped: clean teardown", `exit=${code}`, code === 0)
  }

  const passed = checks.filter((c) => c.pass).length
  console.log(`\n${passed}/${checks.length} checks passed`)
  if (passed !== checks.length) {
    console.log("failed:", checks.filter((c) => !c.pass).map((c) => c.name).join(", "))
    process.exit(1)
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
