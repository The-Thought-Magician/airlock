/**
 * Runtime tool-definition drift detection (SPEC §3.4).
 *
 * Simulates a rug pull by pinning a deliberately wrong tools_hash, then checks
 * that `airlock run` blocks the tools/list response instead of forwarding
 * poisoned definitions to the agent — and that AIRLOCK_ALLOW_DRIFT=1 downgrades
 * the block to a warning that passes through.
 *
 * Usage: npm run test:drift
 */
import { spawn } from "node:child_process"
import { mkdtempSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { requireApiKey } from "../src/env.js"
import { LineReader, encode, type JsonRpcResponse } from "../src/jsonrpc.js"

requireApiKey()

const CONFIG_BODY = [
  "[server.everything]",
  'launcher = "npx"',
  'package  = "@modelcontextprotocol/server-everything"',
  "egress   = []",
  "mounts   = []",
  // A hash the live tools cannot possibly match — stands in for a rug pull.
  'tools_hash = "sha256:deadbeefdeadbeefdeadbeefdeadbeef"',
  "",
].join("\n")

async function runOnce(label: string, allowDrift: boolean): Promise<"blocked" | "passed"> {
  const workDir = mkdtempSync(join(tmpdir(), "airlock-drift-"))
  const configPath = join(workDir, "airlock.toml")
  writeFileSync(configPath, CONFIG_BODY)

  const child = spawn("npx", ["tsx", "src/cli.ts", "run", "everything", "--config", configPath], {
    cwd: process.cwd(),
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      AIRLOCK_LOG: join(workDir, "audit.jsonl"),
      ...(allowDrift ? { AIRLOCK_ALLOW_DRIFT: "1" } : {}),
    },
  })

  const pending = new Map<number, (r: JsonRpcResponse) => void>()
  let nextId = 1
  const reader = new LineReader((l) => {
    let m: JsonRpcResponse
    try {
      m = JSON.parse(l)
    } catch {
      return
    }
    if (typeof m.id === "number") {
      const r = pending.get(m.id)
      if (r) {
        pending.delete(m.id)
        r(m)
      }
    }
  })
  child.stdout.setEncoding("utf8")
  child.stdout.on("data", (c: string) => reader.push(c))
  child.stderr.setEncoding("utf8")
  child.stderr.on("data", (c: string) => process.stderr.write(`  \x1b[2m${c}\x1b[0m`))

  const call = (method: string, params?: unknown) => {
    const id = nextId++
    let timer: ReturnType<typeof setTimeout>
    const p = new Promise<JsonRpcResponse>((res, rej) => {
      pending.set(id, res)
      timer = setTimeout(() => {
        if (pending.delete(id)) rej(new Error(`${method} timed out`))
      }, 300_000)
    })
    child.stdin.write(encode({ jsonrpc: "2.0", id, method, params }))
    return p.finally(() => clearTimeout(timer))
  }

  try {
    await call("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "drift", version: "0" } })
    child.stdin.write(encode({ jsonrpc: "2.0", method: "notifications/initialized" }))
    const res = await call("tools/list")
    const outcome = res.error ? "blocked" : "passed"
    console.log(
      `${label}: ${outcome}` +
        (res.error ? ` — ${res.error.message.slice(0, 80)}…` : ` — ${(res.result as { tools?: unknown[] })?.tools?.length} tools`),
    )
    return outcome
  } finally {
    child.stdin.end()
    await new Promise((r) => setTimeout(r, 1500))
    child.kill()
    rmSync(workDir, { recursive: true, force: true })
  }
}

async function main() {
  console.log("simulating a rug pull with a mismatched tools_hash…\n")
  const blocked = await runOnce("default (should block)", false)
  const passed = await runOnce("AIRLOCK_ALLOW_DRIFT=1 (should pass with a warning)", true)

  const ok = blocked === "blocked" && passed === "passed"
  console.log(`\n${ok ? "PASS" : "FAIL"} — drift is ${blocked === "blocked" ? "blocked by default" : "NOT blocked!"}` +
    ` and ${passed === "passed" ? "bypassable with the escape hatch" : "NOT bypassable"}`)
  process.exit(ok ? 0 : 1)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
