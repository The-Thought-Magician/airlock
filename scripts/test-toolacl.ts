/**
 * Per-tool permissions (allow/deny) end to end — the ToolHive-style control.
 *
 * server-everything exposes 13 tools. With `allow_tools = ["echo","add"]`:
 *   1. tools/list returns ONLY the two allowed tools (others hidden)
 *   2. calling an allowed tool works
 *   3. calling a hidden tool is BLOCKED by the relay (never reaches the server)
 *
 * Usage: npm run test:toolacl
 */
import { spawn } from "node:child_process"
import { mkdtempSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { requireApiKey } from "../src/env.js"
import { LineReader, encode, type JsonRpcResponse } from "../src/jsonrpc.js"

requireApiKey()

async function main() {
  const workDir = mkdtempSync(join(tmpdir(), "airlock-acl-"))
  const configPath = join(workDir, "airlock.toml")
  writeFileSync(
    configPath,
    [
      "[server.everything]",
      'launcher = "npx"',
      'package  = "@modelcontextprotocol/server-everything"',
      "egress   = []",
      "mounts   = []",
      'allow_tools = ["echo", "get-sum"]',
      "",
    ].join("\n"),
  )

  const child = spawn("npx", ["tsx", "src/cli.ts", "run", "everything", "--config", configPath], {
    cwd: process.cwd(),
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, AIRLOCK_LOG: join(workDir, "audit.jsonl") },
  })
  const pending = new Map<number, (r: JsonRpcResponse) => void>()
  let nextId = 1
  const reader = new LineReader((l) => {
    let m: JsonRpcResponse
    try { m = JSON.parse(l) } catch { return }
    if (typeof m.id === "number") { const r = pending.get(m.id); if (r) { pending.delete(m.id); r(m) } }
  })
  child.stdout.setEncoding("utf8"); child.stdout.on("data", (c: string) => reader.push(c))
  child.stderr.setEncoding("utf8"); child.stderr.on("data", (c: string) => process.stderr.write(`  \x1b[2m${c}\x1b[0m`))

  const call = (method: string, params?: unknown) => {
    const id = nextId++
    let timer: ReturnType<typeof setTimeout>
    const p = new Promise<JsonRpcResponse>((res, rej) => {
      pending.set(id, res)
      timer = setTimeout(() => { if (pending.delete(id)) rej(new Error(`${method} timed out`)) }, 300_000)
    })
    child.stdin.write(encode({ jsonrpc: "2.0", id, method, params }))
    return p.finally(() => clearTimeout(timer))
  }

  let pass = 0, fail = 0
  const check = (n: string, cond: boolean, d = "") => { console.log(`${cond ? "PASS" : "FAIL"}  ${n}${d ? `  — ${d}` : ""}`); cond ? pass++ : fail++ }

  try {
    await call("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "acl", version: "0" } })
    child.stdin.write(encode({ jsonrpc: "2.0", method: "notifications/initialized" }))

    const tools = ((await call("tools/list")).result as { tools: { name: string }[] }).tools.map((t) => t.name)
    check("tools/list shows only the allowed tools", tools.length === 2 && tools.includes("echo") && tools.includes("get-sum"), tools.join(", "))
    check("a hidden tool is not in tools/list", !tools.includes("get-env"), tools.join(", "))

    const echo = await call("tools/call", { name: "echo", arguments: { message: "acl" } })
    const echoText = (echo.result as { content?: { text?: string }[] })?.content?.[0]?.text ?? ""
    check("an allowed tool is callable", echoText.includes("acl"), JSON.stringify(echoText))

    const blocked = await call("tools/call", { name: "get-env", arguments: {} })
    check("a hidden tool is blocked on tools/call", blocked.error !== undefined && !blocked.result, blocked.error ? blocked.error.message.slice(0, 60) : "NOT BLOCKED")

    console.log(`\n${pass} passed, ${fail} failed`)
    process.exit(fail === 0 ? 0 : 1)
  } finally {
    child.stdin.end()
    await new Promise((r) => setTimeout(r, 1500))
    child.kill()
    rmSync(workDir, { recursive: true, force: true })
  }
}

main().catch((e) => { console.error(e); process.exit(1) })
