/**
 * Skill launcher end to end (SPEC skills).
 *
 * Runs the bundled `skills/wordcount` skill through `airlock run` with a strict
 * policy and checks:
 *   1. skill_instructions returns the SKILL.md body (frontmatter stripped)
 *   2. skill_exec runs the skill's script inside the jail and returns its output
 *   3. the skill's code is jailed: it cannot read the host filesystem
 *   4. the skill's code is jailed: it has no network with egress = []
 *
 * Usage: npm run test:skill
 */
import { spawn } from "node:child_process"
import { mkdtempSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { requireApiKey } from "../src/env.js"
import { LineReader, encode, type JsonRpcResponse } from "../src/jsonrpc.js"

requireApiKey()

const SKILL_PATH = resolve(process.cwd(), "skills/wordcount")

async function main() {
  const workDir = mkdtempSync(join(tmpdir(), "airlock-skill-"))
  const configPath = join(workDir, "airlock.toml")
  writeFileSync(
    configPath,
    ["[server.wc]", 'launcher = "skill"', `path = ${JSON.stringify(SKILL_PATH)}`, "egress = []", "mounts = []", ""].join("\n"),
  )

  const child = spawn("npx", ["tsx", "src/cli.ts", "run", "wc", "--config", configPath], {
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
  const exec = async (command: string): Promise<string> => {
    const r = await call("tools/call", { name: "skill_exec", arguments: { command } })
    return (r.result as { content: { text: string }[] })?.content?.[0]?.text ?? JSON.stringify(r.error)
  }

  let pass = 0, fail = 0
  const check = (n: string, cond: boolean, d = "") => { console.log(`${cond ? "PASS" : "FAIL"}  ${n}${d ? `  — ${d}` : ""}`); cond ? pass++ : fail++ }

  try {
    await call("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "skill-test", version: "0" } })
    child.stdin.write(encode({ jsonrpc: "2.0", method: "notifications/initialized" }))

    const tools = ((await call("tools/list")).result as { tools: { name: string }[] }).tools.map((t) => t.name)
    check("bridge exposes skill_instructions + skill_exec", tools.includes("skill_instructions") && tools.includes("skill_exec"), tools.join(", "))

    const instr = await call("tools/call", { name: "skill_instructions", arguments: {} })
    const instrText = (instr.result as { content: { text: string }[] }).content[0].text
    check("skill_instructions returns the SKILL.md body", instrText.includes("Word count skill") && !instrText.includes("---\nname:"))

    const counted = await exec('echo "the quick brown fox the lazy dog the end" | python3 scripts/count.py')
    check("skill_exec runs the bundled script in the jail", counted.includes('"words": 9'), counted.slice(0, 80))

    const topped = await exec('echo "a a a b b c" | python3 scripts/top.py 2')
    check("skill_exec passes args to the script", topped.includes('"a"') && topped.includes("3"), topped.slice(0, 80))

    // jailed: cannot read the host filesystem
    const hostRead = await exec('cat ~/.ssh/id_rsa 2>&1 || cat /root/.aws/credentials 2>&1 || echo NO_HOST_FILES')
    check("skill code cannot read host files", !hostRead.includes("PRIVATE KEY") && !/aws_secret/.test(hostRead), hostRead.slice(0, 60))

    // jailed: no network with egress = []
    const net = await exec('curl -s -o /dev/null -w code=%{http_code} --max-time 8 https://example.com 2>&1 || echo BLOCKED')
    check("skill code has no network (egress = [])", !/code=(2|3)\d\d/.test(net), net.slice(0, 60))

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
