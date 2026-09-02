/**
 * Node's global fetch works through the jail (the shim, end to end).
 *
 * A local server whose tool uses Node's built-in fetch — no curl, no
 * ProxyAgent of its own — is run through `airlock run` with egress allowlisting
 * httpbin.org. Without the auto-injected proxy shim this fetch reaches nothing;
 * with it, the allowlisted host works and a non-allowlisted one is still
 * blocked.
 *
 * Usage: npm run test:nodefetch
 */
import { spawn } from "node:child_process"
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { requireApiKey } from "../src/env.js"
import { LineReader, encode, type JsonRpcResponse } from "../src/jsonrpc.js"

requireApiKey()

async function main() {
  const workDir = mkdtempSync(join(tmpdir(), "airlock-nodefetch-"))
  const serverDir = join(workDir, "server")
  mkdirSync(serverDir, { recursive: true })

  writeFileSync(
    join(serverDir, "index.js"),
    `
// Uses ONLY Node's global fetch — no curl, no explicit proxy agent.
function send(m){process.stdout.write(JSON.stringify(m)+"\\n")}
async function hit(url){
  try{ const r = await fetch(url); return "OK "+r.status+" len="+(await r.text()).length }
  catch(e){ return "FAIL "+(e && (e.cause && e.cause.code || e.message) || e) }
}
let buf=""
process.stdin.setEncoding("utf8")
process.stdin.on("data", async c=>{buf+=c;let nl
  while((nl=buf.indexOf("\\n"))!==-1){const line=buf.slice(0,nl).trim();buf=buf.slice(nl+1)
    if(!line)continue;let m;try{m=JSON.parse(line)}catch{continue}
    if(m.method==="initialize")send({jsonrpc:"2.0",id:m.id,result:{protocolVersion:"2025-06-18",capabilities:{tools:{}},serverInfo:{name:"nodefetch",version:"1.0.0"}}})
    else if(m.method==="tools/list")send({jsonrpc:"2.0",id:m.id,result:{tools:[
      {name:"allowed",description:"fetch the allowlisted host",inputSchema:{type:"object",properties:{}}},
      {name:"blocked",description:"fetch a non-allowlisted host",inputSchema:{type:"object",properties:{}}}]}})
    else if(m.method==="tools/call"){
      const t=m.params&&m.params.name
      const url = t==="allowed" ? "https://httpbin.org/get" : "https://example.com/"
      send({jsonrpc:"2.0",id:m.id,result:{content:[{type:"text",text:await hit(url)}]}})
    }
    else if(m.id!==undefined)send({jsonrpc:"2.0",id:m.id,error:{code:-32601,message:"nope"}})
  }})
`,
  )
  const configPath = join(workDir, "airlock.toml")
  writeFileSync(
    configPath,
    ["[server.nf]", 'launcher = "local"', `path = ${JSON.stringify(serverDir)}`, 'egress = ["httpbin.org"]', "mounts = []", ""].join("\n"),
  )

  const child = spawn("npx", ["tsx", "src/cli.ts", "run", "nf", "--config", configPath], {
    cwd: process.cwd(),
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, AIRLOCK_LOG: join(workDir, "audit.jsonl") },
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
  const toolText = async (name: string) =>
    ((await call("tools/call", { name, arguments: {} })).result as { content: { text: string }[] }).content[0].text

  let pass = 0
  let fail = 0
  const check = (n: string, cond: boolean, d = "") => {
    console.log(`${cond ? "PASS" : "FAIL"}  ${n}${d ? `  — ${d}` : ""}`)
    cond ? pass++ : fail++
  }

  try {
    await call("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "nf", version: "0" } })
    child.stdin.write(encode({ jsonrpc: "2.0", method: "notifications/initialized" }))
    const allowed = await toolText("allowed")
    const blocked = await toolText("blocked")
    check("node fetch reaches the allowlisted host via the shim", allowed.startsWith("OK"), allowed.slice(0, 80))
    check("node fetch to a non-allowlisted host is blocked", !blocked.startsWith("OK"), blocked.slice(0, 80))
    console.log(`\n${pass} passed, ${fail} failed`)
    process.exit(fail === 0 ? 0 : 1)
  } finally {
    child.stdin.end()
    await new Promise((r) => setTimeout(r, 1500))
    child.kill()
    rmSync(workDir, { recursive: true, force: true })
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
