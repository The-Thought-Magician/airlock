/**
 * Credential brokering end to end (SPEC §3.3).
 *
 * A jailed server fetches an echo endpoint (httpbin.org/headers) with NO auth
 * header of its own. If brokering works, the response shows the endpoint
 * received an Authorization header — injected by the proxy — while the server's
 * own environment never contained the secret.
 *
 * Three assertions:
 *   1. the echoed request carries the injected credential (proxy added it)
 *   2. the server's env does NOT contain the secret (it never had it)
 *   3. a non-allowlisted host is still blocked (brokering didn't weaken egress)
 *
 * Usage:
 *   set -a && . ./.env && set +a
 *   DEMO_TOKEN='Bearer sk-airlock-demo-not-a-real-key' npm run test:broker
 */
import { spawn } from "node:child_process"
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { requireApiKey } from "../src/env.js"
import { LineReader, encode, type JsonRpcResponse } from "../src/jsonrpc.js"

requireApiKey()

const TOKEN = process.env.DEMO_TOKEN ?? "Bearer sk-airlock-demo-not-a-real-key"
const ECHO_HOST = "httpbin.org"

async function main() {
  const workDir = mkdtempSync(join(tmpdir(), "airlock-broker-"))
  const serverDir = join(workDir, "server")
  mkdirSync(serverDir, { recursive: true })

  // A local server with two tools: `echo` fetches httpbin (no auth of its own)
  // and returns what the endpoint saw; `readenv` returns its own environment.
  writeFileSync(
    join(serverDir, "index.js"),
    `
const { execFile } = require("child_process")
function send(m){process.stdout.write(JSON.stringify(m)+"\\n")}
// curl honours https_proxy and CURL_CA_BUNDLE, both injected by Airlock. Node's
// own fetch(undici) ignores HTTP_PROXY, so a proxy-aware client is used here;
// see docs/LIMITATIONS.md.
function curl(args){
  return new Promise((resolve)=>{
    execFile("curl", args, {timeout:20000}, (err,stdout,stderr)=>{
      resolve(err ? ("curl_error: "+(err.code||err.message)+" "+stderr) : stdout)
    })
  })
}
async function echoHeaders(){ return curl(["-s","https://${ECHO_HOST}/headers"]) }
async function blockedFetch(){ return curl(["-s","-o","/dev/null","-w","code=%{http_code}","https://example.com/"]) }
let buf=""
process.stdin.setEncoding("utf8")
process.stdin.on("data", async c=>{buf+=c;let nl
  while((nl=buf.indexOf("\\n"))!==-1){const line=buf.slice(0,nl).trim();buf=buf.slice(nl+1)
    if(!line)continue;let m;try{m=JSON.parse(line)}catch{continue}
    if(m.method==="initialize")send({jsonrpc:"2.0",id:m.id,result:{protocolVersion:"2025-06-18",capabilities:{tools:{}},serverInfo:{name:"broker-probe",version:"1.0.0"}}})
    else if(m.method==="tools/list")send({jsonrpc:"2.0",id:m.id,result:{tools:[
      {name:"echo",description:"fetch the echo endpoint",inputSchema:{type:"object",properties:{}}},
      {name:"readenv",description:"return own environment",inputSchema:{type:"object",properties:{}}},
      {name:"blocked",description:"try a non-allowlisted host",inputSchema:{type:"object",properties:{}}}]}})
    else if(m.method==="tools/call"){
      const t=m.params&&m.params.name
      let text
      if(t==="echo") text=await echoHeaders()
      else if(t==="readenv") text=JSON.stringify(process.env)
      else if(t==="blocked") text=await blockedFetch()
      else text="unknown tool"
      send({jsonrpc:"2.0",id:m.id,result:{content:[{type:"text",text}]}})
    }
    else if(m.id!==undefined)send({jsonrpc:"2.0",id:m.id,error:{code:-32601,message:"nope"}})
  }})
`,
  )

  const configPath = join(workDir, "airlock.toml")
  writeFileSync(
    configPath,
    [
      "[server.broker]",
      'launcher = "local"',
      `path = ${JSON.stringify(serverDir)}`,
      `egress = ["${ECHO_HOST}"]`,
      "mounts = []",
      "[[server.broker.broker]]",
      `host = "${ECHO_HOST}"`,
      'header = "Authorization"',
      'value = "env:DEMO_TOKEN"',
      "",
    ].join("\n"),
  )

  const child = spawn("npx", ["tsx", "src/cli.ts", "run", "broker", "--config", configPath], {
    cwd: process.cwd(),
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, DEMO_TOKEN: TOKEN, AIRLOCK_LOG: join(workDir, "audit.jsonl") },
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
  const toolText = async (name: string): Promise<string> => {
    const res = await call("tools/call", { name, arguments: {} })
    return (res.result as { content: { text: string }[] }).content[0].text
  }

  let pass = 0
  let fail = 0
  const check = (name: string, cond: boolean, detail = "") => {
    console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? `  — ${detail}` : ""}`)
    cond ? pass++ : fail++
  }

  try {
    await call("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "broker-test", version: "0" } })
    child.stdin.write(encode({ jsonrpc: "2.0", method: "notifications/initialized" }))

    const echoed = await toolText("echo")
    const env = await toolText("readenv")
    const blocked = await toolText("blocked")

    if (echoed.startsWith("curl_error")) {
      console.log(`\n(echo endpoint unreachable: ${echoed.slice(0, 120)})`)
      console.log("cannot judge injection if the endpoint is down; treating as inconclusive.")
    }

    // 1. the endpoint saw the injected header
    check(
      "proxy injected the credential into the request",
      echoed.includes(TOKEN),
      echoed.includes(TOKEN) ? "endpoint echoed the Authorization header" : `not found in: ${echoed.slice(0, 160)}`,
    )
    // 2. the server never had the secret
    check(
      "server env does NOT contain the secret",
      !env.includes(TOKEN) && !env.includes("DEMO_TOKEN"),
      env.includes(TOKEN) ? "LEAKED into env!" : "confirmed absent from the server's environment",
    )
    // 3. egress still enforced
    check("non-allowlisted host still blocked", !blocked.includes("code=200"), blocked.slice(0, 80))

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
