/**
 * Does the relay corrupt multi-byte UTF-8? (the caveat from FINDINGS-DAY1 §4b)
 *
 * The SDK decodes each cmd.data frame with a fresh `new TextDecoder()` and no
 * streaming flag. In theory a multi-byte character split across two frames is
 * turned into replacement characters before Airlock ever sees it. This test
 * settles whether that is a real defect or only a theoretical one, by pushing a
 * large payload of mixed emoji and CJK — where almost every byte boundary lands
 * mid-character — through the actual `airlock run` relay and comparing the
 * bytes that come back.
 *
 * Exits 0 if the payload round-trips intact, 1 if it corrupts.
 *
 * Usage: npm run test:utf8
 */
import { spawn } from "node:child_process"
import { mkdtempSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { requireApiKey } from "../src/env.js"
import { LineReader, encode, type JsonRpcResponse } from "../src/jsonrpc.js"

requireApiKey()

// A big string where multi-byte characters sit at nearly every offset, so some
// chunk boundary is very likely to fall inside one. Emoji are 4 UTF-8 bytes,
// CJK are 3, combining sequences vary — a thorough spread.
function payload(): string {
  const alphabet = "🔒🌐日本語한국어🇯🇵café🧪🛰️𝓪𝓫🦀—…✓✗🔑"
  let s = ""
  for (let i = 0; i < 8000; i++) s += alphabet
  return s // ~ hundreds of KB of mixed-width UTF-8
}

async function main() {
  const expected = payload()
  const workDir = mkdtempSync(join(tmpdir(), "airlock-utf8-"))
  const serverDir = join(workDir, "server")
  const { mkdirSync } = await import("node:fs")
  mkdirSync(serverDir, { recursive: true })

  // A minimal local MCP server that echoes a big unicode blob back verbatim.
  writeFileSync(
    join(serverDir, "index.js"),
    `
const BLOB = ${JSON.stringify(expected)}
function send(m){process.stdout.write(JSON.stringify(m)+"\\n")}
let buf=""
process.stdin.setEncoding("utf8")
process.stdin.on("data",c=>{buf+=c;let nl
  while((nl=buf.indexOf("\\n"))!==-1){const line=buf.slice(0,nl).trim();buf=buf.slice(nl+1)
    if(!line)continue;let m;try{m=JSON.parse(line)}catch{continue}
    if(m.method==="initialize")send({jsonrpc:"2.0",id:m.id,result:{protocolVersion:m.params?.protocolVersion||"2025-06-18",capabilities:{tools:{}},serverInfo:{name:"utf8-echo",version:"1.0.0"}}})
    else if(m.method==="tools/list")send({jsonrpc:"2.0",id:m.id,result:{tools:[{name:"blob",description:"return a big unicode blob",inputSchema:{type:"object",properties:{}}}]}})
    else if(m.method==="tools/call")send({jsonrpc:"2.0",id:m.id,result:{content:[{type:"text",text:BLOB}]}})
    else if(m.id!==undefined)send({jsonrpc:"2.0",id:m.id,error:{code:-32601,message:"nope"}})
  }})
`,
  )
  const configPath = join(workDir, "airlock.toml")
  writeFileSync(
    configPath,
    ["[server.utf8]", 'launcher = "local"', `path = ${JSON.stringify(serverDir)}`, "egress = []", "mounts = []", ""].join("\n"),
  )

  const child = spawn("npx", ["tsx", "src/cli.ts", "run", "utf8", "--config", configPath], {
    cwd: process.cwd(),
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, AIRLOCK_LOG: join(workDir, "audit.jsonl") },
  })

  const pending = new Map<number, (r: JsonRpcResponse) => void>()
  const reader = new LineReader((line) => {
    let m: JsonRpcResponse
    try {
      m = JSON.parse(line)
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

  let nextId = 1
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
    await call("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "utf8-test", version: "0" } })
    child.stdin.write(encode({ jsonrpc: "2.0", method: "notifications/initialized" }))
    const res = await call("tools/call", { name: "blob", arguments: {} })
    const got = (res.result as { content: { text: string }[] }).content[0].text

    const ok = got === expected
    const gotBytes = Buffer.byteLength(got, "utf8")
    const wantBytes = Buffer.byteLength(expected, "utf8")
    const replacements = (got.match(/�/g) ?? []).length

    console.log(`expected ${expected.length} chars / ${wantBytes} bytes`)
    console.log(`got      ${got.length} chars / ${gotBytes} bytes`)
    console.log(`U+FFFD replacement chars in output: ${replacements}`)

    if (ok) {
      console.log("\nPASS — the payload round-tripped byte-for-byte. The frame-split")
      console.log("       concern does not manifest in practice on this transport.")
      process.exitCode = 0
    } else {
      // Find the first divergence for a precise report.
      let i = 0
      while (i < got.length && i < expected.length && got[i] === expected[i]) i++
      console.log(`\nFAIL — output differs. first divergence at char ${i}:`)
      console.log(`       expected …${JSON.stringify(expected.slice(i, i + 10))}`)
      console.log(`       got      …${JSON.stringify(got.slice(i, i + 10))}`)
      console.log("       The base64-per-line wrapper fix from FINDINGS-DAY1 §4b is needed.")
      process.exitCode = 1
    }
  } finally {
    child.stdin.end()
    await new Promise((r) => setTimeout(r, 1000))
    child.kill()
    rmSync(workDir, { recursive: true, force: true })
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
