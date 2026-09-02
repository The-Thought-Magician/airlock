/**
 * The Airlock demo (SPEC §8) as a reproducible transcript.
 *
 * Runs the SAME evil MCP server and the SAME tool call twice — once natively,
 * once under Airlock — and shows the difference. This is the actual deliverable;
 * the code is the evidence that the demo is real.
 *
 * Safety (SPEC §8.2), all enforced by this script, not merely promised:
 *   - the "credential" is a fake file this script writes to a temp dir with
 *     fake contents. No real ~/.aws or ~/.ssh is ever read.
 *   - the exfil target is a localhost listener this script starts and stops.
 *     Nothing leaves this machine.
 *
 * Usage:
 *   set -a && . ./.env && set +a
 *   npm run demo
 */
import { spawn } from "node:child_process"
import { createServer } from "node:http"
import { mkdtempSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"
import { dirname, resolve } from "node:path"
import { requireApiKey } from "../src/env.js"
import { LineReader, encode, type JsonRpcResponse } from "../src/jsonrpc.js"
import { AuditLog } from "../src/audit.js"

const here = dirname(fileURLToPath(import.meta.url))
const projectRoot = resolve(here, "..")
const EVIL_DIR = join(here, "evil-server")
const EXFIL_PORT = 9099
const PROTOCOL_VERSION = "2025-06-18"

// ---- pretty output ------------------------------------------------------
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`
const red = (s: string) => `\x1b[31m${s}\x1b[0m`
const green = (s: string) => `\x1b[32m${s}\x1b[0m`
const dim = (s: string) => `\x1b[2m${s}\x1b[0m`
const rule = () => console.log(dim("─".repeat(72)))

function heading(title: string) {
  console.log("\n" + bold(title))
  rule()
}

/** A minimal MCP client driving one server subprocess. */
class Client {
  private nextId = 1
  private readonly pending = new Map<number, (r: JsonRpcResponse) => void>()
  private readonly reader: LineReader

  constructor(private readonly write: (line: string) => void) {
    this.reader = new LineReader((line) => {
      let msg: JsonRpcResponse
      try {
        msg = JSON.parse(line)
      } catch {
        return
      }
      if (typeof msg.id === "number") {
        const resolve = this.pending.get(msg.id)
        if (resolve) {
          this.pending.delete(msg.id)
          resolve(msg)
        }
      }
    })
  }
  feed(chunk: string) {
    this.reader.push(chunk)
  }
  call(method: string, params?: unknown, timeoutMs = 300_000): Promise<JsonRpcResponse> {
    const id = this.nextId++
    let timer: ReturnType<typeof setTimeout>
    const p = new Promise<JsonRpcResponse>((res, rej) => {
      this.pending.set(id, res)
      timer = setTimeout(() => {
        if (this.pending.delete(id)) rej(new Error(`${method} timed out`))
      }, timeoutMs)
    })
    this.write(encode({ jsonrpc: "2.0", id, method, params }))
    return p.finally(() => clearTimeout(timer))
  }
  notify(method: string, params?: unknown) {
    this.write(encode({ jsonrpc: "2.0", method, params }))
  }
}

async function runCall(client: Client): Promise<{ sum: string; note: unknown; egress: string }> {
  await client.call("initialize", {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: "airlock-demo", version: "0.0.0" },
  })
  client.notify("notifications/initialized")
  const tools = (await client.call("tools/list")).result as { tools: { name: string; description: string }[] }
  console.log(`agent sees tool: ${bold(tools.tools[0].name)} — "${tools.tools[0].description}"`)
  console.log(`agent calls: ${bold("add(2, 3)")}`)
  const res = (await client.call("tools/call", { name: "add", arguments: { a: 2, b: 3 } })).result as {
    content: { text: string }[]
    _airlockDemoNote?: unknown
  }
  console.log(`agent calls: ${bold("ping()")} ${dim("(the server's second, network-facing tool)")}`)
  const ping = (await client.call("tools/call", { name: "ping", arguments: {} })).result as {
    _airlockDemoNote?: { result?: string }
  }
  return { sum: res.content[0].text, note: res._airlockDemoNote, egress: ping._airlockDemoNote?.result ?? "?" }
}

async function main() {
  const apiKey = requireApiKey()

  // ---- Set up the safe demo environment --------------------------------
  const workDir = mkdtempSync(join(tmpdir(), "airlock-demo-"))
  const fakeCredPath = join(workDir, "credentials")
  const fakeCreds =
    "[default]\naws_access_key_id = AKIAFAKEFAKEFAKEFAKE\naws_secret_access_key = FAKEfakeFAKEfakeFAKEfakeFAKEfake0000\n"
  writeFileSync(fakeCredPath, fakeCreds)

  const captured: string[] = []
  const listener = createServer((req, res) => {
    let body = ""
    req.on("data", (c) => (body += c))
    req.on("end", () => {
      captured.push(body)
      res.writeHead(200)
      res.end("ok")
    })
  })
  await new Promise<void>((r) => listener.listen(EXFIL_PORT, "127.0.0.1", r))

  console.log(bold("\n  Airlock demo — the same evil server, run two ways\n"))
  console.log(dim(`  fake credential : ${fakeCredPath}`))
  console.log(dim(`  fake contents   : AKIAFAKE… (not a real key)`))
  console.log(dim(`  exfil listener  : http://127.0.0.1:${EXFIL_PORT} (localhost only)`))

  let nativeStolen = false
  let jailedStolen = false
  let jailedEgress = ""

  try {
    // ================================================================
    // LEFT: the server running NATIVELY, as an MCP client launches it today
    // ================================================================
    heading("1 / 2   evil server running NATIVELY (no Airlock)")
    {
      const child = spawn("node", [join(EVIL_DIR, "index.js")], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, EVIL_TARGET_FILE: fakeCredPath, EVIL_EXFIL_PORT: String(EXFIL_PORT) },
      })
      const client = new Client((line) => child.stdin.write(line))
      child.stdout.setEncoding("utf8")
      child.stdout.on("data", (c: string) => client.feed(c))
      child.stderr.setEncoding("utf8")
      child.stderr.on("data", (c: string) => process.stderr.write(dim(c.toString())))

      const { sum, note, egress } = await runCall(client)
      child.stdin.end()
      await new Promise((r) => setTimeout(r, 500))

      console.log(`\nadd returned: ${sum}  ${dim("(the innocuous part)")}`)
      console.log("what add did on the side:", note)
      console.log(`what ping did: ${egress}`)
      nativeStolen = captured.length > 0
      if (nativeStolen) {
        console.log(red(`\n  ✗ CREDENTIAL STOLEN. The listener received:`))
        console.log(red("    " + captured[captured.length - 1]))
      }
    }

    // reset the capture so the second run is judged on its own
    captured.length = 0

    // ================================================================
    // RIGHT: the SAME server, SAME call, under Airlock
    // ================================================================
    heading("2 / 2   the SAME evil server, SAME call, under Airlock")
    const auditPath = join(workDir, "audit.jsonl")
    {
      // Write a scratch policy identical to [server.evil] but with the demo's
      // fake target and exfil port wired in via `secrets` (which pass through
      // to the server verbatim). In the jail the file will not exist and the
      // POST will not route — that is the demonstration — but wiring them at all
      // proves it is the same server doing the same thing as the native run.
      const demoConfig = join(workDir, "airlock.toml")
      writeFileSync(
        demoConfig,
        [
          "[server.evil]",
          'launcher = "local"',
          `path     = ${JSON.stringify(join(EVIL_DIR))}`,
          "egress   = []",
          "mounts   = []",
          "[server.evil.secrets]",
          `EVIL_TARGET_FILE = ${JSON.stringify(fakeCredPath)}`,
          `EVIL_EXFIL_PORT = ${JSON.stringify(String(EXFIL_PORT))}`,
          "",
        ].join("\n"),
      )

      // Drive the real CLI as a subprocess — exactly how an MCP client invokes
      // Airlock. This is more honest than reaching into runRelay in-process,
      // and it exercises the actual `airlock run` entrypoint.
      const child = spawn("npx", ["tsx", "src/cli.ts", "run", "evil", "--config", demoConfig], {
        cwd: projectRoot,
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, AIRLOCK_LOG: auditPath },
      })
      const client = new Client((line) => child.stdin.write(line))
      child.stdout.setEncoding("utf8")
      child.stdout.on("data", (c: string) => client.feed(c))
      child.stderr.setEncoding("utf8")
      child.stderr.on("data", (c: string) => process.stderr.write(dim(c.toString())))

      try {
        const { sum, note, egress } = await runCall(client)
        console.log(`\nadd returned: ${sum}  ${dim("(same innocuous part)")}`)
        console.log("what add tried on the side:", note)
        console.log(`what ping tried: ${bold(egress)}`)
        jailedEgress = egress
      } finally {
        child.stdin.end()
        await new Promise((r) => setTimeout(r, 1500))
        child.kill()
      }

      jailedStolen = captured.length > 0
      if (!jailedStolen) {
        console.log(green(`\n  ✓ NOTHING STOLEN. The listener received nothing.`))
        console.log(green(`    the credential file was not on the sandbox (ENOENT),`))
        console.log(green(`    and the exfil POST had no route out of the jail.`))
      } else {
        console.log(red(`\n  ✗ something was captured — the jail did not hold: ${captured[0]}`))
      }

      // The audit trail, §3.6
      heading("audit trail (airlock log)")
      for (const line of AuditLog.read(auditPath)) {
        if (line.kind === "net.attempt") {
          console.log(`  net.${line.allowed ? "allow" : bold("BLOCK")}  ${line.host}`)
        } else if (line.kind === "tool.call") {
          console.log(`  tool.call  ${line.tool}`)
        } else if (line.kind === "session.start") {
          console.log(`  session.start  ${line.server}  egress=[${line.egress.join(",")}]`)
        }
      }
    }

    // ---- Verdict --------------------------------------------------------
    heading("result")
    console.log(`  native  : ${nativeStolen ? red("credential stolen and exfiltrated") : "?"}`)
    console.log(
    `  airlock : ${!jailedStolen ? green("credential read blocked (ENOENT)") : red("read NOT blocked")}, ` +
      `${/blocked/i.test(jailedEgress) ? green("raw egress blocked") : red("egress NOT blocked")}`,
  )

    const demoPassed = nativeStolen && !jailedStolen && /blocked/i.test(jailedEgress)
    console.log(
      "\n" +
        (demoPassed
          ? green(bold("  demo verified: the boundary is real, not asserted."))
          : red(bold("  demo did NOT behave as expected — investigate before recording."))),
    )
    process.exitCode = demoPassed ? 0 : 1
  } finally {
    listener.close()
    rmSync(workDir, { recursive: true, force: true })
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
