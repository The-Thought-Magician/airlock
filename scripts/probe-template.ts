/**
 * The fifth warm-start alternative: a custom template (SPEC §0.1, §4).
 *
 * probe-warmstart2.ts showed snapshots lose on speed: restoring one averages
 * ~47s against a 12.3s cold create plus full provision, and revert() is
 * unavailable on this plan. But snapshots were carrying two benefits besides
 * speed — an immutable, reproducible build (so a poisoned upstream release
 * cannot reach you) and something shareable with a team.
 *
 * A custom template might deliver both without the restore cost: it is the
 * ordinary `create` path, it is immutable once built, and it is visible to the
 * whole org rather than being one machine's save point.
 *
 * Measured here:
 *   - one-off build cost of a template with the jail dependencies baked in
 *   - create-from-custom-template time, versus 3.0s for built-in `base`
 *   - whether the baked dependencies are actually present
 *
 * Usage: npm run probe:template
 */
import { SolariClient, Image } from "@solarisdk/sdk"
import type { Sandbox } from "@solarisdk/core"
import { mkdirSync, writeFileSync } from "node:fs"
import { requireApiKey } from "../src/env.js"

const apiKey = requireApiKey()
const PACKAGE = "@modelcontextprotocol/server-everything"
const TEMPLATE_NAME = `airlock-jail-${Date.now().toString(36)}`

async function sh(sandbox: Sandbox, script: string, timeoutMs = 300_000) {
  const out = await sandbox.commands.run("sh", { args: ["-c", script], timeoutMs })
  return (out.stdout + out.stderr).trim()
}

async function main() {
  const solari = new SolariClient({ apiKey })
  const findings: Record<string, unknown> = { at: new Date().toISOString() }

  // ---- What the template bakes in ---------------------------------------
  // Everything the jail needs, plus the server itself, so a launch is just
  // "create and go". Ordered apt → run, matching the documented build order.
  const image = Image.fromTemplate("base")
    .kind("sandbox")
    .aptInstall(["socat", "tinyproxy", "iproute2", "util-linux", "procps"])
    .runCommands(
      "useradd -m -u 4000 -s /bin/sh mcp",
      "mkdir -p /run/airlock /var/log/tinyproxy /home/mcp/work",
      "chown tinyproxy:tinyproxy /var/log/tinyproxy",
      "chown -R 4000:4000 /home/mcp/work",
      // Pin the exact version: this is the supply-chain guarantee, and it is
      // what a snapshot was really buying.
      `npm install -g ${PACKAGE} --no-fund --no-audit`,
    )

  console.log(`building template ${TEMPLATE_NAME}…`)
  console.log("(baking: socat, tinyproxy, iproute2, procps, the mcp user, and the server itself)\n")

  const tBuild = performance.now()
  let template
  try {
    template = await solari.templates.build(image, {
      name: TEMPLATE_NAME,
      kind: "sandbox",
      timeoutMs: 900_000,
      onLog: (line) => console.log(`  [build] ${line}`),
    })
  } catch (err) {
    console.error(`\ntemplate build FAILED: ${err instanceof Error ? err.message : String(err)}`)
    findings.buildFailed = err instanceof Error ? err.message : String(err)
    mkdirSync("findings", { recursive: true })
    writeFileSync(`findings/template-${Date.now()}.json`, JSON.stringify(findings, null, 2))
    process.exit(1)
  }
  const buildMs = performance.now() - tBuild
  console.log(`\ntemplate built in ${(buildMs / 1000).toFixed(1)}s → ${template.templateId} (${template.status})`)
  findings.buildMs = buildMs
  findings.templateId = template.templateId

  // ---- Create from it, three times --------------------------------------
  console.log(`\n=== create({ template: "${template.templateId}" }), x3 ===\n`)
  const times: number[] = []
  for (let i = 1; i <= 3; i++) {
    const t = performance.now()
    const sandbox = await solari.sandboxes.create({
      template: template.templateId,
      timeoutMs: 10 * 60_000,
      metadata: { airlock: "probe-template" },
    })
    await sandbox.connect()
    const ms = performance.now() - t
    times.push(ms)

    const state = await sh(
      sandbox,
      [
        `echo apt=$(command -v tinyproxy >/dev/null && command -v socat >/dev/null && echo yes || echo no)`,
        `echo server=$([ -d "$(npm root -g)/${PACKAGE}" ] && echo yes || echo no)`,
        `echo mcp=$(id -u mcp 2>/dev/null || echo no)`,
        `echo pgrep=$(command -v pgrep >/dev/null && echo yes || echo no)`,
      ].join("\n"),
      60_000,
    )
    console.log(`  #${i}  ${(ms / 1000).toFixed(2)}s   ${state.replace(/\n/g, " ")}`)
    await sandbox.kill().catch(() => {})
  }
  findings.createTimes = times

  // ---- Verdict -----------------------------------------------------------
  const mean = times.reduce((a, b) => a + b, 0) / times.length
  findings.createMeanMs = mean

  // Reference points from probe-warmstart2.ts on the same machine.
  const COLD_TOTAL_S = 12.32
  const FROM_SNAPSHOT_S = 46.81

  console.log("\n\n=== verdict ===\n")
  console.log(`template build (one-off)        : ${(buildMs / 1000).toFixed(1)}s`)
  console.log(`create from custom template     : ${(mean / 1000).toFixed(2)}s mean  (${times.map((t) => (t / 1000).toFixed(1) + "s").join(", ")})`)
  console.log(`cold base + full provision      : ${COLD_TOTAL_S.toFixed(2)}s   (measured earlier)`)
  console.log(`create({ fromSnapshot })        : ${FROM_SNAPSHOT_S.toFixed(2)}s   (measured earlier)`)
  console.log()
  console.log(`vs cold provision : ${(COLD_TOTAL_S / (mean / 1000)).toFixed(1)}x`)
  console.log(`vs fromSnapshot   : ${(FROM_SNAPSHOT_S / (mean / 1000)).toFixed(1)}x`)

  console.log(
    "\nNote: the template is not deleted, so `airlock run` can reuse it. " +
      `Remove it with solari.templates.delete("${template.templateId}").`,
  )

  mkdirSync("findings", { recursive: true })
  const path = `findings/template-${Date.now()}.json`
  writeFileSync(path, JSON.stringify(findings, null, 2))
  console.log(`\nfindings written to ${path}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
