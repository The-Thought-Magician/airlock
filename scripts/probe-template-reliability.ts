/**
 * Is a custom template actually dependable? (follow-up to FINDINGS-WARMSTART)
 *
 * probe-template.ts measured `create({ template: "tpl_…" })` at 11.4s, 3/3
 * successes, and that number is why `airlock build` exists. Roughly 90 minutes
 * later the same call began failing consistently with `No sandbox host
 * available` after ~50s, while `create({ template: "base" })` kept succeeding
 * in ~2s. The template's own status is `ready`.
 *
 * If custom templates are unreliable then the recommendation in
 * FINDINGS-WARMSTART is wrong and cold provisioning from `base` — which has
 * not failed once — has to be the default. That is worth measuring rather than
 * guessing, so this alternates attempts between the two and reports the split.
 *
 * Usage: npm run probe:reliability -- <templateId>
 */
import { SolariClient } from "@solarisdk/sdk"
import { mkdirSync, writeFileSync } from "node:fs"
import { requireApiKey } from "../src/env.js"

const apiKey = requireApiKey()
const templateId = process.argv[2]
if (!templateId) {
  process.stderr.write("usage: npm run probe:reliability -- <templateId>\n")
  process.exit(2)
}

const ROUNDS = 4

interface Attempt {
  template: string
  round: number
  ok: boolean
  ms: number
  error?: string
}

async function main() {
  const solari = new SolariClient({ apiKey })
  const attempts: Attempt[] = []

  for (let round = 1; round <= ROUNDS; round++) {
    // Alternate so a platform-wide capacity dip cannot be mistaken for a
    // template-specific fault: if both fail together it is the platform.
    for (const template of ["base", templateId]) {
      const t = performance.now()
      try {
        const sandbox = await solari.sandboxes.create({
          template,
          timeoutMs: 120_000,
          metadata: { airlock: "reliability" },
        })
        const ms = performance.now() - t
        attempts.push({ template, round, ok: true, ms })
        console.log(`round ${round}  ok    ${template.padEnd(22)} ${(ms / 1000).toFixed(2)}s`)
        await sandbox.kill().catch(() => {})
      } catch (err) {
        const ms = performance.now() - t
        const error = err instanceof Error ? err.message : String(err)
        attempts.push({ template, round, ok: false, ms, error })
        console.log(`round ${round}  FAIL  ${template.padEnd(22)} ${(ms / 1000).toFixed(2)}s  ${error}`)
      }
    }
  }

  console.log("\n=== summary ===\n")
  for (const template of ["base", templateId]) {
    const mine = attempts.filter((a) => a.template === template)
    const ok = mine.filter((a) => a.ok)
    const meanOk = ok.length ? ok.reduce((s, a) => s + a.ms, 0) / ok.length / 1000 : NaN
    console.log(
      `${template.padEnd(24)} ${ok.length}/${mine.length} succeeded` +
        (ok.length ? `, mean ${meanOk.toFixed(2)}s` : "") +
        (ok.length < mine.length ? `  — errors: ${[...new Set(mine.filter((a) => !a.ok).map((a) => a.error))].join("; ")}` : ""),
    )
  }

  const baseOk = attempts.filter((a) => a.template === "base" && a.ok).length
  const tplOk = attempts.filter((a) => a.template === templateId && a.ok).length
  console.log()
  if (baseOk === ROUNDS && tplOk < ROUNDS) {
    console.log(
      "VERDICT: `base` is reliable and the custom template is not. Cold provisioning\n" +
        "must stay the default, and `airlock build` cannot be presented as the happy path.",
    )
  } else if (baseOk < ROUNDS && tplOk < ROUNDS) {
    console.log("VERDICT: both are failing — this is a platform-wide capacity problem, not a template fault.")
  } else {
    console.log("VERDICT: the custom template is behaving; the earlier failures were transient.")
  }

  mkdirSync("findings", { recursive: true })
  const path = `findings/template-reliability-${Date.now()}.json`
  writeFileSync(path, JSON.stringify({ at: new Date().toISOString(), templateId, attempts }, null, 2))
  console.log(`\nfindings written to ${path}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
