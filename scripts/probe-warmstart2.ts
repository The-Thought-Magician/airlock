/**
 * Warm-start alternatives, round two (SPEC §7 Q7, §4).
 *
 * probe-warmstart.ts produced a result that, if it holds, undermines SPEC §4
 * and §5: `create({ fromSnapshot })` took 59s against a 15.3s cold create plus
 * full provision. The spec claims snapshot restore is "milliseconds" and makes
 * that the reason Solari is load-bearing rather than decorative.
 *
 * Before believing it, three things need isolating:
 *
 *   1. Was 59s a cold-storage effect? Restore the SAME snapshot several times
 *      and see whether it warms up.
 *   2. pause/resume worked on the first run (resume 3.68s) and reported "Not
 *      found" on the second, where a failed revert() preceded it. Test it on a
 *      machine that has not had a failed revert, and repeat it.
 *   3. Is revert() available on this plan at all? It returned "Not revertable"
 *      twice. Test it last, since a failed revert appears to invalidate the
 *      session.
 *
 * Usage: npm run probe:warmstart2
 */
import { SolariClient } from "@solarisdk/sdk"
import type { Sandbox } from "@solarisdk/core"
import { mkdirSync, writeFileSync } from "node:fs"
import { requireApiKey } from "../src/env.js"

const apiKey = requireApiKey()
const PACKAGE = "@modelcontextprotocol/server-everything"

interface Sample {
  label: string
  ms: number
  ok: boolean
  detail?: string
}
const samples: Sample[] = []

function note(label: string, ms: number, ok: boolean, detail?: string) {
  samples.push({ label, ms, ok, detail })
  const time = Number.isFinite(ms) ? `${(ms / 1000).toFixed(2)}s` : "—"
  console.log(`${ok ? "  ok " : "FAIL "} ${label.padEnd(38)} ${time.padStart(8)}${detail ? `   ${detail}` : ""}`)
}

async function sh(sandbox: Sandbox, script: string, timeoutMs = 300_000) {
  const out = await sandbox.commands.run("sh", { args: ["-c", script], timeoutMs })
  return (out.stdout + out.stderr).trim()
}

/** Confirm a restored machine is genuinely usable, not merely reachable. */
async function verifyUsable(sandbox: Sandbox): Promise<string> {
  return sh(
    sandbox,
    [
      `echo apt=$(command -v tinyproxy >/dev/null && echo yes || echo no)`,
      `echo server=$([ -d "$(npm root -g)/${PACKAGE}" ] && echo yes || echo no)`,
      `echo proxy=$([ -f /run/tinyproxy.pid ] && kill -0 "$(cat /run/tinyproxy.pid)" 2>/dev/null && echo yes || echo no)`,
      `echo netns=$(ip netns list 2>/dev/null | grep -q airlock && echo yes || echo no)`,
    ].join("\n"),
    60_000,
  ).then((s) => s.replace(/\n/g, " "))
}

async function provision(sandbox: Sandbox) {
  await sh(
    sandbox,
    [
      "set -e",
      "export DEBIAN_FRONTEND=noninteractive",
      "apt-get update -qq >/dev/null 2>&1",
      "apt-get install -y -qq socat tinyproxy iproute2 util-linux >/dev/null 2>&1",
      "id -u mcp >/dev/null 2>&1 || useradd -m -u 4000 -s /bin/sh mcp",
      "mkdir -p /run/airlock /var/log/tinyproxy /home/mcp/work",
      "chown tinyproxy:tinyproxy /var/log/tinyproxy",
    ].join("\n"),
  )
  await sh(sandbox, `npm install -g ${PACKAGE} --silent --no-fund --no-audit`, 600_000)
  await sh(
    sandbox,
    [
      `printf 'User tinyproxy\\nGroup tinyproxy\\nPort 8888\\nListen 127.0.0.1\\nLogLevel Connect\\nLogFile "/var/log/tinyproxy/tinyproxy.log"\\nPidFile "/run/tinyproxy.pid"\\nMaxClients 50\\nAllow 127.0.0.1\\nFilterDefaultDeny Yes\\nFilterType ere\\nConnectPort 443\\n' > /etc/tinyproxy/airlock.conf`,
      "tinyproxy -c /etc/tinyproxy/airlock.conf",
      "ip netns add airlock 2>/dev/null || true",
      "ip netns exec airlock ip link set lo up",
    ].join("\n"),
  )
}

async function main() {
  const solari = new SolariClient({ apiKey })

  console.log("\n=== baseline: cold create + full provision ===\n")
  const tCold = performance.now()
  const s1 = await solari.sandboxes.create({
    template: "base",
    timeoutMs: 25 * 60_000,
    metadata: { airlock: "warmstart2" },
  })
  await s1.connect()
  const createMs = performance.now() - tCold
  note("cold create + connect", createMs, true)

  const tProv = performance.now()
  await provision(s1)
  const provisionMs = performance.now() - tProv
  note("provision (apt + npm + jail)", provisionMs, true)
  const coldTotalMs = createMs + provisionMs
  note("→ cold total", coldTotalMs, true, await verifyUsable(s1))

  console.log("\n=== snapshot() ===\n")
  const tSnap = performance.now()
  const snapshotId = await s1.snapshot("airlock-warmstart2")
  const snapshotMs = performance.now() - tSnap
  note("snapshot()", snapshotMs, true, snapshotId.slice(0, 28) + "…")

  // ---- 2. pause / resume, repeated, on an uncontaminated machine --------
  console.log("\n=== D. pause() + resume(), x2 ===\n")
  const pauseResume: number[] = []
  for (let i = 1; i <= 2; i++) {
    try {
      const tP = performance.now()
      await s1.pause()
      const pauseMs = performance.now() - tP
      note(`pause() #${i}`, pauseMs, true)

      const tR = performance.now()
      await s1.resume()
      if (!s1.connected) await s1.connect()
      const resumeMs = performance.now() - tR
      pauseResume.push(resumeMs)
      note(`resume() #${i}`, resumeMs, true, await verifyUsable(s1))
    } catch (err) {
      note(`pause/resume #${i}`, NaN, false, err instanceof Error ? err.message : String(err))
      break
    }
  }

  // ---- 3. revert, last, because a failure seems to invalidate the session
  console.log("\n=== C. revert(snapshotId) — tested last, it is destructive on failure ===\n")
  try {
    const tRev = performance.now()
    await s1.revert(snapshotId)
    if (!s1.connected) await s1.connect()
    note("revert()", performance.now() - tRev, true, await verifyUsable(s1))
  } catch (err) {
    note("revert()", NaN, false, err instanceof Error ? err.message : String(err))
  }

  await s1.kill().catch(() => {})
  console.log("\n(baseline sandbox killed)")

  // ---- 1. fromSnapshot, repeated, to test for a cold-storage effect -----
  console.log("\n=== B. create({ fromSnapshot }), x3 — same snapshot each time ===\n")
  const forkTimes: number[] = []
  for (let i = 1; i <= 3; i++) {
    try {
      const tF = performance.now()
      const forked = await solari.sandboxes.create({
        template: "base",
        fromSnapshot: snapshotId,
        timeoutMs: 10 * 60_000,
        metadata: { airlock: `warmstart2-fork-${i}` },
      })
      await forked.connect()
      const forkMs = performance.now() - tF
      forkTimes.push(forkMs)
      note(`create({ fromSnapshot }) #${i}`, forkMs, true, await verifyUsable(forked))
      await forked.kill().catch(() => {})
    } catch (err) {
      note(`create({ fromSnapshot }) #${i}`, NaN, false, err instanceof Error ? err.message : String(err))
    }
  }

  // ---- Verdict ----------------------------------------------------------
  console.log("\n\n=== verdict ===\n")
  const mean = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : NaN)
  const forkMean = mean(forkTimes)
  const resumeMean = mean(pauseResume)

  console.log(`cold create + provision : ${(coldTotalMs / 1000).toFixed(2)}s`)
  console.log(`  of which apt+npm+jail : ${(provisionMs / 1000).toFixed(2)}s  (the part a snapshot saves)`)
  console.log(`snapshot() cost         : ${(snapshotMs / 1000).toFixed(2)}s  (one-off, per server version)`)
  console.log(
    `resume() mean           : ${Number.isFinite(resumeMean) ? (resumeMean / 1000).toFixed(2) + "s" : "unavailable"}`,
  )
  console.log(
    `fromSnapshot mean       : ${Number.isFinite(forkMean) ? (forkMean / 1000).toFixed(2) + "s" : "unavailable"}` +
      (forkTimes.length > 1 ? `  (each: ${forkTimes.map((t) => (t / 1000).toFixed(1) + "s").join(", ")})` : ""),
  )
  console.log()
  if (Number.isFinite(forkMean)) {
    console.log(
      forkMean < coldTotalMs
        ? `fromSnapshot is ${(coldTotalMs / forkMean).toFixed(1)}x faster than cold — SPEC §4 holds`
        : `fromSnapshot is ${(forkMean / coldTotalMs).toFixed(1)}x SLOWER than cold — SPEC §4 and §5 need revising`,
    )
  }
  if (Number.isFinite(resumeMean)) {
    console.log(
      resumeMean < coldTotalMs
        ? `resume() is ${(coldTotalMs / resumeMean).toFixed(1)}x faster than cold`
        : `resume() is ${(resumeMean / coldTotalMs).toFixed(1)}x slower than cold`,
    )
  }

  mkdirSync("findings", { recursive: true })
  const path = `findings/warmstart2-${Date.now()}.json`
  writeFileSync(
    path,
    JSON.stringify(
      { at: new Date().toISOString(), snapshotId, coldTotalMs, provisionMs, snapshotMs, forkTimes, pauseResume, samples },
      null,
      2,
    ),
  )
  console.log(`\nfindings written to ${path}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
