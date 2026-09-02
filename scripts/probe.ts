/**
 * Day-one capability probe.
 *
 * Settles the open questions in SPEC.md §7 that need a live API key, in a
 * single sandbox boot:
 *
 *   Q3 — do you get root, and can you run iptables?   (load-bearing for §3.2)
 *   Q4 — what is the per-call round-trip latency?
 *   Q5 — does the `base` template ship node and python?
 *
 * Writes findings to findings/probe-<timestamp>.json and prints a summary.
 *
 * Usage: npm run probe
 */
import { SolariClient } from "@solarisdk/sdk"
import { mkdirSync, writeFileSync } from "node:fs"
import { requireApiKey } from "../src/env.js"

const apiKey = requireApiKey()

const TEMPLATE = process.env.AIRLOCK_TEMPLATE ?? "base"

type Probe = {
  label: string
  cmd: string
  args: string[]
  /** What the result tells us. Printed alongside the output. */
  note?: string
}

/** Commands are NOT shell-interpreted; anything with pipes needs an explicit sh -c. */
const sh = (label: string, script: string, note?: string): Probe => ({
  label,
  cmd: "sh",
  args: ["-c", script],
  note,
})

const PROBES: Probe[] = [
  // ---- Q3: privilege and network control -------------------------------
  sh("id", "id", "uid 0 => we can install the egress proxy and set iptables at build time"),
  sh("whoami", "whoami"),
  sh("sudo", "command -v sudo >/dev/null && sudo -n true 2>&1 && echo PASSWORDLESS_SUDO || echo 'no passwordless sudo'"),
  sh("iptables-present", "command -v iptables || command -v iptables-legacy || command -v nft || echo ABSENT"),
  sh("iptables-list", "iptables -L -n 2>&1 | head -20 || echo FAILED"),
  sh(
    "iptables-write",
    // The real test: can we actually install a rule, not just list them.
    "iptables -N airlock_probe 2>&1 && iptables -A airlock_probe -j ACCEPT 2>&1 && " +
      "echo RULE_INSTALLED && iptables -F airlock_probe && iptables -X airlock_probe && echo CLEANED || echo RULE_FAILED",
    "the actual §3.2 gate: can Airlock install owner-uid egress rules",
  ),
  sh(
    "iptables-owner-module",
    // §3.2 keys DROP rules to the mcp uid, which needs the owner match module.
    "iptables -A OUTPUT -m owner --uid-owner 65534 -j DROP 2>&1 && echo OWNER_MATCH_OK && " +
      "iptables -D OUTPUT -m owner --uid-owner 65534 -j DROP || echo OWNER_MATCH_UNAVAILABLE",
    "uid-keyed DROP is what stops a server that ignores HTTP_PROXY",
  ),
  sh("useradd", "command -v useradd >/dev/null && echo useradd present || echo useradd ABSENT",
     "needed to create the unprivileged `mcp` user"),
  sh("capabilities", "command -v capsh >/dev/null && capsh --print 2>&1 | head -5 || echo 'capsh absent'"),
  sh("net-namespace", "command -v unshare >/dev/null && echo unshare present || echo unshare ABSENT",
     "fallback isolation path if iptables is unavailable"),

  // ---- Q5: what the base template actually ships -----------------------
  sh("os", "cat /etc/os-release | head -3"),
  sh("kernel", "uname -a"),
  sh(
    "runtimes",
    "for b in node npm npx python3 pip3 uv uvx curl wget git iptables tinyproxy squid socat; do " +
      "printf '%-10s %s\\n' \"$b\" \"$(command -v $b || echo -)\"; done",
    "decides whether the first snapshot needs a custom template",
  ),
  sh("node-version", "node --version 2>&1 || echo 'node ABSENT'"),
  sh("python-version", "python3 --version 2>&1 || echo 'python3 ABSENT'"),
  sh("apt", "command -v apt-get >/dev/null && echo 'apt-get present' || echo 'apt-get ABSENT'",
     "needed to install the egress proxy into the snapshot"),

  // ---- Egress reality check --------------------------------------------
  sh(
    "outbound-net",
    "curl -s -o /dev/null -w 'https ok: %{http_code}\\n' --max-time 10 https://api.github.com || echo 'no outbound'",
    "confirms the sandbox has unrestricted egress by default — which is what §3.2 must fix",
  ),
]

async function main() {
  const solari = new SolariClient({ apiKey })

  const bootStart = performance.now()
  const sandbox = await solari.sandboxes.create({
    template: TEMPLATE,
    timeoutMs: 5 * 60_000,
    metadata: { airlock: "probe" },
  })
  const bootMs = performance.now() - bootStart
  console.log(`sandbox up in ${bootMs.toFixed(0)}ms (template=${TEMPLATE})\n`)

  const results: Record<string, { exitCode: number; stdout: string; stderr: string; note?: string }> = {}
  let latency: { samples: number[]; p50: number; p95: number; mean: number } | undefined

  try {
    const connectStart = performance.now()
    await sandbox.connect()
    const connectMs = performance.now() - connectStart
    console.log(`control channel connected in ${connectMs.toFixed(0)}ms\n`)

    for (const p of PROBES) {
      const out = await sandbox.commands.run(p.cmd, { args: p.args })
      results[p.label] = {
        exitCode: out.exitCode,
        stdout: out.stdout.trimEnd(),
        stderr: out.stderr.trimEnd(),
        note: p.note,
      }
      const body = (out.stdout || out.stderr).trimEnd()
      console.log(`── ${p.label} (exit ${out.exitCode})`)
      if (p.note) console.log(`   ↳ ${p.note}`)
      console.log(
        body
          .split("\n")
          .map((l) => "   " + l)
          .join("\n") || "   (no output)",
      )
      console.log()
    }

    // ---- Q4: per-call round-trip latency --------------------------------
    // Trivial command, so the number is transport overhead, not workload.
    const N = 20
    const samples: number[] = []
    for (let i = 0; i < N; i++) {
      const t = performance.now()
      await sandbox.commands.run("true", { args: [] })
      samples.push(performance.now() - t)
    }
    const sorted = [...samples].sort((a, b) => a - b)
    latency = {
      samples,
      p50: sorted[Math.floor(N * 0.5)],
      p95: sorted[Math.floor(N * 0.95)],
      mean: samples.reduce((a, b) => a + b, 0) / N,
    }
    console.log(`── exec round-trip over ${N} calls`)
    console.log(`   mean ${latency.mean.toFixed(1)}ms  p50 ${latency.p50.toFixed(1)}ms  p95 ${latency.p95.toFixed(1)}ms`)
    console.log()
  } finally {
    // kill(), not close() — close() leaves the VM billing until the idle timeout.
    await sandbox.kill()
    console.log("sandbox killed")
  }

  const findings = {
    at: new Date().toISOString(),
    template: TEMPLATE,
    bootMs: Number(bootMs.toFixed(0)),
    latency,
    results,
  }
  mkdirSync("findings", { recursive: true })
  const path = `findings/probe-${Date.now()}.json`
  writeFileSync(path, JSON.stringify(findings, null, 2))
  console.log(`\nfindings written to ${path}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
