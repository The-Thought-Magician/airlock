/**
 * Warm-start alternatives (SPEC §7 Q7, §4).
 *
 * Before building the snapshot flow, measure every way of getting a ready
 * sandbox and pick on evidence. Four candidates:
 *
 *   A. cold create + full provision            (the baseline we pay today)
 *   B. create({ fromSnapshot })                fork a new machine from a save point
 *   C. revert(snapshotId)                      rewind the same machine
 *   D. pause() / resume()                      park without shutdown
 *
 * (A fifth, a custom template with the dependencies baked in, is measured
 * separately in probe-template.ts because a template build is slow and its
 * failure should not cost these numbers.)
 *
 * Speed is only half the question. The other half is **what state survives**,
 * because the jail is partly disk state (apt packages, the installed server)
 * and partly live kernel and process state (the network namespace, tinyproxy,
 * the socat bridge). A path that restores the disk but not the processes still
 * needs the jail rebuilt on resume, which changes the design.
 *
 * Usage: npm run probe:warmstart
 */
import { SolariClient } from "@solarisdk/sdk"
import type { Sandbox } from "@solarisdk/core"
import { mkdirSync, writeFileSync } from "node:fs"
import { requireApiKey } from "../src/env.js"
import { NETNS, PROXY_PORT, PROXY_SOCK } from "../src/jail.js"

const apiKey = requireApiKey()
const PACKAGE = "@modelcontextprotocol/server-everything"

/** What we care about surviving a warm start. */
interface StateReport {
  aptDeps: boolean
  serverInstalled: boolean
  netnsExists: boolean
  tinyproxyRunning: boolean
  bridgeRunning: boolean
  socketPresent: boolean
  hasPgrep: boolean
  proxyListening: boolean
  raw: string
}

interface Measurement {
  path: string
  description: string
  ms: number
  state?: StateReport
  note?: string
}

const results: Measurement[] = []

async function sh(sandbox: Sandbox, script: string, timeoutMs = 300_000) {
  const out = await sandbox.commands.run("sh", { args: ["-c", script], timeoutMs })
  return { ...out, text: (out.stdout + out.stderr).trim() }
}

/**
 * Inspect the jail's state in one round trip. Each line is a yes/no so the
 * result is unambiguous rather than something to eyeball.
 *
 * Deliberately avoids pgrep/pkill: the base image is minimal and may not ship
 * procps, and an absent binary reads as "process dead" — a false negative that
 * would have made snapshots look far worse than they are. Liveness is checked
 * by what the process actually holds: its pidfile, and its listening socket.
 */
async function inspect(sandbox: Sandbox): Promise<StateReport> {
  const out = await sh(
    sandbox,
    [
      `echo apt=$(command -v tinyproxy >/dev/null && command -v socat >/dev/null && echo yes || echo no)`,
      `echo server=$([ -d "$(npm root -g)/${PACKAGE}" ] && echo yes || echo no)`,
      `echo netns=$(ip netns list 2>/dev/null | grep -q ${NETNS} && echo yes || echo no)`,
      // Liveness via the pidfile, using only shell builtins.
      `echo tinyproxy=$([ -f /run/tinyproxy.pid ] && kill -0 "$(cat /run/tinyproxy.pid)" 2>/dev/null && echo yes || echo no)`,
      // The bridge is only real if something is listening inside the namespace.
      `echo bridge=$(ip netns exec ${NETNS} ss -lnt 2>/dev/null | grep -q ':${PROXY_PORT}' && echo yes || echo no)`,
      `echo sock=$([ -S ${PROXY_SOCK} ] && echo yes || echo no)`,
      // Confirm the diagnosis about procps rather than leaving it a guess.
      `echo has_pgrep=$(command -v pgrep >/dev/null && echo yes || echo no)`,
      `echo proxy_listening=$(ss -lnt 2>/dev/null | grep -q '127.0.0.1:${PROXY_PORT}' && echo yes || echo no)`,
    ].join("\n"),
    60_000,
  )
  const get = (k: string) => new RegExp(`${k}=(\\w+)`).exec(out.stdout)?.[1] === "yes"
  return {
    aptDeps: get("apt"),
    serverInstalled: get("server"),
    netnsExists: get("netns"),
    tinyproxyRunning: get("tinyproxy"),
    bridgeRunning: get("bridge"),
    socketPresent: get("sock"),
    hasPgrep: get("has_pgrep"),
    proxyListening: get("proxy_listening"),
    raw: out.stdout.trim().replace(/\n/g, " "),
  }
}

function show(m: Measurement) {
  console.log(`\n── ${m.path}  ${(m.ms / 1000).toFixed(2)}s`)
  console.log(`   ${m.description}`)
  if (m.state) {
    const s = m.state
    const mark = (b: boolean) => (b ? "yes" : "NO ")
    console.log(`   disk : apt=${mark(s.aptDeps)}  server=${mark(s.serverInstalled)}`)
    console.log(
      `   live : netns=${mark(s.netnsExists)}  tinyproxy=${mark(s.tinyproxyRunning)}  ` +
        `bridge=${mark(s.bridgeRunning)}  socket=${mark(s.socketPresent)}  ` +
        `listening=${mark(s.proxyListening)}`,
    )
    console.log(`   env  : pgrep available=${mark(s.hasPgrep)}`)
  }
  if (m.note) console.log(`   note : ${m.note}`)
}

async function main() {
  const solari = new SolariClient({ apiKey })

  // ---- A. Cold create + full provision ---------------------------------
  const tCold = performance.now()
  let sandbox = await solari.sandboxes.create({
    template: "base",
    timeoutMs: 20 * 60_000,
    metadata: { airlock: "probe-warmstart" },
  })
  await sandbox.connect()
  const coldCreateMs = performance.now() - tCold
  console.log(`cold create + connect: ${(coldCreateMs / 1000).toFixed(2)}s`)

  const snapshotId = await (async () => {
    const tProvision = performance.now()

    console.log("provisioning (apt + npm install + jail)…")
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
        "chown -R 4000:4000 /home/mcp/work",
      ].join("\n"),
    )
    const aptMs = performance.now() - tProvision

    const tNpm = performance.now()
    await sh(sandbox, `npm install -g ${PACKAGE} --silent --no-fund --no-audit`, 600_000)
    const npmMs = performance.now() - tNpm

    // Stand up the jail so we can see whether live state survives.
    const tJail = performance.now()
    await sh(
      sandbox,
      [
        `printf '^api\\\\.github\\\\.com$\\n' > /etc/tinyproxy/airlock-allowlist`,
        `printf 'User tinyproxy\\nGroup tinyproxy\\nPort ${PROXY_PORT}\\nListen 127.0.0.1\\nLogLevel Connect\\nLogFile "/var/log/tinyproxy/tinyproxy.log"\\nPidFile "/run/tinyproxy.pid"\\nMaxClients 50\\nAllow 127.0.0.1\\nFilter "/etc/tinyproxy/airlock-allowlist"\\nFilterDefaultDeny Yes\\nFilterType ere\\nConnectPort 443\\n' > /etc/tinyproxy/airlock.conf`,
        "tinyproxy -c /etc/tinyproxy/airlock.conf",
        `ip netns add ${NETNS} 2>/dev/null || true`,
        `ip netns exec ${NETNS} ip link set lo up`,
        `nohup socat UNIX-LISTEN:${PROXY_SOCK},fork,mode=0666,unlink-early TCP:127.0.0.1:${PROXY_PORT} >/dev/null 2>&1 &`,
        "sleep 1",
        `nohup ip netns exec ${NETNS} socat TCP-LISTEN:${PROXY_PORT},fork,bind=127.0.0.1,reuseaddr UNIX-CONNECT:${PROXY_SOCK} >/dev/null 2>&1 &`,
        "sleep 2",
      ].join("\n"),
    )
    const jailMs = performance.now() - tJail
    const totalProvisionMs = performance.now() - tProvision

    results.push({
      path: "A. cold create + full provision",
      description: "what every launch costs with no snapshot at all",
      ms: coldCreateMs + totalProvisionMs,
      state: await inspect(sandbox),
      note:
        `create ${(coldCreateMs / 1000).toFixed(2)}s + apt ${(aptMs / 1000).toFixed(2)}s + ` +
        `npm ${(npmMs / 1000).toFixed(2)}s + jail ${(jailMs / 1000).toFixed(2)}s`,
    })
    show(results[results.length - 1])

    const tSnap = performance.now()
    const id = await sandbox.snapshot("airlock-warmstart-probe")
    console.log(`\nsnapshot() took ${((performance.now() - tSnap) / 1000).toFixed(2)}s → ${id.slice(0, 24)}…`)
    return id
  })()

  try {
    // ---- C. revert ------------------------------------------------------
    // Tested BEFORE pause/resume: the first run did it the other way round
    // and revert came back 409 "Not revertable", which suggests resuming into
    // a fresh slot invalidates it. Order matters, so establish revert on a
    // machine that has only been snapshotted.
    try {
      const tRevert = performance.now()
      await sandbox.revert(snapshotId)
      if (!sandbox.connected) await sandbox.connect()
      const revertMs = performance.now() - tRevert

      results.push({
        path: "C. revert(snapshotId)",
        description: "rewind this machine to the save point",
        ms: revertMs,
        state: await inspect(sandbox),
      })
      show(results[results.length - 1])
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      results.push({
        path: "C. revert(snapshotId)",
        description: "rewind this machine to the save point",
        ms: NaN,
        note: `FAILED: ${msg}`,
      })
      console.log(`\n── C. revert(snapshotId)  FAILED\n   ${msg}`)
    }

    // ---- D. pause / resume ---------------------------------------------
    try {
      const tPause = performance.now()
      await sandbox.pause()
      const pauseMs = performance.now() - tPause

      const tResume = performance.now()
      await sandbox.resume()
      if (!sandbox.connected) await sandbox.connect()
      const resumeMs = performance.now() - tResume

      results.push({
        path: "D. pause() + resume()",
        description: "park the machine and bring it back",
        ms: resumeMs,
        state: await inspect(sandbox),
        note: `pause ${(pauseMs / 1000).toFixed(2)}s, resume ${(resumeMs / 1000).toFixed(2)}s`,
      })
      show(results[results.length - 1])

      // Does revert still work once the machine has been resumed? This is
      // what failed on the first run; confirm it is the ordering and not a
      // one-off.
      try {
        await sandbox.revert(snapshotId)
        console.log("   note : revert still works after a resume")
      } catch (err) {
        console.log(`   note : revert after resume is rejected — ${err instanceof Error ? err.message : err}`)
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      results.push({
        path: "D. pause() + resume()",
        description: "park the machine and bring it back",
        ms: NaN,
        note: `FAILED: ${msg}`,
      })
      console.log(`\n── D. pause() + resume()  FAILED\n   ${msg}`)
    }
  } finally {
    await sandbox.kill()
    console.log("\noriginal sandbox killed")
  }

  // ---- B. create from snapshot ------------------------------------------
  {
    const tFork = performance.now()
    const forked = await solari.sandboxes.create({
      template: "base",
      fromSnapshot: snapshotId,
      timeoutMs: 10 * 60_000,
      metadata: { airlock: "probe-warmstart-fork" },
    })
    await forked.connect()
    const forkMs = performance.now() - tFork

    try {
      results.push({
        path: "B. create({ fromSnapshot })",
        description: "boot a fresh independent machine from the save point",
        ms: forkMs,
        state: await inspect(forked),
      })
      show(results[results.length - 1])
    } finally {
      await forked.kill()
      console.log("\nforked sandbox killed")
    }
  }

  // ---- Verdict ----------------------------------------------------------
  console.log("\n\n=== comparison ===\n")
  const baseline = results.find((r) => r.path.startsWith("A"))!
  console.log("path                              time      speedup   disk state   live state")
  for (const r of results) {
    const speedup = r.path.startsWith("A") ? "—" : `${(baseline.ms / r.ms).toFixed(1)}x`
    const disk = r.state ? (r.state.aptDeps && r.state.serverInstalled ? "intact" : "LOST") : "?"
    const live = r.state
      ? r.state.netnsExists && r.state.tinyproxyRunning && r.state.bridgeRunning
        ? "intact"
        : "rebuild needed"
      : "?"
    console.log(
      `${r.path.padEnd(33)} ${(r.ms / 1000).toFixed(2).padStart(6)}s   ${speedup.padStart(7)}   ` +
        `${disk.padEnd(12)} ${live}`,
    )
  }

  mkdirSync("findings", { recursive: true })
  const path = `findings/warmstart-${Date.now()}.json`
  writeFileSync(path, JSON.stringify({ at: new Date().toISOString(), snapshotId, results }, null, 2))
  console.log(`\nfindings written to ${path}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
