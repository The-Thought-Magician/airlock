/**
 * Egress-control proof (SPEC.md §3.2).
 *
 * probe.ts established that we are uid 0 with a full capability bounding set
 * (cap_net_admin, cap_net_raw), but that the `base` image ships no iptables.
 * The remaining question is whether the §3.2 design actually holds end to end:
 *
 *   1. can we install iptables and have rules stick?
 *   2. does a uid-keyed DROP actually stop the `mcp` user reaching the network?
 *   3. can a server bypass it by ignoring HTTP_PROXY and opening a raw socket?
 *   4. does a filtering forward proxy let allowlisted hosts through and
 *      block everything else?
 *
 * If all four hold, §3.2 is a hard boundary and the fallback in the spec
 * ("best-effort egress filtering") is not needed.
 *
 * Usage: npm run probe:egress
 */
import { SolariClient } from "@solarisdk/sdk"
import { mkdirSync, writeFileSync } from "node:fs"

const apiKey = process.env.SOLARI_API_KEY
if (!apiKey) {
  console.error("SOLARI_API_KEY is not set. Run: set -a && . ./.env && set +a")
  process.exit(1)
}

const MCP_UID = 4000
const PROXY_PORT = 8888
const ALLOWED_HOST = "api.github.com"
const BLOCKED_HOST = "example.com"

type Check = { name: string; expect: string; got: string; pass: boolean }
const checks: Check[] = []

function record(name: string, expect: string, got: string, pass: boolean) {
  checks.push({ name, expect, got, pass })
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}`)
  console.log(`      expected: ${expect}`)
  console.log(`      got     : ${got.replace(/\n/g, " | ")}`)
  console.log()
}

async function main() {
  const solari = new SolariClient({ apiKey })
  const sandbox = await solari.sandboxes.create({
    template: "base",
    timeoutMs: 15 * 60_000,
    metadata: { airlock: "probe-egress" },
  })
  console.log(`sandbox: ${sandbox.sandboxId.slice(0, 24)}…\n`)

  /** Run a shell snippet as root, returning trimmed stdout+stderr. */
  const sh = async (script: string, opts: { user?: string; env?: Record<string, string> } = {}) => {
    const out = await sandbox.commands.run("sh", {
      args: ["-c", script],
      timeoutMs: 300_000,
      ...opts,
    })
    return { ...out, text: (out.stdout + out.stderr).trim() }
  }

  try {
    await sandbox.connect()

    // ---- Step 1: install the tooling the snapshot will bake in -----------
    console.log("installing iptables + tinyproxy (this is snapshot-build work)…")
    const install = await sh(
      "export DEBIAN_FRONTEND=noninteractive; " +
        "apt-get update -qq >/dev/null 2>&1 && " +
        "apt-get install -y -qq iptables tinyproxy >/dev/null 2>&1; " +
        "echo iptables=$(command -v iptables || echo MISSING) tinyproxy=$(command -v tinyproxy || echo MISSING)",
    )
    record(
      "iptables + tinyproxy installable at snapshot-build time",
      "both binaries present",
      install.text,
      install.text.includes("iptables=/") && install.text.includes("tinyproxy=/"),
    )

    // ---- Step 2: create the unprivileged user the server will run as -----
    const user = await sh(
      `id -u mcp >/dev/null 2>&1 || useradd -m -u ${MCP_UID} -s /bin/sh mcp; id mcp`,
    )
    record("unprivileged `mcp` user creatable", `uid=${MCP_UID}`, user.text, user.text.includes(`uid=${MCP_UID}`))

    // ---- Step 3: baseline — mcp has full egress before any rules --------
    const baseline = await sh(
      `curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://${ALLOWED_HOST}`,
      { user: "mcp" },
    )
    record(
      "baseline: mcp reaches the internet with no rules installed",
      "HTTP 200 (unrestricted by default)",
      baseline.text,
      baseline.text.trim() === "200",
    )

    // ---- Step 4: install the uid-keyed DROP -----------------------------
    // Loopback stays open so the server can reach the proxy; everything else
    // originating from uid 4000 is dropped by the kernel.
    const rules = await sh(
      [
        `iptables -A OUTPUT -o lo -m owner --uid-owner ${MCP_UID} -j ACCEPT`,
        `iptables -A OUTPUT -m owner --uid-owner ${MCP_UID} -j REJECT`,
        `echo INSTALLED`,
        `iptables -L OUTPUT -n --line-numbers`,
      ].join(" && "),
    )
    record(
      "uid-keyed OUTPUT rules install and persist",
      "rules accepted by the kernel and listed",
      rules.text,
      rules.text.includes("INSTALLED") && rules.text.includes("owner UID match"),
    )

    // ---- Step 5: the rule actually blocks ------------------------------
    const blockedCurl = await sh(
      `curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://${ALLOWED_HOST} 2>&1; echo " exit=$?"`,
      { user: "mcp" },
    )
    record(
      "mcp curl is blocked by the kernel",
      "non-200 / curl failure",
      blockedCurl.text,
      !blockedCurl.text.startsWith("200"),
    )

    // ---- Step 6: the bypass attempt — raw socket, no proxy env ---------
    // This is the whole point of the uid split: a server that ignores
    // HTTP_PROXY and opens its own socket must still get past the kernel.
    const rawSocket = await sh(
      `python3 -c "` +
        `import socket,sys${"\n"}` +
        `try:${"\n"}` +
        `    s=socket.create_connection(('93.184.216.34',80),timeout=10)${"\n"}` +
        `    print('CONNECTED - BYPASS')${"\n"}` +
        `except Exception as e:${"\n"}` +
        `    print('BLOCKED:', type(e).__name__)` +
        `"`,
      { user: "mcp" },
    )
    record(
      "raw socket bypass (ignoring HTTP_PROXY) is blocked",
      "BLOCKED — the rule is keyed to uid, not to env vars",
      rawSocket.text,
      rawSocket.text.includes("BLOCKED"),
    )

    // ---- Step 7: DNS from mcp is dead too ------------------------------
    const dns = await sh(
      `python3 -c "` +
        `import socket${"\n"}` +
        `try:${"\n"}` +
        `    print('RESOLVED', socket.gethostbyname('example.com'))${"\n"}` +
        `except Exception as e:${"\n"}` +
        `    print('BLOCKED:', type(e).__name__)` +
        `"`,
      { user: "mcp" },
    )
    record(
      "DNS from mcp is blocked (kills DNS-tunnel exfil)",
      "BLOCKED — UDP 53 is egress like anything else",
      dns.text,
      dns.text.includes("BLOCKED"),
    )

    // ---- Step 8: root still has egress (the proxy will need it) --------
    const rootNet = await sh(`curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://${ALLOWED_HOST}`)
    record(
      "root/proxy uid retains egress",
      "HTTP 200",
      rootNet.text,
      rootNet.text.trim() === "200",
    )

    // ---- Step 9: stand up the filtering proxy --------------------------
    // tinyproxy with FilterDefaultDeny: only hosts matching the filter file
    // are forwarded. This is where airlock.toml's `egress` list lands.
    const proxySetup = await sh(
      [
        `printf '%s\\n' '^${ALLOWED_HOST.replace(/\./g, "\\\\.")}$' > /etc/tinyproxy/allowlist`,
        `cat > /etc/tinyproxy/tinyproxy.conf <<'EOF'
User tinyproxy
Group tinyproxy
Port ${PROXY_PORT}
Listen 127.0.0.1
Timeout 600
LogLevel Info
LogFile "/var/log/tinyproxy.log"
PidFile "/run/tinyproxy.pid"
MaxClients 50
Allow 127.0.0.1
Filter "/etc/tinyproxy/allowlist"
FilterDefaultDeny Yes
FilterExtended On
ConnectPort 443
EOF`,
        `mkdir -p /var/log /run`,
        `tinyproxy -c /etc/tinyproxy/tinyproxy.conf`,
        `sleep 2`,
        `echo "proxy uid: $(id -u tinyproxy)"; ss -lntp 2>/dev/null | grep ${PROXY_PORT} || netstat -lntp 2>/dev/null | grep ${PROXY_PORT} || echo "(no ss/netstat)"`,
      ].join("; "),
    )
    console.log("proxy setup:", proxySetup.text.replace(/\n/g, " | "), "\n")

    // The proxy's own uid must be allowed out, or it can forward nothing.
    await sh(`iptables -I OUTPUT 1 -m owner --uid-owner $(id -u tinyproxy) -j ACCEPT`)

    // ---- Step 10: allowlisted host succeeds through the proxy ----------
    const proxyEnv = {
      http_proxy: `http://127.0.0.1:${PROXY_PORT}`,
      https_proxy: `http://127.0.0.1:${PROXY_PORT}`,
      HTTP_PROXY: `http://127.0.0.1:${PROXY_PORT}`,
      HTTPS_PROXY: `http://127.0.0.1:${PROXY_PORT}`,
    }
    const allowed = await sh(
      `curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://${ALLOWED_HOST}`,
      { user: "mcp", env: proxyEnv },
    )
    record(
      `allowlisted host (${ALLOWED_HOST}) succeeds via the proxy`,
      "HTTP 200",
      allowed.text,
      allowed.text.trim() === "200",
    )

    // ---- Step 11: non-allowlisted host is refused by the proxy ---------
    const blocked = await sh(
      `curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://${BLOCKED_HOST}`,
      { user: "mcp", env: proxyEnv },
    )
    record(
      `non-allowlisted host (${BLOCKED_HOST}) is refused`,
      "403 / connection refused, not 200",
      blocked.text,
      blocked.text.trim() !== "200",
    )

    // ---- Step 12: the proxy logged both attempts (feeds §3.6) ----------
    const log = await sh(`tail -25 /var/log/tinyproxy.log 2>/dev/null || echo "(no log)"`)
    console.log("── proxy log tail (this is the §3.6 audit source)")
    console.log(log.text.split("\n").map((l) => "   " + l).join("\n"))
    console.log()
  } finally {
    await sandbox.kill()
    console.log("sandbox killed\n")
  }

  const passed = checks.filter((c) => c.pass).length
  console.log(`${passed}/${checks.length} checks passed`)
  const verdict =
    passed === checks.length
      ? "§3.2 HOLDS as a hard boundary — uid-keyed iptables + filtering proxy both work"
      : "§3.2 partially holds — review failures before claiming a hard boundary"
  console.log(verdict)

  mkdirSync("findings", { recursive: true })
  const path = `findings/egress-${Date.now()}.json`
  writeFileSync(path, JSON.stringify({ at: new Date().toISOString(), verdict, checks }, null, 2))
  console.log(`findings written to ${path}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
