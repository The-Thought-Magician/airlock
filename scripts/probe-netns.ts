/**
 * Candidate replacement mechanism for SPEC.md §3.2.
 *
 * probe-netfilter.ts ruled out the spec's design: `xt_owner` is not compiled
 * into this kernel (no /lib/modules, no modprobe), so uid-keyed DROP rules are
 * impossible. `veth` is also absent, so the usual netns+veth pairing is out.
 *
 * But `ip netns add` works, and a namespace with no interface at all is a total
 * network blackout — enforced by the absence of a route, not by a match rule.
 * Unix domain sockets are filesystem objects, so they cross a netns boundary
 * freely. That gives a bridge the kernel cannot be talked out of:
 *
 *     [ netns "airlock", no interfaces ]        [ root netns ]
 *       mcp server                                tinyproxy :8888
 *         └─ HTTP_PROXY=127.0.0.1:8888             ▲  (domain allowlist)
 *              └─ socat TCP-LISTEN:8888 ───────────┘
 *                   └── UNIX-CONNECT /run/airlock/proxy.sock
 *                         (shared filesystem, crosses the netns)
 *
 * The server sees an ordinary HTTP proxy on loopback. It has no interface to
 * anywhere else, so ignoring HTTP_PROXY buys it nothing — there is no route to
 * ignore it *to*. Escaping requires CAP_SYS_ADMIN, which an unprivileged uid
 * with no-new-privs does not have.
 *
 * This script tests whether that holds.
 *
 * Usage: npm run probe:netns
 */
import { SolariClient } from "@solarisdk/sdk"
import { mkdirSync, writeFileSync } from "node:fs"

const apiKey = process.env.SOLARI_API_KEY
if (!apiKey) {
  console.error("SOLARI_API_KEY is not set. Run: set -a && . ./.env && set +a")
  process.exit(1)
}

const NS = "airlock"
const SOCK = "/run/airlock/proxy.sock"
const PROXY_PORT = 8888
const ALLOWED = "api.github.com"
const BLOCKED = "example.com"

type Check = { name: string; expect: string; got: string; pass: boolean }
const checks: Check[] = []
const sections: Record<string, string> = {}

function record(name: string, expect: string, got: string, pass: boolean) {
  checks.push({ name, expect, got, pass })
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}`)
  console.log(`      expect: ${expect}`)
  console.log(`      got   : ${got.replace(/\n/g, " | ").slice(0, 300)}`)
  console.log()
}

async function main() {
  const solari = new SolariClient({ apiKey })
  const sandbox = await solari.sandboxes.create({
    template: "base",
    timeoutMs: 15 * 60_000,
    metadata: { airlock: "probe-netns" },
  })
  console.log(`sandbox: ${sandbox.sandboxId.slice(0, 24)}…\n`)

  const sh = async (script: string, timeoutMs = 120_000) => {
    try {
      const out = await sandbox.commands.run("sh", { args: ["-c", script], timeoutMs })
      return (out.stdout + out.stderr).trim()
    } catch (err) {
      return `STEP ERROR: ${err instanceof Error ? err.message : String(err)}`
    }
  }
  const step = async (label: string, script: string, timeoutMs = 120_000) => {
    const text = await sh(script, timeoutMs)
    sections[label] = text
    console.log(`── ${label}`)
    console.log(text.split("\n").map((l) => "   " + l).join("\n") || "   (no output)")
    console.log()
    return text
  }

  try {
    await sandbox.connect()

    await step(
      "install",
      "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1; " +
        "apt-get install -y -qq socat tinyproxy iproute2 util-linux >/dev/null 2>&1; " +
        "for b in socat tinyproxy ip setpriv unshare; do printf '%-10s %s\\n' \"$b\" \"$(command -v $b || echo MISSING)\"; done; " +
        "id -u mcp >/dev/null 2>&1 || useradd -m -u 4000 -s /bin/sh mcp; id mcp",
      300_000,
    )

    // ---- 1. does a bare netns actually black out the network? -------------
    const blackout = await sh(
      `unshare -n sh -c "timeout 8 curl -s -o /dev/null -w 'code=%{http_code}' https://${ALLOWED} 2>&1; echo \\" exit=\\$?\\""`,
    )
    record(
      "bare netns is a total network blackout",
      "curl fails (no interface, no route)",
      blackout,
      !blackout.includes("code=200"),
    )

    // ---- 2. build the proxy in the root netns -----------------------------
    // Config files go in via files.write, not printf/heredoc. The previous two
    // probes both failed on shell quoting: a heredoc terminator left mid-line,
    // and a regex that arrived with its backslashes doubled so the allowlist
    // matched nothing and FilterDefaultDeny refused every host.
    await sh("mkdir -p /var/log/tinyproxy /run/airlock && chown tinyproxy:tinyproxy /var/log/tinyproxy")

    // Anchored ERE, one domain per line. This is what airlock.toml's `egress`
    // list compiles down to.
    await sandbox.files.write("/etc/tinyproxy/allowlist", `^${ALLOWED.replace(/\./g, "\\.")}$\n`)
    await sandbox.files.write(
      "/etc/tinyproxy/airlock.conf",
      [
        "User tinyproxy",
        "Group tinyproxy",
        `Port ${PROXY_PORT}`,
        "Listen 127.0.0.1",
        "Timeout 600",
        "LogLevel Connect",
        'LogFile "/var/log/tinyproxy/tinyproxy.log"',
        'PidFile "/run/tinyproxy.pid"',
        "MaxClients 50",
        "Allow 127.0.0.1",
        'Filter "/etc/tinyproxy/allowlist"',
        "FilterDefaultDeny Yes",
        "FilterType ere",
        "ConnectPort 443",
        "",
      ].join("\n"),
    )

    await step(
      "proxy setup (root netns)",
      [
        "echo '# allowlist contents:'",
        "cat /etc/tinyproxy/allowlist",
        "tinyproxy -c /etc/tinyproxy/airlock.conf 2>&1",
        'echo "tinyproxy_exit=$?"',
        "sleep 2",
        `ss -lntp 2>/dev/null | grep ${PROXY_PORT} || echo 'NOT LISTENING'`,
      ].join("\n"),
    )

    const proxyDirect = await sh(
      `timeout 20 curl -s -o /dev/null -w 'code=%{http_code}' -x http://127.0.0.1:${PROXY_PORT} https://${ALLOWED}; echo; ` +
        `timeout 20 curl -s -o /dev/null -w 'blocked=%{http_code}' -x http://127.0.0.1:${PROXY_PORT} https://${BLOCKED}`,
    )
    record(
      "proxy allows allowlisted host and refuses others",
      `code=200 for ${ALLOWED}, non-200 for ${BLOCKED}`,
      proxyDirect,
      proxyDirect.includes("code=200") && !proxyDirect.includes("blocked=200"),
    )

    // ---- 3. bridge the netns to the proxy over a unix socket --------------
    // Joined with newlines, not "; " — a "; " after a backgrounded `&` is a
    // shell syntax error, which is what killed this step last run.
    await step(
      "unix-socket bridge",
      [
        `ip netns add ${NS} 2>&1 || echo '(netns exists)'`,
        `ip netns exec ${NS} ip link set lo up 2>&1`,
        // root side: unix socket -> tinyproxy
        `nohup socat UNIX-LISTEN:${SOCK},fork,mode=0666,unlink-early TCP:127.0.0.1:${PROXY_PORT} >/dev/null 2>&1 &`,
        "sleep 1",
        // netns side: loopback TCP -> unix socket (crosses the namespace)
        `nohup ip netns exec ${NS} socat TCP-LISTEN:${PROXY_PORT},fork,bind=127.0.0.1,reuseaddr UNIX-CONNECT:${SOCK} >/dev/null 2>&1 &`,
        "sleep 2",
        `ls -la ${SOCK} 2>&1`,
        "echo '# listener inside the netns:'",
        `ip netns exec ${NS} ss -lnt 2>&1 | head -5`,
      ].join("\n"),
    )

    const proxyEnv = `http_proxy=http://127.0.0.1:${PROXY_PORT} https_proxy=http://127.0.0.1:${PROXY_PORT}`

    // ---- 4. the real test: server inside the netns, as mcp ---------------
    const jailedAllowed = await sh(
      `ip netns exec ${NS} setpriv --reuid=4000 --regid=4000 --clear-groups --no-new-privs ` +
        `env ${proxyEnv} timeout 25 curl -s -o /dev/null -w 'code=%{http_code}' https://${ALLOWED} 2>&1; echo " exit=$?"`,
    )
    record(
      "jailed mcp reaches the ALLOWLISTED host through the bridge",
      "code=200",
      jailedAllowed,
      jailedAllowed.includes("code=200"),
    )

    const jailedBlocked = await sh(
      `ip netns exec ${NS} setpriv --reuid=4000 --regid=4000 --clear-groups --no-new-privs ` +
        `env ${proxyEnv} timeout 25 curl -s -o /dev/null -w 'code=%{http_code}' https://${BLOCKED} 2>&1; echo " exit=$?"`,
    )
    record(
      "jailed mcp is REFUSED for a non-allowlisted host",
      "non-200 (proxy denies)",
      jailedBlocked,
      !jailedBlocked.includes("code=200"),
    )

    // ---- 5. the bypass attempts ------------------------------------------
    // This is the point of the whole design: ignoring HTTP_PROXY must not help,
    // because there is no interface to reach anything directly.
    const rawSocket = await sh(
      `ip netns exec ${NS} setpriv --reuid=4000 --regid=4000 --clear-groups --no-new-privs ` +
        `python3 -c "` +
        `import socket${"\n"}` +
        `for host,port in [('140.82.121.6',443),('1.1.1.1',443),('8.8.8.8',53)]:${"\n"}` +
        `    try:${"\n"}` +
        `        socket.create_connection((host,port),timeout=5); print('CONNECTED-BYPASS',host)${"\n"}` +
        `    except Exception as e: print('blocked',host,type(e).__name__)` +
        `" 2>&1`,
      90_000,
    )
    record(
      "raw socket to a hardcoded IP is blocked (ignoring HTTP_PROXY does not help)",
      "every destination blocked — no route exists",
      rawSocket,
      !rawSocket.includes("CONNECTED-BYPASS"),
    )

    const dnsTest = await sh(
      `ip netns exec ${NS} setpriv --reuid=4000 --regid=4000 --clear-groups --no-new-privs ` +
        `timeout 10 python3 -c "import socket;print('RESOLVED',socket.gethostbyname('example.com'))" 2>&1 | tail -1`,
    )
    record(
      "DNS from the jail is blocked (kills DNS-tunnel exfil)",
      "resolution fails",
      dnsTest,
      !dnsTest.includes("RESOLVED"),
    )

    const escape = await sh(
      `ip netns exec ${NS} setpriv --reuid=4000 --regid=4000 --clear-groups --no-new-privs ` +
        `sh -c "nsenter --net=/proc/1/ns/net curl -s -o /dev/null -w code=%{http_code} --max-time 8 https://${BLOCKED} 2>&1; echo \\" exit=\\$?\\"" 2>&1`,
    )
    record(
      "jailed mcp cannot setns back to the host namespace",
      "nsenter denied (needs CAP_SYS_ADMIN)",
      escape,
      !escape.includes("code=200"),
    )

    // ---- 6. the audit source ---------------------------------------------
    await step("tinyproxy log (the §3.6 audit source)", "tail -20 /var/log/tinyproxy/tinyproxy.log 2>&1")
  } finally {
    await sandbox.kill()
    console.log("sandbox killed\n")
  }

  const passed = checks.filter((c) => c.pass).length
  const verdict =
    passed === checks.length
      ? "netns blackout + unix-socket proxy bridge HOLDS — hard egress boundary without xt_owner"
      : `${checks.length - passed} check(s) failed — mechanism not yet proven`
  console.log(`${passed}/${checks.length} checks passed`)
  console.log(verdict)

  mkdirSync("findings", { recursive: true })
  const path = `findings/netns-${Date.now()}.json`
  writeFileSync(path, JSON.stringify({ at: new Date().toISOString(), verdict, checks, sections }, null, 2))
  console.log(`findings written to ${path}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
