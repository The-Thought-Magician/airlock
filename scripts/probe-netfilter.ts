/**
 * Netfilter / isolation mechanism diagnostic.
 *
 * probe-egress.ts showed the uid-keyed iptables path from SPEC.md §3.2 fails on
 * this kernel: `owner` match reports "revision 0 not supported, missing kernel
 * module" and the nf_tables backend cannot fetch a ruleset generation id.
 *
 * This script figures out what DOES work, across three candidate mechanisms:
 *
 *   A. iptables-legacy backend (xt_owner may exist there)
 *   B. plain iptables rules with no owner match (destination-based)
 *   C. network namespace + veth — the jailed process gets no route except to
 *      the proxy, which is stronger than uid matching and needs no owner module
 *
 * Whichever wins becomes the real §3.2 mechanism.
 *
 * Usage: npm run probe:netfilter
 */
import { SolariClient } from "@solarisdk/sdk"
import { mkdirSync, writeFileSync } from "node:fs"

const apiKey = process.env.SOLARI_API_KEY
if (!apiKey) {
  console.error("SOLARI_API_KEY is not set. Run: set -a && . ./.env && set +a")
  process.exit(1)
}

const sections: Record<string, string> = {}

async function main() {
  const solari = new SolariClient({ apiKey })
  const sandbox = await solari.sandboxes.create({
    template: "base",
    timeoutMs: 15 * 60_000,
    metadata: { airlock: "probe-netfilter" },
  })
  console.log(`sandbox: ${sandbox.sandboxId.slice(0, 24)}…\n`)

  /**
   * Run a shell snippet. Every step is isolated and time-boxed so one hang
   * cannot stall the whole diagnostic — a stalled step is itself a finding.
   */
  const step = async (label: string, script: string, timeoutMs = 120_000) => {
    let text: string
    try {
      const out = await sandbox.commands.run("sh", { args: ["-c", script], timeoutMs })
      text = (out.stdout + out.stderr).trim()
    } catch (err) {
      text = `STEP ERROR: ${err instanceof Error ? err.message : String(err)}`
    }
    sections[label] = text
    console.log(`── ${label}`)
    console.log(text.split("\n").map((l) => "   " + l).join("\n") || "   (no output)")
    console.log()
    return text
  }

  try {
    await sandbox.connect()

    await step(
      "install tooling",
      "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1; " +
        "apt-get install -y -qq iptables iproute2 tinyproxy >/dev/null 2>&1; " +
        "for b in iptables iptables-legacy iptables-nft ip nsenter unshare tinyproxy modprobe ss; do " +
        "printf '%-16s %s\\n' \"$b\" \"$(command -v $b || echo -)\"; done",
      300_000,
    )

    // ---- Kernel module reality --------------------------------------------
    await step(
      "kernel modules",
      "echo '# lsmod:'; lsmod 2>&1 | head -15; " +
        "echo '# modprobe xt_owner:'; modprobe xt_owner 2>&1 && echo 'modprobe ok' || echo 'modprobe failed'; " +
        "echo '# /lib/modules:'; ls /lib/modules 2>&1 | head -3; " +
        "echo '# netfilter in /proc/net:'; ls /proc/net 2>/dev/null | grep -i -E 'nf_|ip_tables|netfilter' | head || echo none; " +
        "echo '# kernel config:'; " +
        "(zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_(NETFILTER_XT_MATCH_OWNER|VETH|NET_NS|IP_NF_IPTABLES|NF_TABLES)=' || echo 'no /proc/config.gz')",
    )

    // ---- A: legacy backend -------------------------------------------------
    await step(
      "A. iptables-legacy + owner match",
      "echo '# legacy list:'; iptables-legacy -L OUTPUT -n 2>&1 | head -3; " +
        "echo '# legacy owner match:'; " +
        "if iptables-legacy -A OUTPUT -m owner --uid-owner 4000 -j REJECT 2>&1; then " +
        "echo LEGACY_OWNER_OK; iptables-legacy -D OUTPUT -m owner --uid-owner 4000 -j REJECT; " +
        "else echo LEGACY_OWNER_FAILED; fi",
    )

    // ---- B: plain destination rules, no owner match ------------------------
    await step(
      "B. plain iptables rules (no owner match)",
      "echo '# nft backend:'; " +
        "if iptables -A OUTPUT -d 1.1.1.1 -j REJECT 2>&1; then echo NFT_PLAIN_OK; iptables -D OUTPUT -d 1.1.1.1 -j REJECT; else echo NFT_PLAIN_FAILED; fi; " +
        "echo '# legacy backend:'; " +
        "if iptables-legacy -A OUTPUT -d 1.1.1.1 -j REJECT 2>&1; then echo LEGACY_PLAIN_OK; " +
        "echo '# does it actually block?'; timeout 8 curl -s -o /dev/null -w 'code=%{http_code}' https://1.1.1.1 2>&1; echo \" exit=$?\"; " +
        "iptables-legacy -D OUTPUT -d 1.1.1.1 -j REJECT; else echo LEGACY_PLAIN_FAILED; fi",
    )

    // ---- C: network namespace + veth --------------------------------------
    // If this works it is the best mechanism: the jailed process has no route
    // to anything except the proxy, enforced by routing rather than by a match.
    await step(
      "C. netns + veth",
      [
        "if ip netns add airlock 2>&1; then echo NETNS_CREATED; else echo NETNS_FAILED; fi",
        "if ip link add veth-h type veth peer name veth-g 2>&1; then echo VETH_CREATED; else echo VETH_FAILED; fi",
        "ip link set veth-g netns airlock 2>&1 && echo VETH_MOVED",
        "ip addr add 10.99.0.1/30 dev veth-h 2>&1; ip link set veth-h up 2>&1",
        "ip netns exec airlock ip addr add 10.99.0.2/30 dev veth-g 2>&1",
        "ip netns exec airlock ip link set veth-g up 2>&1",
        "ip netns exec airlock ip link set lo up 2>&1",
        "echo '# guest netns routes (no default route means no egress):'",
        "ip netns exec airlock ip route show 2>&1",
        "echo '# guest -> host veth endpoint reachable? (TCP, not ICMP)'",
        "nc -z -w2 10.99.0.1 22 2>&1; echo \"nc_exit=$? (refused is fine, means routed)\"",
        "echo '# guest -> internet (MUST fail):'",
        "ip netns exec airlock timeout 6 curl -s -o /dev/null -w 'code=%{http_code}' https://api.github.com 2>&1; echo \" exit=$?\"",
        "echo '# guest -> DNS (MUST fail):'",
        "ip netns exec airlock timeout 6 python3 -c \"import socket;print('RESOLVED',socket.gethostbyname('example.com'))\" 2>&1 | tail -1",
      ].join("; "),
    )

    // ---- Why tinyproxy did not start --------------------------------------
    // Note: tinyproxy daemonizes by default; `-d` keeps it in the foreground,
    // which is what stalled the previous run when it was backgrounded with `&`.
    await step(
      "tinyproxy startup",
      [
        "id tinyproxy 2>&1 || echo 'no tinyproxy user'",
        "mkdir -p /var/log/tinyproxy /run",
        "printf '^api\\\\.github\\\\.com$\\n' > /etc/tinyproxy/allowlist",
        "cat > /tmp/tp.conf <<'CONF'\n" +
          "User tinyproxy\nGroup tinyproxy\nPort 8888\nListen 127.0.0.1\nTimeout 600\n" +
          "LogLevel Info\nLogFile \"/var/log/tinyproxy/tinyproxy.log\"\nPidFile \"/run/tinyproxy.pid\"\n" +
          "MaxClients 50\nAllow 127.0.0.1\nFilter \"/etc/tinyproxy/allowlist\"\n" +
          "FilterDefaultDeny Yes\nFilterExtended On\nConnectPort 443\nCONF",
        "chown -R tinyproxy:tinyproxy /var/log/tinyproxy 2>&1",
        "echo '# start (daemonizes, no -d):'",
        "tinyproxy -c /tmp/tp.conf 2>&1; echo \"start_exit=$?\"",
        "sleep 2",
        "echo '# listening?'; (ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null) | grep 8888 || echo 'NOT LISTENING'",
        "echo '# allowlisted host via proxy:'",
        "timeout 20 curl -s -o /dev/null -w 'code=%{http_code}' -x http://127.0.0.1:8888 https://api.github.com 2>&1",
        "echo; echo '# blocked host via proxy:'",
        "timeout 20 curl -s -o /dev/null -w 'code=%{http_code}' -x http://127.0.0.1:8888 https://example.com 2>&1",
        "echo; echo '# log:'; tail -15 /var/log/tinyproxy/tinyproxy.log 2>&1 || echo 'no log'",
      ].join("; "),
      180_000,
    )
  } finally {
    await sandbox.kill()
    console.log("sandbox killed")
  }

  mkdirSync("findings", { recursive: true })
  const path = `findings/netfilter-${Date.now()}.json`
  writeFileSync(path, JSON.stringify({ at: new Date().toISOString(), sections }, null, 2))
  console.log(`\nfindings written to ${path}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
