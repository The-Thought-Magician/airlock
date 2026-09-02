/**
 * Credential brokering (SPEC §3.3).
 *
 * The plain egress path (tinyproxy) only tunnels HTTPS — it CONNECTs and then
 * forwards opaque bytes, so it cannot add an Authorization header. To broker a
 * credential into an HTTPS request the proxy has to terminate TLS, inject, and
 * re-encrypt to the origin. That is a man-in-the-middle, and it only works if
 * the CA doing it is trusted inside the sandbox.
 *
 * So when a server declares `broker` rules, Airlock swaps tinyproxy for
 * mitmproxy: it enforces the same domain allowlist AND injects the configured
 * headers on allowlisted hosts, with its CA installed into the sandbox trust
 * store. The server itself holds no credential — reading its own env yields
 * nothing useful, which is the §3.3 guarantee.
 *
 * The honest cost, which belongs in the docs: this is real TLS interception
 * inside the sandbox. It is scoped to the disposable VM and to the hosts the
 * policy allowlists, but it is a stronger mechanism than the plain proxy and
 * should be understood as such.
 */
import type { Sandbox } from "@solarisdk/core"
import { domainToEre, type ServerPolicy } from "./config.js"
import { PROXY_PORT, PROXY_LOG } from "./jail.js"

export const MITM_DIR = "/opt/airlock-mitm"
export const MITM_CA = `${MITM_DIR}/mitmproxy-ca-cert.pem`
const MITM_CONFIG = `${MITM_DIR}/config.json`
const MITM_ADDON = `${MITM_DIR}/addon.py`

type Logger = (msg: string) => void

async function sh(sandbox: Sandbox, script: string, timeoutMs = 600_000) {
  const out = await sandbox.commands.run("sh", { args: ["-c", script], timeoutMs })
  return { ...out, text: (out.stdout + out.stderr).trim() }
}

/**
 * The mitmproxy addon. Reads its rules from a JSON file (so no secret is baked
 * into the script), enforces the allowlist, and injects headers per host.
 * Decisions are logged with an AIRLOCK prefix so the audit layer can parse them
 * from the same PROXY_LOG the plain proxy uses.
 */
const ADDON_SOURCE = `# Airlock brokering addon. Generated; do not edit in the guest.
import json, os, re, sys
from mitmproxy import http

_cfg = json.load(open(os.environ["AIRLOCK_BROKER_CONFIG"]))
_allow = [re.compile(p) for p in _cfg["allow"]]
_inject = _cfg["inject"]

def _log(s):
    sys.stderr.write("AIRLOCK " + s + "\\n")
    sys.stderr.flush()

def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    if not any(p.match(host) for p in _allow):
        flow.response = http.Response.make(403, b"airlock: host not on allowlist\\n")
        _log("BLOCK " + host)
        return
    injected = []
    for r in _inject:
        if host == r["host"]:
            flow.request.headers[r["header"]] = r["value"]
            injected.append(r["header"])
    if injected:
        _log("INJECT " + host + " " + ",".join(injected))
    _log("ALLOW " + host)
`

/**
 * Install and start mitmproxy as the egress proxy, listening on PROXY_PORT in
 * the root namespace (the socat bridge from jail.ts connects to it exactly as
 * it does for tinyproxy). Returns the extra environment the server needs so its
 * HTTPS client trusts the interception CA.
 */
export async function startBrokerProxy(
  sandbox: Sandbox,
  policy: ServerPolicy,
  log: Logger,
): Promise<Record<string, string>> {
  log(`brokering ${policy.broker.length} credential(s) via TLS-terminating proxy`)
  log(`  hosts: ${[...new Set(policy.broker.map((b) => b.host))].join(", ")}`)

  // Install mitmproxy if it is not already present (e.g. from a template).
  const install = await sh(
    sandbox,
    "command -v mitmdump >/dev/null && echo present || " +
      "(pip3 install --break-system-packages --quiet mitmproxy >/dev/null 2>&1 && echo installed)",
  )
  if (!/present|installed/.test(install.stdout)) {
    throw new Error(`could not install mitmproxy:\n${install.text.slice(-2000)}`)
  }

  // Config as data, addon as code. The secret only ever lands in this file
  // inside the disposable VM, never in the server's environment.
  await sandbox.files.write(
    MITM_CONFIG,
    JSON.stringify({
      allow: policy.egress.map(domainToEre),
      inject: policy.broker.map((b) => ({ host: b.host, header: b.header, value: b.value })),
    }),
  )
  await sandbox.files.write(MITM_ADDON, ADDON_SOURCE)

  // Start mitmdump; it generates its CA in confdir on first run. Its stderr
  // (our AIRLOCK log lines) goes to the same PROXY_LOG the audit layer reads.
  await sh(
    sandbox,
    [
      `mkdir -p ${MITM_DIR}`,
      "pkill -f mitmdump 2>/dev/null || true",
      `pkill -f 'socat TCP-LISTEN:${PROXY_PORT}' 2>/dev/null || true`,
      "sleep 1",
      `AIRLOCK_BROKER_CONFIG=${MITM_CONFIG} nohup mitmdump ` +
        `--set confdir=${MITM_DIR} -s ${MITM_ADDON} ` +
        `--listen-host 127.0.0.1 --listen-port ${PROXY_PORT} ` +
        `--set block_global=false -q >> ${PROXY_LOG} 2>&1 &`,
    ].join("\n"),
  )

  // Wait for the CA to be generated, then trust it everywhere the server might
  // look: the system store, and the per-runtime env vars node/python/curl honour.
  const caReady = await sh(
    sandbox,
    [
      "for i in $(seq 1 30); do",
      `  [ -f ${MITM_CA} ] && break`,
      "  sleep 0.5",
      "done",
      `[ -f ${MITM_CA} ] || { echo NO_CA; exit 1; }`,
      // System trust store.
      `cp ${MITM_CA} /usr/local/share/ca-certificates/airlock-mitm.crt`,
      "update-ca-certificates >/dev/null 2>&1 || true",
      // Confirm the listener is actually up.
      `ss -lnt 2>/dev/null | grep -q ':${PROXY_PORT}' && echo LISTENING || echo NOT_LISTENING`,
    ].join("\n"),
  )
  if (caReady.stdout.includes("NO_CA")) {
    const diag = await sh(sandbox, `tail -20 ${PROXY_LOG} 2>&1`)
    throw new Error(`mitmproxy did not generate a CA:\n${diag.text}`)
  }
  if (!caReady.stdout.includes("LISTENING")) {
    const diag = await sh(sandbox, `tail -20 ${PROXY_LOG} 2>&1`)
    throw new Error(`mitmproxy is not listening on ${PROXY_PORT}:\n${diag.text}`)
  }

  log("interception CA installed into the sandbox trust store")

  // The env that makes each runtime trust the interception CA. Bundling all of
  // them is cheap and covers node, python-requests, and curl without knowing
  // which the server uses.
  return {
    NODE_EXTRA_CA_CERTS: MITM_CA,
    REQUESTS_CA_BUNDLE: MITM_CA,
    SSL_CERT_FILE: MITM_CA,
    CURL_CA_BUNDLE: MITM_CA,
  }
}
