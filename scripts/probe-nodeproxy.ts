/**
 * Does a --require shim route Node's global fetch through an HTTP proxy?
 *
 * Node's built-in fetch (undici) ignores HTTP_PROXY, so a jailed node server
 * using fetch reaches nothing. Proposed mitigation: a shim loaded via
 * NODE_OPTIONS=--require that calls undici's setGlobalDispatcher(new
 * ProxyAgent(...)). The open question is whether the npm `undici` package's
 * dispatcher affects the fetch-internal undici at all.
 *
 * This answers it directly from the proxy's log, without the netns jail (which
 * is not needed to settle the question and was flaking on the platform): if a
 * node fetch with the shim shows up in tinyproxy's log, the shim works.
 *
 * Usage: npm run probe:nodeproxy
 */
import { SolariClient } from "@solarisdk/sdk"
import type { Sandbox } from "@solarisdk/core"
import { requireApiKey } from "../src/env.js"

const apiKey = requireApiKey()
const PORT = 8888
const HOST = "httpbin.org"

async function main() {
  const solari = new SolariClient({ apiKey })
  const sandbox: Sandbox = await solari.sandboxes.create({ template: "base", timeoutMs: 15 * 60_000, metadata: { airlock: "probe-nodeproxy" } })
  const sh = async (script: string, env: Record<string, string> = {}, timeoutMs = 600_000) => {
    const out = await sandbox.commands.run("sh", { args: ["-c", script], env, timeoutMs })
    return (out.stdout + out.stderr).trim()
  }

  try {
    await sandbox.connect()
    console.log("provisioning (tinyproxy + undici)…")
    await sh(
      [
        "set -e",
        "export DEBIAN_FRONTEND=noninteractive",
        "apt-get update -qq >/dev/null 2>&1",
        "apt-get install -y -qq tinyproxy >/dev/null 2>&1",
        "mkdir -p /var/log/tinyproxy",
        "chown tinyproxy:tinyproxy /var/log/tinyproxy",
        "npm install -g undici@5 --silent --no-fund --no-audit >/dev/null 2>&1",
        "echo done",
      ].join("\n"),
    )
    const nodePath = (await sh("npm root -g")).trim()

    // tinyproxy with an allowlist of just httpbin.org, logging every decision.
    await sandbox.files.write("/etc/tinyproxy/allow", `^${HOST.replace(/\./g, "\\.")}$\n`)
    await sandbox.files.write(
      "/etc/tinyproxy/p.conf",
      [
        "User tinyproxy",
        "Group tinyproxy",
        `Port ${PORT}`,
        "Listen 127.0.0.1",
        'LogFile "/var/log/tinyproxy/p.log"',
        'PidFile "/run/tinyproxy.pid"',
        "Allow 127.0.0.1",
        "LogLevel Connect",
        'Filter "/etc/tinyproxy/allow"',
        "FilterDefaultDeny Yes",
        "FilterType ere",
        "ConnectPort 443",
        "",
      ].join("\n"),
    )
    await sh("tinyproxy -c /etc/tinyproxy/p.conf && sleep 1 && echo started")

    await sandbox.files.write(
      "/opt/shim-proxyagent.cjs",
      `try{const{setGlobalDispatcher,ProxyAgent}=require('undici');const p=process.env.HTTPS_PROXY||process.env.https_proxy;if(p){setGlobalDispatcher(new ProxyAgent(p));process.stderr.write('shim: ProxyAgent set\\n')}}catch(e){process.stderr.write('shim error: '+e.message+'\\n')}`,
    )
    await sandbox.files.write(
      "/opt/shim-envagent.cjs",
      `try{const u=require('undici');if(u.EnvHttpProxyAgent){u.setGlobalDispatcher(new u.EnvHttpProxyAgent());process.stderr.write('shim: EnvHttpProxyAgent set\\n')}else process.stderr.write('shim: none\\n')}catch(e){process.stderr.write('shim error: '+e.message+'\\n')}`,
    )

    const fetchCode = `fetch('https://${HOST}/headers').then(r=>r.text()).then(t=>console.log('OK len='+t.length)).catch(e=>console.log('FAIL '+(e.cause&&e.cause.code||e.message)))`
    const proxyEnv = { HTTPS_PROXY: `http://127.0.0.1:${PORT}`, https_proxy: `http://127.0.0.1:${PORT}` }

    const runNode = (label: string, env: Record<string, string>) =>
      sh(`node -e ${JSON.stringify(fetchCode)}`, env, 60_000).then((o) => `${label}: ${o.replace(/\n/g, " | ")}`)

    console.log("\n--- results (watch the proxy log to see which requests used it) ---")
    console.log(await runNode("baseline: proxy env, NO shim", proxyEnv))
    console.log(await runNode("ProxyAgent shim + proxy env", { ...proxyEnv, NODE_PATH: nodePath, NODE_OPTIONS: "--require /opt/shim-proxyagent.cjs" }))
    console.log(await runNode("EnvHttpProxyAgent shim + proxy env", { ...proxyEnv, NODE_PATH: nodePath, NODE_OPTIONS: "--require /opt/shim-envagent.cjs" }))
    console.log(await sh(`curl -s -o /dev/null -w 'curl: code=%{http_code}' https://${HOST}/headers`, proxyEnv, 60_000))

    console.log("\n--- proxy log (a line here means that request went THROUGH the proxy) ---")
    console.log(await sh("cat /var/log/tinyproxy/p.log 2>/dev/null | grep -E 'CONNECT|refused' | tail -20"))
  } finally {
    await sandbox.kill().catch(() => {})
    console.log("\nsandbox killed")
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
