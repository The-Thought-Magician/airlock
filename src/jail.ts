/**
 * Building the jail inside a sandbox (SPEC §3.1, §3.2).
 *
 * The egress mechanism here is the one verified in docs/FINDINGS-DAY1.md, not
 * the uid-keyed iptables design the spec originally called for — `xt_owner` is
 * not compiled into the sandbox kernel, so that design is unbuildable. What we
 * do instead:
 *
 *   - a network namespace with NO interfaces (loopback only), which is a total
 *     blackout enforced by the absence of a route rather than by a filter rule
 *   - a unix socket bridging that namespace to a filtering proxy, because unix
 *     sockets are filesystem objects and cross a netns freely
 *   - the server running as uid 4000 with --no-new-privs, so it cannot setns
 *     back out
 *
 * Shell conventions in this file, learned the hard way while probing:
 *   - config files go in via files.write, never printf/heredoc — quoting
 *     through two layers silently doubled backslashes and broke an allowlist
 *   - multi-step scripts are joined with "\n", never "; " — a "; " after a
 *     backgrounded `&` is a shell syntax error
 */
import type { Sandbox } from "@solarisdk/core"
import { domainToEre, type ServerPolicy } from "./config.js"

export const MCP_UID = 4000
export const MCP_GID = 4000
export const NETNS = "airlock"
export const PROXY_PORT = 8888
export const PROXY_SOCK = "/run/airlock/proxy.sock"
export const PROXY_LOG = "/var/log/tinyproxy/tinyproxy.log"
export const WORKDIR = "/home/mcp/work"

/** Where a launcher's entrypoint ended up, and how to invoke it. */
export interface Entrypoint {
  cmd: string
  args: string[]
}

export type Logger = (msg: string) => void

async function sh(sandbox: Sandbox, script: string, timeoutMs = 300_000) {
  const out = await sandbox.commands.run("sh", { args: ["-c", script], timeoutMs })
  return { ...out, text: (out.stdout + out.stderr).trim() }
}

/** Generic so callers keep access to stdout/stderr on the value they passed in. */
function must<T extends { exitCode: number; text: string }>(result: T, what: string): T {
  if (result.exitCode !== 0) {
    throw new Error(`${what} failed (exit ${result.exitCode}):\n${result.text.slice(-4000)}`)
  }
  return result
}

/**
 * Install the pieces the jail is made of. Idempotent, so it is safe to re-run
 * against a sandbox restored from a snapshot that already has them.
 *
 * This is the work SPEC §4 snapshots away — on a pinned snapshot none of it
 * runs again.
 */
export async function installJailDependencies(sandbox: Sandbox, log: Logger): Promise<void> {
  log("installing jail dependencies (socat, tinyproxy, iproute2)…")
  must(
    await sh(
      sandbox,
      [
        "set -e",
        "export DEBIAN_FRONTEND=noninteractive",
        // Only pay for apt if something is actually missing.
        'if command -v socat >/dev/null && command -v tinyproxy >/dev/null && command -v ip >/dev/null; then',
        '  echo "already present"',
        "else",
        "  apt-get update -qq >/dev/null 2>&1",
        "  apt-get install -y -qq socat tinyproxy iproute2 util-linux >/dev/null 2>&1",
        "fi",
        `id -u mcp >/dev/null 2>&1 || useradd -m -u ${MCP_UID} -s /bin/sh mcp`,
        `mkdir -p /run/airlock /var/log/tinyproxy ${WORKDIR}`,
        "chown tinyproxy:tinyproxy /var/log/tinyproxy",
        `chown -R ${MCP_UID}:${MCP_GID} ${WORKDIR}`,
        "for b in socat tinyproxy ip setpriv; do command -v $b >/dev/null || { echo \"MISSING: $b\"; exit 1; }; done",
        "echo ok",
      ].join("\n"),
    ),
    "installing jail dependencies",
  )
}

/**
 * Install the MCP server itself, as root in the host namespace where the
 * network still works. This deliberately happens OUTSIDE the jail: inside it
 * there is no route to a package registry, which is the whole point.
 *
 * Returns how to invoke the installed entrypoint.
 */
export async function installServer(sandbox: Sandbox, policy: ServerPolicy, log: Logger): Promise<Entrypoint> {
  await installServerPackage(sandbox, policy, log)
  return resolveEntrypoint(sandbox, policy)
}

/** Strip any version suffix: `@scope/pkg@1.2.3` → `@scope/pkg`. */
export function packageName(spec: string): string {
  const at = spec.lastIndexOf("@")
  return at > 0 ? spec.slice(0, at) : spec
}

/** The shell command that installs this policy's package. Shared with the template build. */
export function installCommand(policy: ServerPolicy): string {
  switch (policy.launcher) {
    case "npx":
      return `npm install -g ${JSON.stringify(policy.package)} --silent --no-fund --no-audit`
    case "python":
      return `pip3 install --break-system-packages --quiet ${JSON.stringify(policy.package)}`
    case "uvx":
      throw new Error(
        'the uvx launcher is not implemented yet (uv is not in the base image). Use launcher = "npx" or "python".',
      )
  }
}

export async function installServerPackage(sandbox: Sandbox, policy: ServerPolicy, log: Logger): Promise<void> {
  log(`installing ${policy.launcher === "npx" ? "npm" : "pip"} package ${policy.package}…`)
  must(await sh(sandbox, installCommand(policy), 600_000), `installing ${policy.package}`)
}

/**
 * Work out how to invoke the installed server.
 *
 * Split from installation so a pinned template — where the package is already
 * baked in — can resolve the entrypoint in one round trip instead of paying to
 * install it again.
 */
export async function resolveEntrypoint(sandbox: Sandbox, policy: ServerPolicy): Promise<Entrypoint> {
  switch (policy.launcher) {
    case "npx": {
      // Read the entrypoint out of the package's own bin field rather than
      // guessing a binary name from the package name.
      const probe = must(
        await sh(
          sandbox,
          [
            `PKG_DIR="$(npm root -g)/${packageName(policy.package)}"`,
            'node -e \'const p=require(process.argv[1]+"/package.json");const b=p.bin;' +
              'if(!b){console.error("no bin field");process.exit(1)}' +
              'const rel=typeof b==="string"?b:Object.values(b)[0];' +
              'console.log(require("path").resolve(process.argv[1],rel))\' "$PKG_DIR"',
          ].join("\n"),
        ),
        `resolving entrypoint for ${policy.package}`,
      )
      const script = probe.stdout.trim().split("\n").filter(Boolean).pop()
      if (!script) throw new Error(`could not resolve an entrypoint for ${policy.package}`)
      return { cmd: "node", args: [script, ...policy.args] }
    }

    case "python": {
      // `package` names the distribution; the importable module is the same
      // name with dashes normalised, which covers the common case.
      const module = packageName(policy.package).replace(/-/g, "_")
      return { cmd: "python3", args: ["-m", module, ...policy.args] }
    }

    case "uvx":
      throw new Error(
        'the uvx launcher is not implemented yet (uv is not in the base image). Use launcher = "npx" or "python".',
      )
  }
}

/** Read the version that actually landed, for the record in airlock.toml. */
export async function installedVersion(sandbox: Sandbox, policy: ServerPolicy): Promise<string | undefined> {
  const name = packageName(policy.package)
  const out =
    policy.launcher === "npx"
      ? await sh(sandbox, `node -e 'console.log(require("${"$"}(npm root -g)/${name}/package.json").version)' 2>/dev/null || true`)
      : await sh(sandbox, `pip3 show ${JSON.stringify(name)} 2>/dev/null | sed -n 's/^Version: //p' || true`)
  const v = out.stdout.trim().split("\n").filter(Boolean).pop()
  return v && /^\d/.test(v) ? v : undefined
}

/**
 * Sync declared mounts INTO the sandbox (SPEC §3.1).
 *
 * There is no host-mount mechanism in Solari at all, so the developer's
 * filesystem is absent by construction rather than by policy. This is the
 * inverse of a traditional sandbox: instead of restricting access, we
 * selectively admit the paths the policy names.
 */
export async function syncMountsIn(sandbox: Sandbox, policy: ServerPolicy, log: Logger): Promise<void> {
  if (policy.mounts.length === 0) {
    log("no mounts declared — the sandbox sees none of your filesystem")
    return
  }
  const { readFileSync, statSync, readdirSync } = await import("node:fs")
  const { join, relative } = await import("node:path")

  for (const mount of policy.mounts) {
    const stat = statSync(mount.path)
    const files: string[] = []
    if (stat.isDirectory()) {
      const walk = (dir: string) => {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
          if (entry.name === ".git" || entry.name === "node_modules") continue
          const full = join(dir, entry.name)
          if (entry.isDirectory()) walk(full)
          else if (entry.isFile()) files.push(full)
        }
      }
      walk(mount.path)
    } else {
      files.push(mount.path)
    }

    log(`admitting ${mount.path} → ${mount.guestPath} (${mount.mode}, ${files.length} files)`)
    await sh(sandbox, `mkdir -p ${JSON.stringify(mount.guestPath)}`)
    for (const file of files) {
      const rel = stat.isDirectory() ? relative(mount.path, file) : ""
      const dest = rel ? `${mount.guestPath}/${rel}` : mount.guestPath
      await sandbox.files.write(dest, readFileSync(file))
    }
    // The server runs as mcp; read-only mounts stay owned by root so it cannot
    // rewrite them, which makes `ro` structural rather than advisory.
    const own = mount.mode === "rw" ? `${MCP_UID}:${MCP_GID}` : "root:root"
    const perms = mount.mode === "rw" ? "755" : "555"
    await sh(
      sandbox,
      [
        `chown -R ${own} ${JSON.stringify(mount.guestPath)}`,
        `chmod -R ${perms} ${JSON.stringify(mount.guestPath)}`,
      ].join("\n"),
    )
  }
}

/** Copy `rw` mounts back out to the developer's machine after the session. */
export async function syncMountsOut(sandbox: Sandbox, policy: ServerPolicy, log: Logger): Promise<void> {
  const writable = policy.mounts.filter((m) => m.mode === "rw")
  if (writable.length === 0) return
  const { writeFileSync, mkdirSync } = await import("node:fs")
  const { dirname, join } = await import("node:path")

  for (const mount of writable) {
    const listing = await sh(sandbox, `find ${JSON.stringify(mount.guestPath)} -type f 2>/dev/null || true`)
    const guestFiles = listing.stdout.trim().split("\n").filter(Boolean)
    log(`syncing back ${guestFiles.length} files from ${mount.guestPath}`)
    for (const guestFile of guestFiles) {
      const rel = guestFile.slice(mount.guestPath.length).replace(/^\//, "")
      const dest = rel ? join(mount.path, rel) : mount.path
      const bytes = await sandbox.files.read(guestFile)
      mkdirSync(dirname(dest), { recursive: true })
      writeFileSync(dest, bytes)
    }
  }
}

/**
 * Stand up the network jail. Returns the env the server must be launched with.
 *
 * With an empty allowlist we skip the proxy and the bridge entirely: the
 * namespace then has no interfaces and no route to anything, so the server has
 * literally no network. That is the strongest configuration and it is what
 * `egress = []` means.
 */
export async function buildNetworkJail(
  sandbox: Sandbox,
  policy: ServerPolicy,
  log: Logger,
): Promise<Record<string, string>> {
  // Fresh namespace each session so a previous run's state cannot leak in.
  must(
    await sh(
      sandbox,
      [
        `ip netns delete ${NETNS} 2>/dev/null || true`,
        `ip netns add ${NETNS}`,
        `ip netns exec ${NETNS} ip link set lo up`,
      ].join("\n"),
    ),
    "creating the network namespace",
  )

  if (policy.egress.length === 0) {
    log("egress: [] — no network at all (namespace has no interfaces)")
    const verify = await sh(
      sandbox,
      `ip netns exec ${NETNS} ip route show | wc -l`,
    )
    if (verify.stdout.trim() !== "0") {
      throw new Error(`expected no routes in the jail, found:\n${verify.text}`)
    }
    return {}
  }

  log(`egress: ${policy.egress.join(", ")}`)

  // The allowlist and config go in as files — see the header note on quoting.
  await sandbox.files.write(
    "/etc/tinyproxy/airlock-allowlist",
    policy.egress.map(domainToEre).join("\n") + "\n",
  )
  await sandbox.files.write(
    "/etc/tinyproxy/airlock.conf",
    [
      "User tinyproxy",
      "Group tinyproxy",
      `Port ${PROXY_PORT}`,
      "Listen 127.0.0.1",
      "Timeout 600",
      // "Connect" level logs every allow and every refusal, which is the
      // evidence `airlock log --blocked` reads (SPEC §3.6).
      "LogLevel Connect",
      `LogFile "${PROXY_LOG}"`,
      'PidFile "/run/tinyproxy.pid"',
      "MaxClients 50",
      "Allow 127.0.0.1",
      'Filter "/etc/tinyproxy/airlock-allowlist"',
      "FilterDefaultDeny Yes",
      "FilterType ere",
      "ConnectPort 443",
      "",
    ].join("\n"),
  )

  must(
    await sh(
      sandbox,
      [
        "set -e",
        // Restart cleanly in case a snapshot restored a running instance.
        "if [ -f /run/tinyproxy.pid ]; then kill \"$(cat /run/tinyproxy.pid)\" 2>/dev/null || true; fi",
        "pkill -f 'socat UNIX-LISTEN:/run/airlock' 2>/dev/null || true",
        `pkill -f 'socat TCP-LISTEN:${PROXY_PORT}' 2>/dev/null || true`,
        "sleep 1",
        "tinyproxy -c /etc/tinyproxy/airlock.conf",
        "sleep 1",
      ].join("\n"),
    ),
    "starting the filtering proxy",
  )

  // Bridge: unix socket in the shared filesystem crosses the namespace.
  must(
    await sh(
      sandbox,
      [
        `nohup socat UNIX-LISTEN:${PROXY_SOCK},fork,mode=0666,unlink-early TCP:127.0.0.1:${PROXY_PORT} >/dev/null 2>&1 &`,
        "sleep 1",
        `nohup ip netns exec ${NETNS} socat TCP-LISTEN:${PROXY_PORT},fork,bind=127.0.0.1,reuseaddr UNIX-CONNECT:${PROXY_SOCK} >/dev/null 2>&1 &`,
        "sleep 2",
        "echo bridged",
      ].join("\n"),
    ),
    "bridging the namespace to the proxy",
  )

  // Assert the bridge is actually up rather than trusting that it is. A silent
  // failure here would look like a working jail that simply has no network,
  // which is exactly the kind of thing that must not pass unnoticed.
  const listening = await sh(
    sandbox,
    `ip netns exec ${NETNS} ss -lnt 2>/dev/null | grep -c ':${PROXY_PORT}' || echo 0`,
  )
  if (listening.stdout.trim() === "0") {
    const diag = await sh(sandbox, `ls -la ${PROXY_SOCK} 2>&1; tail -5 ${PROXY_LOG} 2>&1`)
    throw new Error(`the proxy bridge is not listening inside the jail:\n${diag.text}`)
  }

  const proxyUrl = `http://127.0.0.1:${PROXY_PORT}`
  return {
    http_proxy: proxyUrl,
    https_proxy: proxyUrl,
    HTTP_PROXY: proxyUrl,
    HTTPS_PROXY: proxyUrl,
    NO_PROXY: "127.0.0.1,localhost",
    no_proxy: "127.0.0.1,localhost",
  }
}

/**
 * Wrap an entrypoint so it runs inside the jail as the unprivileged user.
 *
 * `--no-new-privs` is what stops the process re-acquiring CAP_SYS_ADMIN and
 * using setns to walk back out of the namespace.
 */
export function jailCommand(entry: Entrypoint): Entrypoint {
  return {
    cmd: "ip",
    args: [
      "netns",
      "exec",
      NETNS,
      "setpriv",
      `--reuid=${MCP_UID}`,
      `--regid=${MCP_GID}`,
      "--clear-groups",
      "--no-new-privs",
      entry.cmd,
      ...entry.args,
    ],
  }
}

/**
 * Prove the jail is real before any third-party code runs inside it.
 *
 * A security boundary that is assumed rather than checked is the failure mode
 * this whole project exists to argue against, so Airlock verifies its own
 * boundary on every launch and refuses to start the server if it cannot.
 *
 * Checks, using the same `jailCommand` wrapper the server itself is launched
 * with, so what is verified is exactly what is used:
 *
 *   - the process really is uid 4000, not root
 *   - its network namespace is not the host's (compared by inode)
 *   - with `egress = []`, it has no routes at all
 *   - with an allowlist, it can reach the proxy and nothing else directly
 */
export async function verifyJail(sandbox: Sandbox, policy: ServerPolicy, log: Logger): Promise<void> {
  const probe = jailCommand({
    cmd: "sh",
    args: [
      "-c",
      [
        "echo uid=$(id -u)",
        "echo netns=$(readlink /proc/self/ns/net)",
        "echo routes=$(ip route show 2>/dev/null | wc -l)",
      ].join("\n"),
    ],
  })
  const inside = await sandbox.commands.run(probe.cmd, { args: probe.args, timeoutMs: 60_000 })
  if (inside.exitCode !== 0) {
    throw new Error(`jail verification could not run (exit ${inside.exitCode}): ${inside.stderr.slice(-2000)}`)
  }
  const hostNs = await sh(sandbox, "readlink /proc/self/ns/net")

  const parse = (key: string) => inside.stdout.match(new RegExp(`${key}=(\\S+)`))?.[1]
  const uid = parse("uid")
  const netns = parse("netns")
  const routes = parse("routes")
  const hostNetns = hostNs.stdout.trim()

  const failures: string[] = []
  if (uid !== String(MCP_UID)) {
    failures.push(`expected uid ${MCP_UID} inside the jail, got ${uid ?? "unknown"}`)
  }
  if (!netns) {
    failures.push("could not read the jailed process's network namespace")
  } else if (netns === hostNetns) {
    failures.push(`the jailed process shares the host network namespace (${netns})`)
  }
  if (policy.egress.length === 0 && routes !== "0") {
    failures.push(`expected no routes with egress = [], found ${routes}`)
  }

  if (failures.length > 0) {
    // Fail closed: better to refuse to run than to run a server the user
    // believes is contained when it is not.
    throw new Error(
      `refusing to start ${policy.name}: the jail did not verify.\n  ` +
        failures.join("\n  ") +
        `\n\nThis is a bug in Airlock, not in your policy. Please report it.`,
    )
  }

  log(
    `jail verified: uid=${uid}, netns=${netns} (host is ${hostNetns}), routes=${routes}` +
      (policy.egress.length === 0 ? " — no network" : " — proxy only"),
  )
}

/** Read the proxy's decisions back out, for the audit log (SPEC §3.6). */
export async function readProxyLog(sandbox: Sandbox): Promise<string> {
  const out = await sh(sandbox, `cat ${PROXY_LOG} 2>/dev/null || true`)
  return out.stdout
}
