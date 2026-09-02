/**
 * airlock.toml — the policy file (SPEC §6.3).
 *
 * One block per server. Everything is deny-by-default: a server with no
 * `egress` gets no network at all, and a server with no `mounts` sees none of
 * the developer's files. Both are the safe reading of an omitted field, which
 * is the point of §3.1 — isolation is the default, access is the opt-in.
 */
import { readFileSync, existsSync } from "node:fs"
import { homedir } from "node:os"
import { resolve, isAbsolute } from "node:path"
import { parse as parseToml } from "smol-toml"

export type Launcher = "npx" | "python" | "uvx" | "local"
export type MountMode = "ro" | "rw"

export interface Mount {
  /** Path on the developer's machine. */
  path: string
  /** Absolute path as it will appear inside the sandbox. */
  guestPath: string
  mode: MountMode
}

export interface ServerPolicy {
  name: string
  launcher: Launcher
  /** npm package, pip distribution, or uv tool name. Empty for `local`. */
  package: string
  /**
   * For `launcher = "local"`: a directory on this machine holding the server's
   * source, uploaded into the sandbox at launch.
   *
   * This exists so a server can be jailed without publishing it to a registry
   * first — which is what the demo needs, since publishing a working
   * credential-stealer would be irresponsible (SPEC §8.2).
   */
  path?: string
  /** Extra argv appended after the entrypoint. */
  args: string[]
  /** Allowlisted domains. Empty means no network whatsoever. */
  egress: string[]
  mounts: Mount[]
  /**
   * Env vars handed to the server.
   *
   * NOTE: this is pass-through today. SPEC §3.3 (brokering the real credential
   * at the proxy so the server only ever holds a placeholder) is not built yet,
   * so anything here genuinely reaches the server process. `airlock run` warns
   * when this is non-empty.
   */
  secrets: Record<string, string>
  /**
   * Pinned template minted by `airlock build` (SPEC §4).
   *
   * The spec originally pinned a snapshot here. Snapshots lost on measurement
   * — restore is ~4x slower than provisioning cold, and `revert()` is
   * unavailable — so the pin is a `tpl_…` id. See docs/FINDINGS-WARMSTART.md.
   */
  template?: string
  /** Version that landed in the template, recorded by `airlock build`. */
  version?: string
  /** Tool-definition hash at build time (SPEC §3.4). */
  toolsHash?: string
}

export interface AirlockConfig {
  servers: Record<string, ServerPolicy>
  path: string
}

const LAUNCHERS: readonly string[] = ["npx", "python", "uvx", "local"]

class ConfigError extends Error {}

/** `~/projects/x` → `/home/you/projects/x`. */
export function expandHome(p: string): string {
  if (p === "~") return homedir()
  if (p.startsWith("~/")) return resolve(homedir(), p.slice(2))
  return resolve(p)
}

/**
 * Compile a domain pattern to an anchored POSIX ERE for the tinyproxy filter
 * file. `*.github.com` matches subdomains; a bare domain matches only itself.
 */
export function domainToEre(domain: string): string {
  const d = domain.trim()
  if (d.length === 0) throw new ConfigError("empty domain in egress list")
  if (d.includes("/")) {
    throw new ConfigError(`egress entries are domains, not URLs or paths: ${JSON.stringify(d)}`)
  }
  if (d.startsWith("*.")) {
    // Match the apex too, so "*.github.com" covers "github.com".
    const rest = d.slice(2).replace(/\./g, "\\.")
    return `^(.*\\.)?${rest}$`
  }
  return `^${d.replace(/\./g, "\\.")}$`
}

function asStringArray(v: unknown, field: string, server: string): string[] {
  if (v === undefined) return []
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    throw new ConfigError(`[server.${server}] ${field} must be an array of strings`)
  }
  return v as string[]
}

function parseMounts(v: unknown, server: string): Mount[] {
  if (v === undefined) return []
  if (!Array.isArray(v)) throw new ConfigError(`[server.${server}] mounts must be an array`)
  return v.map((entry, i) => {
    if (typeof entry !== "object" || entry === null) {
      throw new ConfigError(`[server.${server}] mounts[${i}] must be a table with { path, mode }`)
    }
    const e = entry as Record<string, unknown>
    if (typeof e.path !== "string") {
      throw new ConfigError(`[server.${server}] mounts[${i}].path must be a string`)
    }
    const mode = e.mode ?? "ro"
    if (mode !== "ro" && mode !== "rw") {
      throw new ConfigError(`[server.${server}] mounts[${i}].mode must be "ro" or "rw"`)
    }
    const hostPath = expandHome(e.path)
    // The guest path mirrors the host path under a fixed root, so a server that
    // was told about ~/projects/demo sees a stable, predictable location.
    const guestPath =
      typeof e.guestPath === "string" && isAbsolute(e.guestPath)
        ? e.guestPath
        : `/mnt/airlock${hostPath.startsWith("/") ? hostPath : "/" + hostPath}`
    return { path: hostPath, guestPath, mode: mode as MountMode }
  })
}

export function parseConfig(text: string, path: string): AirlockConfig {
  const raw = parseToml(text) as Record<string, unknown>
  const serverTable = (raw.server ?? {}) as Record<string, unknown>
  if (typeof serverTable !== "object" || serverTable === null) {
    throw new ConfigError("expected a [server.<name>] table")
  }

  const servers: Record<string, ServerPolicy> = {}
  for (const [name, valueRaw] of Object.entries(serverTable)) {
    if (typeof valueRaw !== "object" || valueRaw === null) {
      throw new ConfigError(`[server.${name}] must be a table`)
    }
    const value = valueRaw as Record<string, unknown>

    const launcher = value.launcher
    if (typeof launcher !== "string" || !LAUNCHERS.includes(launcher)) {
      throw new ConfigError(
        `[server.${name}] launcher must be one of ${LAUNCHERS.join(", ")} (got ${JSON.stringify(launcher)})`,
      )
    }
    if (launcher === "local") {
      if (typeof value.path !== "string" || value.path.length === 0) {
        throw new ConfigError(`[server.${name}] launcher = "local" requires \`path\` (a directory to upload)`)
      }
    } else if (typeof value.package !== "string" || value.package.length === 0) {
      throw new ConfigError(`[server.${name}] package is required`)
    }

    const secretsRaw = value.secrets ?? {}
    if (typeof secretsRaw !== "object" || secretsRaw === null || Array.isArray(secretsRaw)) {
      throw new ConfigError(`[server.${name}] secrets must be a table`)
    }
    const secrets: Record<string, string> = {}
    for (const [k, v] of Object.entries(secretsRaw as Record<string, unknown>)) {
      if (typeof v !== "string") throw new ConfigError(`[server.${name}] secrets.${k} must be a string`)
      secrets[k] = v
    }

    const egress = asStringArray(value.egress, "egress", name)
    // Fail at parse time, not when tinyproxy silently refuses everything.
    for (const d of egress) domainToEre(d)

    servers[name] = {
      name,
      launcher: launcher as Launcher,
      package: typeof value.package === "string" ? value.package : "",
      path: typeof value.path === "string" ? expandHome(value.path) : undefined,
      args: asStringArray(value.args, "args", name),
      egress,
      mounts: parseMounts(value.mounts, name),
      secrets,
      template: typeof value.template === "string" && value.template.length > 0 ? value.template : undefined,
      version: typeof value.version === "string" && value.version.length > 0 ? value.version : undefined,
      toolsHash: typeof value.tools_hash === "string" && value.tools_hash.length > 0 ? value.tools_hash : undefined,
    }

    // The field was renamed when snapshots were measured and dropped. Say so
    // rather than silently ignoring a key the user believes is doing something.
    if (typeof value.snapshot === "string") {
      throw new ConfigError(
        `[server.${name}] \`snapshot\` is no longer supported — snapshot restore measured ~4x slower ` +
          `than provisioning cold (see docs/FINDINGS-WARMSTART.md). Run \`airlock build ${name}\` ` +
          `to mint a template and replace it with \`template = "tpl_…"\`.`,
      )
    }
  }

  return { servers, path }
}

export function findConfigPath(explicit?: string): string {
  if (explicit) return resolve(explicit)
  const candidates = [resolve("airlock.toml"), resolve(homedir(), ".config/airlock/airlock.toml")]
  const found = candidates.find((c) => existsSync(c))
  if (!found) {
    throw new ConfigError(
      `no airlock.toml found. Looked in:\n  ${candidates.join("\n  ")}\nRun \`airlock init\` to generate one.`,
    )
  }
  return found
}

export function loadConfig(explicit?: string): AirlockConfig {
  const path = findConfigPath(explicit)
  return parseConfig(readFileSync(path, "utf8"), path)
}
