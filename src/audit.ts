/**
 * Audit log (SPEC §3.6) — local, append-only JSONL, greppable.
 *
 * Two sources feed it: the relay sees every JSON-RPC frame, and the egress
 * proxy's own log records every network attempt with its verdict. Arguments are
 * recorded as a digest plus a size rather than verbatim, so the audit trail
 * does not itself become a place secrets accumulate.
 */
import { appendFileSync, mkdirSync, existsSync, readFileSync } from "node:fs"
import { createHash } from "node:crypto"
import { dirname, resolve } from "node:path"
import { homedir } from "node:os"

export type AuditEvent =
  | { kind: "session.start"; at: string; server: string; sandboxId: string; egress: string[]; mounts: string[] }
  | { kind: "session.end"; at: string; server: string; sandboxId: string; durationMs: number; exitCode?: number }
  | { kind: "tool.call"; at: string; server: string; tool: string; argsDigest: string; argsBytes: number }
  | {
      kind: "tool.result"
      at: string
      server: string
      tool: string
      durationMs: number
      resultBytes: number
      isError: boolean
    }
  | { kind: "rpc"; at: string; server: string; method: string; direction: "in" | "out"; bytes: number }
  | { kind: "net.attempt"; at: string; server: string; host: string; allowed: boolean; raw: string }
  | { kind: "warn"; at: string; server: string; message: string }

export function defaultLogPath(): string {
  return resolve(homedir(), ".local/state/airlock/audit.jsonl")
}

export function digest(value: unknown): { argsDigest: string; argsBytes: number } {
  const json = JSON.stringify(value ?? null)
  return {
    argsDigest: "sha256:" + createHash("sha256").update(json).digest("hex").slice(0, 16),
    argsBytes: Buffer.byteLength(json, "utf8"),
  }
}

export class AuditLog {
  constructor(private readonly path: string = defaultLogPath()) {
    mkdirSync(dirname(this.path), { recursive: true })
  }

  write(event: AuditEvent): void {
    try {
      appendFileSync(this.path, JSON.stringify(event) + "\n")
    } catch {
      // The audit log must never take down the relay it is observing.
    }
  }

  static read(path: string = defaultLogPath()): AuditEvent[] {
    if (!existsSync(path)) return []
    return readFileSync(path, "utf8")
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .flatMap((line) => {
        try {
          return [JSON.parse(line) as AuditEvent]
        } catch {
          return []
        }
      })
  }
}

/**
 * Turn tinyproxy's log into structured network events.
 *
 * Lines look like:
 *   CONNECT ... Request (file descriptor 2): CONNECT api.github.com:443 HTTP/1.1
 *   CONNECT ... Established connection to host "api.github.com" using fd 3.
 *   NOTICE  ... Proxying refused on filtered domain "example.com"
 *
 * A refusal names the host directly, so denials — the interesting half — are
 * read from their own line rather than inferred from a missing success.
 */
export function parseProxyLog(log: string, server: string, at: string): AuditEvent[] {
  const events: AuditEvent[] = []
  for (const line of log.split("\n")) {
    // tinyproxy (plain allowlist path)
    const refused = line.match(/Proxying refused on filtered domain "([^"]+)"/)
    if (refused) {
      events.push({ kind: "net.attempt", at, server, host: refused[1], allowed: false, raw: line.trim() })
      continue
    }
    const established = line.match(/Established connection to host "([^"]+)"/)
    if (established) {
      events.push({ kind: "net.attempt", at, server, host: established[1], allowed: true, raw: line.trim() })
      continue
    }
    // mitmproxy broker addon (AIRLOCK BLOCK|ALLOW|INJECT <host> …)
    const broker = line.match(/AIRLOCK (BLOCK|ALLOW|INJECT) (\S+)/)
    if (broker) {
      events.push({
        kind: "net.attempt",
        at,
        server,
        host: broker[2],
        allowed: broker[1] !== "BLOCK",
        raw: line.trim(),
      })
    }
  }
  return events
}
