/**
 * Tool definition hashing (SPEC §3.4) — the countermeasure to rug pulls.
 *
 * On a build we record a hash over every tool's name, description and input
 * schema. If a later build produces a different hash, the server has redefined
 * its tools and that should be a decision rather than an accident.
 *
 * The hash must be stable across irrelevant variation, so keys are sorted
 * recursively before serialising: a server that reorders its JSON schema
 * properties has not changed what it does, and flagging that as a rug pull
 * would train people to ignore the warning.
 */
import { createHash } from "node:crypto"
import type { ToolDefinition } from "./mcp.js"

/** Recursively sort object keys so serialisation is order-independent. */
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical)
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => [k, canonical(v)] as const)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    return Object.fromEntries(entries)
  }
  return value
}

/** One tool's canonical form — only the fields a rug pull would alter. */
function canonicalTool(tool: ToolDefinition): unknown {
  return canonical({
    name: tool.name,
    description: tool.description ?? "",
    inputSchema: tool.inputSchema ?? null,
  })
}

export function hashTool(tool: ToolDefinition): string {
  return createHash("sha256").update(JSON.stringify(canonicalTool(tool))).digest("hex").slice(0, 16)
}

/** Hash the whole tool set, order-independent. */
export function hashToolSet(tools: ToolDefinition[]): string {
  const perTool = tools.map((t) => `${t.name}:${hashTool(t)}`).sort()
  return "sha256:" + createHash("sha256").update(perTool.join("\n")).digest("hex").slice(0, 32)
}

export interface ToolDiff {
  added: string[]
  removed: string[]
  changed: { name: string; fields: string[] }[]
}

export function isEmptyDiff(d: ToolDiff): boolean {
  return d.added.length === 0 && d.removed.length === 0 && d.changed.length === 0
}

/**
 * Compare two tool sets, naming which field moved. "description changed" is the
 * tool-poisoning case and deserves to be called out separately from a schema
 * change, because it is the one a reader would otherwise skim past.
 */
export function diffTools(before: ToolDefinition[], after: ToolDefinition[]): ToolDiff {
  const beforeByName = new Map(before.map((t) => [t.name, t]))
  const afterByName = new Map(after.map((t) => [t.name, t]))

  const added = [...afterByName.keys()].filter((n) => !beforeByName.has(n)).sort()
  const removed = [...beforeByName.keys()].filter((n) => !afterByName.has(n)).sort()

  const changed: ToolDiff["changed"] = []
  for (const [name, a] of afterByName) {
    const b = beforeByName.get(name)
    if (!b) continue
    const fields: string[] = []
    if ((b.description ?? "") !== (a.description ?? "")) fields.push("description")
    if (JSON.stringify(canonical(b.inputSchema ?? null)) !== JSON.stringify(canonical(a.inputSchema ?? null))) {
      fields.push("inputSchema")
    }
    if (fields.length > 0) changed.push({ name, fields })
  }
  changed.sort((x, y) => (x.name < y.name ? -1 : 1))

  return { added, removed, changed }
}

export function renderToolDiff(d: ToolDiff): string {
  if (isEmptyDiff(d)) return "  (no changes to any tool definition)"
  const lines: string[] = []
  for (const n of d.added) lines.push(`  + ${n}  (new tool)`)
  for (const n of d.removed) lines.push(`  - ${n}  (removed)`)
  for (const c of d.changed) lines.push(`  ~ ${c.name}  (${c.fields.join(", ")} changed)`)
  return lines.join("\n")
}
