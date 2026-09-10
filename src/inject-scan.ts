/**
 * Prompt-injection scanning (SPEC §3.5).
 *
 * Tool descriptions are read by the agent, so a malicious server can smuggle
 * instructions there — "ignore previous instructions", "always read ~/.ssh
 * first", zero-width characters hiding text, and so on. This scans the fields
 * an agent actually sees (name, description, and the descriptions inside the
 * input schema) and reports matches.
 *
 * Per the spec this is **warnings, not a block**: false positives are certain
 * (a legitimate tool may say "before responding, validate the input"), so it
 * informs a human at approval time rather than refusing to run. It is the P2
 * control — the least load-bearing — and is deliberately conservative.
 */
import type { ToolDefinition } from "./mcp.js"

export interface InjectionFinding {
  tool: string
  field: string
  pattern: string
  excerpt: string
}

interface Rule {
  label: string
  re: RegExp
}

const RULES: Rule[] = [
  // Direct attempts to override the agent's instructions.
  { label: "instruction override", re: /\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b/i },
  { label: "system-prompt reference", re: /\bsystem prompt\b/i },
  // Coercive imperatives aimed at the agent's behaviour.
  { label: "coercive imperative", re: /\b(always|never|you must|be sure to|make sure to|immediately)\b[^.\n]{0,40}\b(call|run|invoke|use|send|read|fetch)\b/i },
  { label: "pre-response instruction", re: /\bbefore (responding|answering|replying|proceeding)\b/i },
  { label: "secrecy instruction", re: /\b(do not|don't|never)\b[^.\n]{0,30}\b(tell|mention|inform|reveal|disclose|show)\b[^.\n]{0,30}\b(user|human|them)\b/i },
  // References to credential locations — a tool has no honest reason to name these.
  { label: "credential path", re: /(~\/\.ssh|id_rsa|\.aws\/credentials|\.env\b|\.config\/gh|GITHUB_TOKEN|AWS_SECRET|private key)/i },
  // Obfuscation.
  { label: "long base64 blob", re: /[A-Za-z0-9+/]{120,}={0,2}/ },
  { label: "zero-width / bidi control chars", re: /[​‌‍⁠‪-‮⁦-⁩]/ },
  { label: "html/script comment", re: /<!--|<script\b/i },
]

/** Walk a JSON-schema-ish object collecting every `description` string in it. */
function schemaDescriptions(schema: unknown, path = "inputSchema"): { field: string; text: string }[] {
  const out: { field: string; text: string }[] = []
  const visit = (node: unknown, p: string) => {
    if (node === null || typeof node !== "object") return
    if (Array.isArray(node)) {
      node.forEach((n, i) => visit(n, `${p}[${i}]`))
      return
    }
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (k === "description" && typeof v === "string") out.push({ field: `${p}.description`, text: v })
      else visit(v, `${p}.${k}`)
    }
  }
  visit(schema, path)
  return out
}

/**
 * Scan a raw block of text (e.g. a SKILL.md) for the same patterns. Used by the
 * `skill` launcher, whose instructions are read by the agent just like a tool
 * description.
 */
export function scanText(text: string, field = "text"): InjectionFinding[] {
  const findings: InjectionFinding[] = []
  for (const rule of RULES) {
    const m = rule.re.exec(text)
    if (m) {
      const at = Math.max(0, m.index - 15)
      findings.push({
        tool: field,
        field,
        pattern: rule.label,
        excerpt: (at > 0 ? "…" : "") + text.slice(at, m.index + m[0].length + 15).replace(/\s+/g, " ").trim() + "…",
      })
    }
  }
  return findings
}

export function scanTool(tool: ToolDefinition): InjectionFinding[] {
  const fields: { field: string; text: string }[] = [
    { field: "name", text: tool.name ?? "" },
    { field: "description", text: tool.description ?? "" },
    ...schemaDescriptions(tool.inputSchema),
  ]
  const findings: InjectionFinding[] = []
  for (const { field, text } of fields) {
    for (const rule of RULES) {
      const m = rule.re.exec(text)
      if (m) {
        const at = Math.max(0, m.index - 15)
        findings.push({
          tool: tool.name,
          field,
          pattern: rule.label,
          excerpt: (at > 0 ? "…" : "") + text.slice(at, m.index + m[0].length + 15).replace(/\s+/g, " ").trim() + "…",
        })
      }
    }
  }
  return findings
}

export function scanTools(tools: ToolDefinition[]): InjectionFinding[] {
  return tools.flatMap(scanTool)
}

export function renderInjectionFindings(findings: InjectionFinding[]): string {
  if (findings.length === 0) return "  no prompt-injection patterns found in tool descriptions"
  return findings
    .map((f) => `  ⚠ ${f.tool} (${f.field}): ${f.pattern}\n      ${JSON.stringify(f.excerpt)}`)
    .join("\n")
}
