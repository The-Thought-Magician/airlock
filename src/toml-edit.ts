/**
 * Surgical edits to airlock.toml.
 *
 * `airlock build` writes a template id back into the policy file, and the file
 * is hand-maintained: it has comments explaining each server's egress and
 * mounts, and those comments are the most valuable part of a security policy.
 * Parsing to an object and re-serialising would delete every one of them.
 *
 * So this edits the text in place — replacing a key's line if present, or
 * appending it inside the right block if not.
 */

/** Render a value as TOML. Strings are JSON-quoted, which is TOML-compatible. */
function toTomlValue(v: string | number | boolean): string {
  if (typeof v === "string") return JSON.stringify(v)
  return String(v)
}

interface BlockRange {
  /** Index of the `[server.<name>]` header line. */
  header: number
  /** Index one past the last line belonging to the block. */
  end: number
}

function findBlock(lines: string[], server: string): BlockRange | undefined {
  // Accept both `[server.name]` and quoted `[server."name"]`.
  const headerRe = new RegExp(
    `^\\s*\\[\\s*server\\s*\\.\\s*("?)${server.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\1\\s*\\]\\s*$`,
  )
  const header = lines.findIndex((l) => headerRe.test(l))
  if (header === -1) return undefined

  let end = lines.length
  for (let i = header + 1; i < lines.length; i++) {
    // Any new table header ends this block.
    if (/^\s*\[/.test(lines[i])) {
      end = i
      break
    }
  }
  // Trim trailing blank AND comment lines. By convention a comment block sitting
  // just above a table header documents that header, so appending after it would
  // attach the new key to the wrong explanation — the keys still parse into the
  // right table, but the file reads as though they belong to the next server,
  // which in a security policy is exactly the wrong kind of confusing.
  while (end > header + 1) {
    const line = lines[end - 1].trim()
    if (line === "" || line.startsWith("#")) end--
    else break
  }
  return { header, end }
}

/**
 * The column the block aligns its `=` to, if it aligns them consistently.
 * Matching it keeps a generated line indistinguishable from a hand-written one.
 */
function alignmentColumn(lines: string[], block: BlockRange): number | undefined {
  const columns = new Set<number>()
  for (let i = block.header + 1; i < block.end; i++) {
    const m = /^(\s*[A-Za-z0-9_-]+\s*)=/.exec(lines[i])
    if (m) columns.add(m[1].length)
  }
  return columns.size === 1 ? [...columns][0] : undefined
}

/**
 * Set one or more keys inside `[server.<name>]`, preserving all comments,
 * ordering, and unrelated content. Throws if the block does not exist.
 */
export function setServerKeys(
  text: string,
  server: string,
  keys: Record<string, string | number | boolean>,
): string {
  const newline = text.includes("\r\n") ? "\r\n" : "\n"
  const lines = text.split(/\r?\n/)
  const block = findBlock(lines, server)
  if (!block) {
    throw new Error(`could not find [server.${server}] in the policy file`)
  }

  let { end } = block
  const column = alignmentColumn(lines, block)

  for (const [key, value] of Object.entries(keys)) {
    const keyRe = new RegExp(`^(\\s*)${key}(\\s*)=`)
    let replaced = false
    for (let i = block.header + 1; i < end; i++) {
      const m = keyRe.exec(lines[i])
      if (m) {
        // Preserve the author's alignment padding around `=`.
        lines[i] = `${m[1]}${key}${m[2]}= ${toTomlValue(value)}`
        replaced = true
        break
      }
    }
    if (!replaced) {
      // Match the block's alignment where it has one, so the new line looks
      // like the lines around it. `column` counts the characters before `=`,
      // and the format below already contributes one space, hence the -1.
      // A key longer than the column just takes a single space rather than
      // pushing everything out of shape.
      const pad = column !== undefined ? " ".repeat(Math.max(0, column - key.length - 1)) : ""
      lines.splice(end, 0, `${key}${pad} = ${toTomlValue(value)}`)
      end++
    }
  }

  return lines.join(newline)
}
