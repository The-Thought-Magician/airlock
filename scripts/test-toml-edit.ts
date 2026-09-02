/**
 * Tests for the policy-file editor.
 *
 * `airlock build` writes into the user's hand-maintained airlock.toml. A bug
 * here corrupts a security policy, or worse, silently writes a template id
 * into the wrong server's block — which would run one server's code under
 * another's egress rules. Worth testing without spending a template build.
 *
 * Usage: npm run test:toml
 */
import { setServerKeys } from "../src/toml-edit.js"
import { parseConfig } from "../src/config.js"

const original = `# Airlock policy — keep these comments!

# The reference test server. No network, no files.
[server.everything]
launcher = "npx"
package  = "@modelcontextprotocol/server-everything"
egress   = []
mounts   = []

# A server that needs one host and nothing else.
[server.fetch]
launcher = "npx"
package  = "@modelcontextprotocol/server-everything"
egress   = ["api.github.com"]
template = "tpl_OLD"
mounts   = []

# [server.commented]
# launcher = "npx"
`

let pass = 0
let fail = 0
function check(name: string, cond: boolean, detail = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? `  — ${detail}` : ""}`)
  if (cond) pass++
  else fail++
}

// ---- inserting a key that is not there yet ------------------------------
const inserted = setServerKeys(original, "everything", { template: "tpl_NEW", tools_hash: "sha256:abc" })
check("inserts into the named block", /\[server\.everything\][\s\S]*?template\s+= "tpl_NEW"/.test(inserted))
check(
  "does not leak into the following block",
  !inserted.split("[server.fetch]")[1].includes("tpl_NEW"),
)

// The first version of this passed the two checks above while inserting the
// keys *after* the comment introducing [server.fetch] — parseable, but it read
// as though the keys belonged to the next server. Assert position, not just
// containment.
const insertedLines = inserted.split("\n")
const templateLine = insertedLines.findIndex((l) => l.includes("tpl_NEW"))
const nextComment = insertedLines.findIndex((l) => l.includes("needs one host"))
const mountsLine = insertedLines.findIndex((l) => l.startsWith("mounts"))
check(
  "inserts after the block's last key, not after the next block's comment",
  templateLine > mountsLine && templateLine < nextComment,
  `key at ${templateLine}, mounts at ${mountsLine}, next comment at ${nextComment}`,
)
check(
  "leaves a blank line before the next block's comment",
  insertedLines[nextComment - 1].trim() === "",
)
check(
  "matches the block's = alignment",
  insertedLines[templateLine] === 'template = "tpl_NEW"',
  JSON.stringify(insertedLines[templateLine]),
)
check(
  "preserves every comment",
  ["keep these comments", "reference test server", "needs one host"].every((c) => inserted.includes(c)),
)
check("preserves a commented-out block", inserted.includes("# [server.commented]"))

// ---- replacing a key that already exists --------------------------------
const replaced = setServerKeys(original, "fetch", { template: "tpl_REPLACED" })
check("replaces an existing value", replaced.includes('template = "tpl_REPLACED"') && !replaced.includes("tpl_OLD"))
check("does not duplicate the key", (replaced.match(/template\s*=/g) ?? []).length === 1)

// ---- the author's alignment survives ------------------------------------
const aligned = `[server.x]\nlauncher   = "npx"\npackage    = "p"\ntemplate   = "tpl_A"\n`
const realigned = setServerKeys(aligned, "x", { template: "tpl_B" })
check(
  "preserves alignment padding around =",
  realigned.includes('template   = "tpl_B"'),
  JSON.stringify(realigned.split("\n")[3]),
)

// ---- an unknown server must be loud, not a silent no-op -----------------
let threw = false
try {
  setServerKeys(original, "nope", { template: "x" })
} catch {
  threw = true
}
check("throws on an unknown server", threw)

// ---- writing the same value twice changes nothing -----------------------
const twice = setServerKeys(setServerKeys(original, "everything", { template: "tpl_Z" }), "everything", {
  template: "tpl_Z",
})
check("idempotent", (twice.match(/template\s*=\s*"tpl_Z"/g) ?? []).length === 1)

// ---- and the result must still be valid policy -------------------------
const parsed = parseConfig(inserted, "test.toml")
check(
  "output still parses, with other servers intact",
  parsed.servers.everything.template === "tpl_NEW" &&
    parsed.servers.everything.toolsHash === "sha256:abc" &&
    parsed.servers.fetch.egress[0] === "api.github.com" &&
    parsed.servers.fetch.template === "tpl_OLD",
)

// ---- a stale `snapshot` key must be rejected, not ignored ---------------
threw = false
try {
  parseConfig(`[server.old]\nlauncher = "npx"\npackage = "p"\nsnapshot = "snap_x"\n`, "test.toml")
} catch (err) {
  threw = err instanceof Error && err.message.includes("no longer supported")
}
check("rejects the retired `snapshot` key with an explanation", threw)

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
