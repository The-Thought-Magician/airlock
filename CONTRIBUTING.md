# Contributing

A small, self-contained TypeScript codebase. The two extension points most
likely to be useful are adding a launcher and adding a policy control.

## Setup

```bash
npm install
export SOLARI_API_KEY=slr_live_...     # needed for anything that boots a sandbox
npm run typecheck                      # tsc --noEmit
```

There is no unit-test framework; correctness is checked by end-to-end scripts
that boot real sandboxes (`npm run test:*`, `npm run e2e`, `npm run probe:*`) and
by pure-function tests that don't (`npm run test:toml`, `npm run test:inject`).
Prefer a pure-function test where the logic allows it — it's faster and free.

## House rules learned the hard way

These are in the code comments too, but collected here because each one cost a
debugging round:

- **Write guest config via `sandbox.files.write`, never `printf`/heredoc.**
  Quoting through the SDK → shell → file doubled backslashes and silently broke
  an allowlist regex.
- **Join multi-step shell scripts with `"\n"`, not `"; "`.** A `; ` after a
  backgrounded `&` is a shell syntax error.
- **The base image has no `pgrep`/`procps`.** A liveness check written with it
  reports every process as dead. Check pidfiles and listening sockets instead
  (or bake `procps` into a template).
- **`kill()` the sandbox, never `close()`.** `close()` only drops the local
  channel and leaves the VM billing until its idle timeout.
- **Keep stdout protocol-only in the relay.** Any diagnostic on stdout corrupts
  the JSON-RPC stream. Everything goes to stderr. The e2e suite asserts this.
- **Verify mechanisms before building on them.** Several spec assumptions were
  wrong against the live API (iptables owner-match, snapshot speed, node fetch
  honouring the proxy). The `probe:*` scripts exist to settle a question with a
  measurement before writing code against it.

## Adding a launcher

A launcher is how a server is installed and started inside the sandbox. All the
plumbing is in `src/jail.ts`; add a case to three functions and the config enum.

1. **`src/config.ts`** — add the name to the `Launcher` union and the
   `LAUNCHERS` array, and validate any launcher-specific fields in `parseConfig`.
2. **`src/jail.ts` → `installCommand(policy)`** — the shell command that installs
   the package (used both at run time and when baking a template). Return
   `"true"` if there's nothing to install ahead of time.
3. **`src/jail.ts` → `resolveEntrypoint(sandbox, policy)`** — return
   `{ cmd, args }` for how to launch the installed server. Resolve the real
   entrypoint from the package's own metadata rather than guessing a binary name.
4. **`src/jail.ts` → `installedVersion(sandbox, policy)`** — optional; return the
   version that landed, for the `airlock build` record.

The `uvx` launcher is a good worked example: it installs `uv`, runs
`uv tool install`, and reads the executable name back from `uv tool list`. The
`local` launcher shows uploading source instead of installing a package.

Node-based launchers automatically get the proxy shim (so `fetch` works) and the
base64 stdout wrapper — both keyed off `launcher` in `src/relay.ts`, so wire a
new node-based launcher into those checks if it applies.

## Adding a policy control

The policy layer (SPEC §3) is: filesystem scoping, egress allowlist, secret
brokering, tool-definition pinning, prompt-injection scanning, audit log. To add
another:

1. **`src/config.ts`** — add the field to `ServerPolicy` and parse it, with a
   safe deny-by-default. Fail at parse time on bad input, not at run time.
2. **Enforce it** in the right place:
   - something structural about the sandbox → `src/jail.ts`
     (`buildNetworkJail`, `verifyJail`, or a new step in the launch sequence);
   - something about the JSON-RPC stream → `src/relay.ts` (the `fromServer` /
     `fromClient` handlers; see how tool-definition drift gates `tools/list`);
   - something checked at build/approval time → `src/template.ts` and
     `src/cli.ts` `cmdBuild` (see the injection scan).
3. **Audit it** — emit an `AuditEvent` from `src/audit.ts` so the control's
   decisions show up in `airlock log`.
4. **Fail closed** — if the control can't be established, refuse to run rather
   than run unprotected. `verifyJail` is the model.
5. **Test it** — an end-to-end script that proves the control actually blocks
   what it claims to (see `test-drift.ts`, `test-broker.ts`), and update
   THREAT-MODEL with what it does and does not cover.

## Docs are part of the work

This is a security tool; a control nobody understands doesn't get adopted. If
you change behaviour, update the relevant doc in `docs/` in the same change, and
if you measured something surprising, record it in a `FINDINGS-*.md` so the next
person doesn't re-learn it.
