# Airlock demo

The same deliberately malicious MCP server, run two ways: natively, as an MCP
client launches servers today, and then under Airlock. Same server, same tool
calls, opposite outcomes.

```
npm install
set -a && . ./.env && set +a     # your SOLARI_API_KEY
npm run demo
```

## Safety — read this

This directory contains **working demonstration malware**. It is built to be
**inert**, and the safety properties below are enforced by the code, not merely
promised. Reviewers judging security work should check that the author
understood the responsibility, so here it is, plainly:

- **The "stolen" credential is a fake file with fake contents.** `run-demo.ts`
  writes it to a fresh temp directory at the start of each run and deletes it at
  the end. The evil server is pointed at *that* file. It never reads a real
  `~/.aws/credentials`, `~/.ssh/id_rsa`, or anything else on your machine — the
  target path is injected, not discovered.

- **The exfiltration target is localhost.** The evil server's exfil host is
  hardcoded to `127.0.0.1` (`demo/evil-server/index.js`), and the listener that
  receives it is started by the demo on `127.0.0.1` and closed when the demo
  ends. Nothing leaves your machine. There is no code path that would let it
  post to a real remote endpoint.

- **The network-probe target (`1.1.1.1:443`) is a reachability check only.** The
  `ping` tool opens a raw TCP socket to a public resolver to show whether egress
  is open; it sends nothing. Under Airlock the connection fails with
  `ENETUNREACH` because the jail has no route.

- **Nothing published here functions against any real service.** The evil server
  is dependency-free, clearly labelled, and lives only in `demo/evil-server/`.

If you want to point the evil server at a different (still fake) file to prove
the point, set `EVIL_TARGET_FILE`. Do not point it at a real credential file —
there is no reason to, and the demo does not need it.

## What you see

![Airlock demo output: native run steals and exfiltrates the credential; the jailed run gets ENOENT on the read and ENETUNREACH on the egress](image.png)

`demo/transcript.txt` is the same run as text. The shape of it:

**Native (no Airlock)** — the server does its advertised job *and* its hidden one:

```
agent calls: add(2, 3)
[evil-server] READ …/credentials — 112 bytes of "secrets"
[evil-server] EXFIL POST succeeded (200) to 127.0.0.1:9099
agent calls: ping()
[evil-server] PHONE-HOME connected to 1.1.1.1:443 (raw socket, ignored HTTP_PROXY)
  ✗ CREDENTIAL STOLEN.
```

**Under Airlock** — the same code, the same calls, contained:

```
airlock: jail verified: uid=4000, netns=net:[…] (host is net:[…]), routes=0
agent calls: add(2, 3)
[evil-server] could not read …/credentials: ENOENT
agent calls: ping()
[evil-server] PHONE-HOME failed: ENETUNREACH
  ✓ NOTHING STOLEN.
```

Two boundaries are exercised:

- **Filesystem (§3.1).** The credential read returns `ENOENT` — not because a
  rule denied it, but because the file is not on the sandbox at all. There is no
  mechanism by which your laptop's files could be there. Isolation is the
  default; access is the opt-in.
- **Network (§3.2).** The `ping` tool ignores the injected `HTTP_PROXY` and
  opens a raw socket directly, which is the bypass a real server would attempt.
  It still fails, with `ENETUNREACH`, because the server runs in a network
  namespace with no interfaces — there is no route to ignore the proxy *to*.

The demo asserts both outcomes and exits non-zero if either boundary fails, so
it is a test as much as a showpiece.

## The evil server

`demo/evil-server/index.js` is a complete, readable MCP server in one
dependency-free file. It advertises two innocent-looking tools:

- `add(a, b)` — returns the sum, and on the side reads the target file and POSTs
  it to the exfil listener.
- `ping()` — returns "pong", and on the side opens a raw socket to a remote IP.

Both hidden behaviours are logged to stderr so the demo can narrate them. This
is the tool-poisoning pattern: the description an agent reads is a lie about what
the tool does.

## Recording the 40-second version (SPEC §8.3)

`npm run demo` is the content. To capture it:

```bash
# asciinema → GIF, keeps it crisp and small
asciinema rec demo.cast -c "npm run demo"
agg demo.cast demo.gif        # or: svg-term < demo.cast > demo.svg
```

Or a plain screen recording of the terminal. The run takes ~30–40s, most of it
the one-time cold provision of the sandbox on the Airlock side.
