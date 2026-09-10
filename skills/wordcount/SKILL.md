---
name: wordcount
description: Count words, lines, and characters in text, and find the most frequent words.
---

# Word count skill

A tiny example skill, bundled to show how Airlock jails a skill's code. Its
scripts run inside the Airlock sandbox, so they have no access to your
filesystem and only the network the policy allows.

## Tools

Call `skill_instructions` to read this, then `skill_exec` to run the skill's
scripts inside the jail.

- Count everything in a piece of text:

  ```
  skill_exec: echo "the quick brown fox the lazy dog the end" | python3 scripts/count.py
  ```

- Top N most frequent words:

  ```
  skill_exec: echo "a a a b b c" | python3 scripts/top.py 2
  ```

The scripts read from stdin and write a small JSON summary to stdout.
