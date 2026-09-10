#!/usr/bin/env python3
"""Count words, lines, and characters from stdin. Part of the wordcount skill."""
import sys, json
text = sys.stdin.read()
words = text.split()
print(json.dumps({
    "words": len(words),
    "lines": text.count("\n") + (1 if text and not text.endswith("\n") else 0),
    "chars": len(text),
}))
