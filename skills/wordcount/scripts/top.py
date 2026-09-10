#!/usr/bin/env python3
"""Print the top N most frequent words from stdin. Usage: top.py [N]."""
import sys, json
from collections import Counter
n = int(sys.argv[1]) if len(sys.argv) > 1 else 3
counts = Counter(sys.stdin.read().split())
print(json.dumps({"top": counts.most_common(n)}))
