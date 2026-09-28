#!/usr/bin/env python3
"""Summarize a PhishScan JSON run, or compare two runs (before vs. after).

Usage:
    python3 tools/stats.py results.json
    python3 tools/stats.py results_v1.0.json results_v1.1.json
"""
import json
import re
import sys
from collections import Counter

VERDICTS = ["LIKELY PHISHING", "SUSPICIOUS", "LIKELY BENIGN"]


def load(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, list) else [data]


def top_findings(run, n=15):
    counts = Counter()
    for r in run:
        # count each rule once per email, ignoring info-only findings
        titles = {re.sub(r" \(\d+ indicators\)", "", f["title"])
                  for f in r["findings"] if f["severity"] != "info"}
        counts.update(titles)
    return counts.most_common(n)


def pct(n, total):
    return f"{100 * n / total:5.1f}%" if total else "  n/a"


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    runs = [load(p) for p in sys.argv[1:]]
    labels = ["Before", "After"] if len(runs) == 2 else ["Count"]

    print("\nVerdicts")
    print(f"  {'':<17}" + "".join(f"{l:>16}" for l in labels))
    for v in VERDICTS:
        row = ""
        for run in runs:
            n = sum(r["verdict"] == v for r in run)
            row += f"{n:>7} ({pct(n, len(run))})"
        print(f"  {v:<17}{row}")
    print(f"  {'TOTAL':<17}" + "".join(f"{len(run):>16}" for run in runs))

    if len(runs) == 2:
        before = {r["file"]: r for r in runs[0]}
        changed = [(f, before[f["file"]]) for f in runs[1]
                   if f["file"] in before and before[f["file"]]["verdict"] != f["verdict"]]
        print(f"\nChanged verdicts ({len(changed)})")
        for new, old in sorted(changed, key=lambda x: x[0]["file"]):
            print(f"  {new['file']}: {old['verdict']} ({old['risk_score']}) -> "
                  f"{new['verdict']} ({new['risk_score']})  |  {new['headers']['subject'][:60]}")

    print(f"\nTop findings ({labels[-1].lower()} run, emails affected)")
    for title, n in top_findings(runs[-1]):
        print(f"  {n:>5}  {title}")
    print()


if __name__ == "__main__":
    main()
