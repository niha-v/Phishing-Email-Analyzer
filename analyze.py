#!/usr/bin/env python3
"""PhishScan command-line interface.

Examples:
    python analyze.py samples/phish_sample.eml
    python analyze.py samples/ --json results.json --report-dir reports/
    VT_API_KEY=xxxx python analyze.py suspicious.eml --vt
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from phishscan import analyze, parse_email
from phishscan.report import render_console, to_json, to_markdown


def collect_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted(p.glob("*.eml")))
        elif p.is_file():
            files.append(p)
        else:
            print(f"[!] Not found: {p}", file=sys.stderr)
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description="Static analyzer for suspicious .eml files.")
    ap.add_argument("paths", nargs="+", help=".eml file(s) or directories containing them")
    ap.add_argument("--json", metavar="FILE", help="write results as JSON")
    ap.add_argument("--report-dir", metavar="DIR", help="write a Markdown case report per email")
    ap.add_argument("--vt", action="store_true", help="enrich with VirusTotal (needs VT_API_KEY env var)")
    ap.add_argument("--no-color", action="store_true", help="disable colored output")
    ap.add_argument("--summary", action="store_true", help="print one line per email instead of full report")
    args = ap.parse_args()

    files = collect_files(args.paths)
    if not files:
        print("[!] No .eml files to analyze.", file=sys.stderr)
        return 1

    api_key = os.environ.get("VT_API_KEY")
    if args.vt and not api_key:
        print("[!] --vt requires the VT_API_KEY environment variable. Skipping enrichment.", file=sys.stderr)

    color = sys.stdout.isatty() and not args.no_color
    results = []
    for f in files:
        try:
            result = analyze(parse_email(f))
        except Exception as exc:
            print(f"[!] Failed to parse {f}: {exc}", file=sys.stderr)
            continue
        if args.vt and api_key:
            from phishscan.enrich import enrich_with_virustotal
            print(f"[*] Querying VirusTotal for {f.name} (free tier is rate-limited)...", file=sys.stderr)
            enrich_with_virustotal(result, api_key)
        results.append(result)

        if args.summary:
            print(f"{result.verdict:<16} {result.score:>3}/100  {f.name}  |  {result.email.subject}")
        else:
            print(render_console(result, color=color))
            print()

        if args.report_dir:
            out_dir = Path(args.report_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{f.stem}_report.md").write_text(to_markdown(result), encoding="utf-8")

    if args.json and results:
        Path(args.json).write_text(to_json(results), encoding="utf-8")
        print(f"[+] JSON written to {args.json}", file=sys.stderr)
    if args.report_dir and results:
        print(f"[+] Markdown reports written to {args.report_dir}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
