"""Render analysis results as console text, JSON, or a Markdown ticket report."""
from __future__ import annotations

import json
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .analyzer import AnalysisResult

SEV_COLOR = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m", "info": "\033[37m"}
VERDICT_COLOR = {"LIKELY PHISHING": "\033[1;91m", "SUSPICIOUS": "\033[1;93m", "LIKELY BENIGN": "\033[1;92m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


# --------------------------------------------------------------------------- #
# Defanging (safe to paste into tickets / chat)
# --------------------------------------------------------------------------- #
def defang(value: str) -> str:
    return value.replace(".", "[.]")


def defang_text(text: str) -> str:
    """Defang dots that sit inside hostnames, leaving sentence punctuation alone."""
    text = re.sub(r"\bhttp", "hxxp", text)
    return re.sub(r"(?<=[A-Za-z0-9-])\.(?=[A-Za-z0-9-])", "[.]", text)


def defang_url(url: str) -> str:
    p = urlparse(url)
    if not p.netloc:
        return defang(url)
    scheme = p.scheme.lower().replace("http", "hxxp")
    rest = url.split(p.netloc, 1)[1]
    return f"{scheme}://{defang(p.netloc)}{rest}"


# --------------------------------------------------------------------------- #
# Dict / JSON
# --------------------------------------------------------------------------- #
def to_dict(r: AnalysisResult) -> dict:
    e = r.email
    return {
        "file": Path(e.path).name,
        "verdict": r.verdict,
        "risk_score": r.score,
        "headers": {
            "subject": e.subject, "date": e.date, "from_name": e.from_name,
            "from": e.from_addr, "reply_to": e.reply_to, "return_path": e.return_path,
            "message_id": e.message_id,
        },
        "authentication": r.auth,
        "received_hops": e.received,
        "findings": [f.to_dict() for f in r.findings],
        "iocs": r.iocs,
    }


def to_json(results: list[AnalysisResult]) -> str:
    data = [to_dict(r) for r in results]
    return json.dumps(data[0] if len(data) == 1 else data, indent=2)


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #
def render_console(r: AnalysisResult, color: bool = True) -> str:
    c = (lambda code, s: f"{code}{s}{RESET}") if color else (lambda code, s: s)
    e, width, out = r.email, 72, []
    rule = "═" * width

    out += [rule, c(BOLD, f" PhishScan Report: {Path(e.path).name}"), rule]
    out.append(f" Verdict     : {c(VERDICT_COLOR[r.verdict], r.verdict)}   (risk score {r.score}/100)")
    for label, val in [("Subject", e.subject), ("From", f'"{e.from_name}" <{e.from_addr}>' if e.from_name else e.from_addr),
                       ("Reply-To", e.reply_to), ("Return-Path", e.return_path), ("Date", e.date)]:
        if val:
            out.append(f" {label:<12}: {val}")

    auth = "  |  ".join(f"{m.upper()}: {r.auth.get(m, 'n/a')}" for m in ("spf", "dkim", "dmarc"))
    out += ["", c(BOLD, " Authentication"), f"   {auth}"]

    if e.received_ips:
        out += ["", c(BOLD, f" Received hops ({len(e.received)})"),
                f"   IPs (most recent first): {', '.join(e.received_ips)}"]

    out += ["", c(BOLD, f" Findings ({len(r.findings)})")]
    if not r.findings:
        out.append("   No suspicious indicators detected.")
    for f in r.findings:
        tag = c(SEV_COLOR[f.severity], f"[{f.severity.upper():<6}]")
        out.append(f"   {tag} {f.title}  {c(DIM, '(' + f.category + ')')}")
        for line in textwrap.wrap(f.detail, width - 13):
            out.append(f"             {line}")

    iocs = r.iocs
    out += ["", c(BOLD, " Indicators of Compromise (defanged)")]
    if iocs["emails"]:
        out.append("   Sender addresses: " + ", ".join(defang(a) for a in iocs["emails"]))
    if iocs["urls"]:
        out.append("   URLs:")
        out += [f"     - {defang_url(u)}" for u in iocs["urls"]]
    if iocs["domains"]:
        out.append("   Domains: " + ", ".join(defang(d) for d in iocs["domains"]))
    if iocs["ips"]:
        out.append("   IPs: " + ", ".join(defang(i) for i in iocs["ips"]))
    if iocs["attachments"]:
        out.append("   Attachments:")
        for a in iocs["attachments"]:
            out.append(f"     - {a['filename']} ({a['size']} bytes)")
            out.append(f"       SHA256 {a['sha256']}")
            out.append(f"       MD5    {a['md5']}")

    out.append(rule)
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Markdown (ticket / case notes)
# --------------------------------------------------------------------------- #
def to_markdown(r: AnalysisResult) -> str:
    e = r.email
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md = [
        f"# Phishing Analysis: {Path(e.path).name}",
        "",
        f"**Verdict:** {r.verdict}  ",
        f"**Risk score:** {r.score}/100  ",
        f"**Analyzed:** {now}",
        "",
        "## Message details",
        "",
        "| Field | Value |",
        "|---|---|",
    ]
    for label, val in [("Subject", e.subject), ("From", f"{e.from_name} <{e.from_addr}>"),
                       ("Reply-To", e.reply_to), ("Return-Path", e.return_path),
                       ("Date", e.date), ("Message-ID", e.message_id)]:
        md.append(f"| {label} | {(val or '-').replace('|', '/')} |")

    md += ["", "## Authentication", "",
           " / ".join(f"**{m.upper()}:** {r.auth.get(m, 'n/a')}" for m in ("spf", "dkim", "dmarc")),
           "", "## Findings", ""]
    if r.findings:
        md += ["| Severity | Category | Finding | Detail |", "|---|---|---|---|"]
        for f in r.findings:
            md.append(f"| {f.severity.upper()} | {f.category} | {f.title} | {defang_text(f.detail) if f.category == 'links' else f.detail} |")
    else:
        md.append("No suspicious indicators detected.")

    md += ["", "## Indicators of compromise (defanged)", ""]
    for a in r.iocs["emails"]:
        md.append(f"- Email: `{defang(a)}`")
    for u in r.iocs["urls"]:
        md.append(f"- URL: `{defang_url(u)}`")
    for d in r.iocs["domains"]:
        md.append(f"- Domain: `{defang(d)}`")
    for ip in r.iocs["ips"]:
        md.append(f"- IP: `{defang(ip)}`")
    for a in r.iocs["attachments"]:
        md.append(f"- Attachment: `{a['filename']}` SHA256 `{a['sha256']}`")

    md += ["", "## Recommended actions", ""]
    if r.verdict == "LIKELY PHISHING":
        md += ["- [ ] Quarantine / purge the message from all mailboxes",
               "- [ ] Block sender domain, URLs, and IPs at the mail gateway and proxy",
               "- [ ] Identify recipients who clicked or replied; reset credentials where needed",
               "- [ ] Submit hashes and URLs to threat intel / sandbox for further analysis"]
    elif r.verdict == "SUSPICIOUS":
        md += ["- [ ] Manually review links and attachments in a sandbox",
               "- [ ] Confirm with the purported sender through a known-good channel"]
    else:
        md += ["- [ ] No action required; close as benign unless other context applies"]
    return "\n".join(md) + "\n"
