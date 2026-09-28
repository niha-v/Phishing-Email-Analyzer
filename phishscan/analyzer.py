"""Run all checks against a parsed email and produce a scored result."""
from __future__ import annotations

from dataclasses import dataclass

from .checks import FREE_MAIL, SEVERITY_POINTS, Finding, auth_summary, run_all_checks
from .parser import IPV4_RE, ParsedEmail, domain_of

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class AnalysisResult:
    email: ParsedEmail
    findings: list[Finding]
    auth: dict[str, str]
    iocs: dict[str, list]

    @property
    def score(self) -> int:
        # Each distinct finding counts once (at its highest severity), so five
        # links tripping the same rule don't inflate the score fivefold.
        best: dict[str, int] = {}
        for f in self.findings:
            best[f.title] = max(best.get(f.title, 0), SEVERITY_POINTS[f.severity])
        return min(100, sum(best.values()))

    @property
    def verdict(self) -> str:
        if self.score >= 60:
            return "LIKELY PHISHING"
        if self.score >= 25:
            return "SUSPICIOUS"
        return "LIKELY BENIGN"


def extract_iocs(e: ParsedEmail) -> dict[str, list]:
    urls = sorted({l.href for l in e.links})
    domains, ips = set(), list(e.received_ips)
    for link in e.links:
        if IPV4_RE.fullmatch(link.host):
            ips.append(link.host)
        elif link.host:
            domains.add(link.host)
    emails = []
    for addr in (e.from_addr, e.reply_to, e.return_path):
        dom = domain_of(addr)
        if dom:
            emails.append(addr.lower())
            if dom not in FREE_MAIL:  # never suggest blocking gmail.com etc.
                domains.add(dom)
    return {
        "emails": list(dict.fromkeys(emails)),
        "urls": urls,
        "domains": sorted(domains),
        "ips": list(dict.fromkeys(ips)),
        "attachments": [
            {"filename": a.filename, "size": a.size, "md5": a.md5, "sha256": a.sha256}
            for a in e.attachments
        ],
    }


def analyze(e: ParsedEmail) -> AnalysisResult:
    findings = sorted(run_all_checks(e), key=lambda f: SEVERITY_ORDER[f.severity])
    return AnalysisResult(email=e, findings=findings, auth=auth_summary(e), iocs=extract_iocs(e))
