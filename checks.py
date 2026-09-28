"""Detection rules. Each check takes a ParsedEmail and returns a list of Findings."""
from __future__ import annotations

import html
import re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from urllib.parse import urlparse

from .parser import IPV4_RE, ParsedEmail, base_domain, domain_of

SEVERITY_POINTS = {"info": 0, "low": 5, "medium": 15, "high": 30}


@dataclass
class Finding:
    category: str
    severity: str  # info | low | medium | high
    title: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Reference data
# --------------------------------------------------------------------------- #
BRANDS = {
    # finance / payments
    "paypal": {"paypal.com"},
    "venmo": {"venmo.com"},
    "zelle": {"zellepay.com"},
    "cashapp": {"cash.app", "squareup.com"},
    "coinbase": {"coinbase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "chase": {"chase.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "libertymutual": {"libertymutual.com"},
    "irs": {"irs.gov"},
    # tech / accounts
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com"},
    "office365": {"microsoft.com", "office.com", "office365.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "googlemail.com"},
    "netflix": {"netflix.com"},
    "spotify": {"spotify.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
    "adobe": {"adobe.com"},
    # retail / delivery (common in job and prize scams)
    "amazon": {"amazon.com", "amazon.co.uk", "amazonses.com"},
    "walmart": {"walmart.com"},
    "samsclub": {"samsclub.com"},
    "costco": {"costco.com"},
    "bestbuy": {"bestbuy.com"},
    "homedepot": {"homedepot.com"},
    "cocacola": {"coca-cola.com", "coke.com", "cocacolacompany.com"},
    "doordash": {"doordash.com"},
    "instacart": {"instacart.com"},
    "uber": {"uber.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "dhl": {"dhl.com"},
}
# Brands that are also everyday words; skipped in the subject-line check.
SUBJECT_BRAND_EXCLUDE = {"chase", "apple"}
LEGIT_BASES = {b: {base_domain(d) for d in ds} for b, ds in BRANDS.items()}

FREE_MAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com",
    "protonmail.com", "proton.me", "gmx.com", "mail.com", "yandex.com", "zoho.com",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "icu", "buzz", "rest", "monster",
    "gq", "tk", "ml", "cf", "ga", "zip", "mov", "click", "link", "work", "support",
}

DANGEROUS_EXT = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".bat", ".cmd",
    ".ps1", ".lnk", ".iso", ".img", ".msi", ".jar", ".cpl", ".dll", ".one",
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
HTML_EXT = {".html", ".htm", ".shtml", ".svg"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tar", ".ace"}
DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"within (24|48|72) hours",
    r"account (has been |will be )?(suspended|locked|disabled|restricted|closed)",
    r"verify your (account|identity|information)", r"unusual (sign-?in|login|activity)",
    r"final (notice|warning|reminder)", r"action required", r"confirm your (password|details|information)",
    r"payment (failed|declined|overdue)", r"password (will )?expire",
    r"\bwire transfer\b", r"\bgift cards?\b", r"avoid (suspension|termination|penalty)",
]
SENSITIVE_PATTERNS = r"\b(password|passcode|social security|ssn|credit card|card number|login credentials|bank account|pin number)\b"
GENERIC_GREETING = r"\bdear (customer|user|client|member|valued|account holder|sir/madam)\b"

JOB_CONTEXT = r"\b(jobs?|internships?|interns?|positions?|hiring|recruit\w*|careers?|resumes?|applicants?|candidates?|vacanc\w*|employment|onboarding)\b"
JOB_OFFER = [
    r"\bcongratulations\b", r"\byou(?:'ve| have)? (?:been|were|are) (?:selected|shortlisted|hired|chosen|approved)",
    r"\b(?:job|internship|employment) offer\b", r"\boffer letter\b", r"completing your internship", r"\bnext batch\b",
]
JOB_EASY = [
    r"no (?:prior |previous )?experience (?:needed|required|necessary)", r"work (?:from|at) home",
    r"flexible (?:hours|schedule)", r"\bearn (?:up to )?\$\s?\d[\d,]*", r"\$\s?\d[\d,]*\s?(?:per|/|an?) ?(?:hour|hr|week|day)",
    r"(?:weekly|daily) pay", r"no interview", r"immediate (?:start|hire|hiring)", r"no boss",
]
JOB_PAYMENT = [
    r"(?:training|registration|certification|onboarding|processing|application|enrollment) fee",
    r"pay (?:for|a|the) .{0,30}(?:training|certification|course|kit|equipment|software)",
    r"(?:deposit|cash) (?:the |a )?check", r"purchase (?:your )?(?:equipment|supplies|software|laptop)",
    r"refundable (?:deposit|fee)",
]
JOB_OFFPLATFORM = [r"\bwhatsapp\b", r"\btelegram\b", r"\bsignal app\b", r"text (?:me|us) (?:at|on)", r"\bwechat\b"]

HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a"), ("$", "s")]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalize_homoglyphs(s: str) -> str:
    s = s.lower()
    for fake, real in HOMOGLYPHS:
        s = s.replace(fake, real)
    return s


def lookalike_brand(host: str) -> str | None:
    """Return the brand a domain appears to imitate, or None."""
    b = base_domain(host)
    if not b or IPV4_RE.fullmatch(b):
        return None
    if any(b in bases for bases in LEGIT_BASES.values()):
        return None  # it's a genuine brand domain

    label = b.split(".")[0]
    norm = normalize_homoglyphs(label)
    parts = [p for p in re.split(r"[-_]", norm) if p]

    for brand in BRANDS:
        if label == brand:                      # paypal.xyz
            return brand
        if len(brand) <= 4:                     # short names: exact token only
            if brand in parts:
                return brand
            continue
        max_dist = 1 if len(brand) <= 7 else 2
        if norm == brand or brand in parts:     # paypa1.com, paypal-secure.com
            return brand
        if any(len(p) >= 4 and levenshtein(p, brand) <= max_dist for p in parts):
            return brand                        # paypall.com, micros0ft-login.com
    return None


def mentions_brand(text: str, brand: str) -> bool:
    t = (text or "").lower()
    if re.search(rf"\b{re.escape(brand)}\b", t):
        return True
    return len(brand) >= 6 and brand in re.sub(r"[^a-z0-9]", "", t)


def auth_summary(e: ParsedEmail) -> dict[str, str]:
    results: dict[str, str] = {}
    for mech, res in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", " ".join(e.auth_results), re.I):
        results.setdefault(mech.lower(), res.lower())
    return results


def _visible_text(e: ParsedEmail) -> str:
    stripped = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", e.html_body, flags=re.S | re.I)
    stripped = html.unescape(re.sub(r"<[^>]+>", " ", stripped))
    return f"{e.subject}\n{e.text_body}\n{stripped}"


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def check_authentication(e: ParsedEmail) -> list[Finding]:
    if not e.auth_results:
        return [Finding("authentication", "low", "No authentication results",
                        "No Authentication-Results or Received-SPF header was found, so SPF/DKIM/DMARC "
                        "outcomes can't be verified from this file.")]
    findings, results = [], auth_summary(e)
    for mech in ("spf", "dkim", "dmarc"):
        res = results.get(mech)
        name = mech.upper()
        if res is None:
            findings.append(Finding("authentication", "low", f"{name} not reported",
                                    f"The receiving server did not record a {name} result."))
        elif res in ("fail", "permerror"):
            sev = "high" if mech == "dmarc" else "medium"
            findings.append(Finding("authentication", sev, f"{name} {res}",
                                    f"{name} check returned '{res}'. The sender is not authorized "
                                    f"to send for the claimed domain."))
        elif res in ("softfail", "none", "neutral", "temperror", "policy"):
            findings.append(Finding("authentication", "low", f"{name} {res}",
                                    f"{name} check returned '{res}', which provides no positive assurance."))
    return findings


def check_sender(e: ParsedEmail) -> list[Finding]:
    findings = []
    from_dom = domain_of(e.from_addr)
    from_base = base_domain(from_dom)

    if not from_dom:
        return [Finding("sender", "high", "Malformed From address",
                        f"Could not extract a domain from From: '{e.from_addr}'.")]

    auth = auth_summary(e)
    # DMARC pass (or SPF + DKIM pass) means the domain owner authorized this mail,
    # so ESP-style header differences are expected and shouldn't add risk.
    authorized = auth.get("dmarc") == "pass" or (auth.get("spf") == "pass" and auth.get("dkim") == "pass")

    rp_dom = domain_of(e.return_path)
    if rp_dom and base_domain(rp_dom) != from_base:
        if authorized:
            findings.append(Finding("sender", "info", "Return-Path domain mismatch",
                                    f"Bounces go to {rp_dom}, but authentication passed, so this is "
                                    f"most likely an email service provider."))
        else:
            findings.append(Finding("sender", "medium", "Return-Path domain mismatch",
                                    f"From domain is {from_dom} but bounces go to {rp_dom}, and "
                                    f"authentication did not confirm the sender."))

    if e.reply_to:
        rt_dom = domain_of(e.reply_to)
        if rt_dom and base_domain(rt_dom) != from_base:
            sev = "high" if rt_dom in FREE_MAIL else "medium"
            findings.append(Finding("sender", sev, "Reply-To differs from sender",
                                    f"Replies go to {e.reply_to} instead of {e.from_addr}"
                                    + (" (a free webmail account)." if rt_dom in FREE_MAIL else ".")))

    embedded = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", e.from_name or "")
    if embedded and base_domain(embedded.group(1)) != from_base:
        findings.append(Finding("sender", "high", "Display name contains a different address",
                                f"Display name '{e.from_name}' shows an address that doesn't match "
                                f"the real sender {e.from_addr}."))

    name_flagged = False
    for brand, bases in LEGIT_BASES.items():
        if mentions_brand(e.from_name, brand) and from_base not in bases:
            findings.append(Finding("sender", "high", "Brand impersonation in display name",
                                    f"Display name '{e.from_name}' references {brand} but the message "
                                    f"was sent from {from_dom}."))
            name_flagged = True
            break

    if not name_flagged:
        for brand, bases in LEGIT_BASES.items():
            if brand in SUBJECT_BRAND_EXCLUDE:
                continue
            if mentions_brand(e.subject, brand) and from_base not in bases:
                findings.append(Finding("sender", "medium", "Brand name in subject from unrelated sender",
                                        f"Subject mentions {brand} but the message was sent from {from_dom}. "
                                        f"Common in prize, discount, and fake-job spam."))
                break

    sender_lookalike = lookalike_brand(from_dom)
    if sender_lookalike:
        findings.append(Finding("sender", "high", "Lookalike sender domain",
                                f"{from_dom} resembles {sender_lookalike} but is not an official domain."))

    mid = re.search(r"@([^>\s]+)", e.message_id or "")
    if mid and base_domain(mid.group(1)) != from_base:
        findings.append(Finding("sender", "info" if authorized else "low", "Message-ID domain mismatch",
                                f"Message-ID was generated by {mid.group(1)}, not {from_dom}."))
    return findings


def check_links(e: ParsedEmail) -> list[Finding]:
    findings, seen = [], set()

    def add(sev, title, detail):
        if (title, detail) not in seen:
            seen.add((title, detail))
            findings.append(Finding("links", sev, title, detail))

    http_links = []
    for link in e.links:
        try:
            parsed = urlparse(link.href)
        except ValueError:
            continue
        host = link.host
        if not host:
            continue

        if IPV4_RE.fullmatch(host):
            add("high", "Link to raw IP address", link.href)
        if "@" in parsed.netloc:
            add("high", "Obfuscated URL ('@' in host)", link.href)
        if host.startswith("xn--") or ".xn--" in host:
            add("high", "Punycode (IDN) domain", f"{host} may use look-alike Unicode characters.")
        if host in SHORTENERS:
            add("medium", "URL shortener hides destination", link.href)
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            add("low", "Link uses a high-abuse TLD", host)
        if host.count(".") >= 4:
            add("low", "Excessive subdomains", host)
        if parsed.scheme == "http":
            http_links.append(link.href)

        if link.source == "html" and link.text:
            shown = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", link.text.lower())
            if shown and base_domain(shown.group(1)) != base_domain(host):
                add("high", "Link text doesn't match destination",
                    f"Displays '{link.text}' but actually opens {link.href}")

        brand = lookalike_brand(host)
        if brand:
            add("high", "Lookalike domain in link", f"{host} imitates {brand}.")
        else:
            tokens = re.split(r"[.\-_]", host)
            for b, bases in LEGIT_BASES.items():
                if len(b) >= 5 and b in tokens and base_domain(host) not in bases:
                    add("medium", "Brand name in unrelated domain", f"{host} contains '{b}'.")
                    break

    if http_links:
        add("low", "Unencrypted HTTP links",
            f"{len(http_links)} link(s) use plain HTTP, e.g. {http_links[0]}. Common in marketing "
            f"tracking links, so this is a weak signal on its own.")
    return findings


def check_content(e: ParsedEmail) -> list[Finding]:
    findings = []
    body = _visible_text(e)

    hits = [p for p in URGENCY_PATTERNS if re.search(p, body, re.I)]
    if hits:
        sample = sorted({m.group(0).lower() for p in hits for m in [re.search(p, body, re.I)] if m})
        sev = "medium" if len(hits) >= 3 else "low"
        findings.append(Finding("content", sev, f"Urgency / pressure language ({len(hits)} indicators)",
                                "Phrases found: " + ", ".join(f"'{s}'" for s in sample[:6])))

    sensitive = sorted({m.lower() for m in re.findall(SENSITIVE_PATTERNS, body, re.I)})
    if sensitive:
        findings.append(Finding("content", "medium", "Mentions sensitive information",
                                "References: " + ", ".join(sensitive)))

    greeting = re.search(GENERIC_GREETING, body, re.I)
    if greeting:
        findings.append(Finding("content", "low", "Generic greeting",
                                f"'{greeting.group(0)}' suggests a mass-sent message."))

    if re.search(r"<form\b", e.html_body, re.I):
        findings.append(Finding("content", "high", "HTML form embedded in email body",
                                "Legitimate senders rarely collect data through forms inside an email."))
    if re.search(r"<script\b", e.html_body, re.I):
        findings.append(Finding("content", "medium", "Script tag in email body",
                                "Email clients block scripts; their presence suggests malicious intent."))
    return findings


def check_attachments(e: ParsedEmail) -> list[Finding]:
    findings = []
    for att in e.attachments:
        name = att.filename.lower()
        suffixes = PurePosixPath(name).suffixes
        ext = suffixes[-1] if suffixes else ""

        if len(suffixes) >= 2 and suffixes[-2] in DECOY_EXT and ext in DANGEROUS_EXT | MACRO_EXT | HTML_EXT:
            findings.append(Finding("attachments", "high", "Double file extension",
                                    f"'{att.filename}' disguises a {ext} file as {suffixes[-2]}."))

        if ext in DANGEROUS_EXT:
            findings.append(Finding("attachments", "high", "Executable / script attachment",
                                    f"'{att.filename}' ({ext}) can run code when opened."))
        elif ext in MACRO_EXT:
            findings.append(Finding("attachments", "high", "Macro-enabled Office attachment",
                                    f"'{att.filename}' may contain VBA macros."))
        elif ext in HTML_EXT:
            text = att.content.decode("utf-8", errors="ignore").lower()
            if re.search(r"<form|password|window\.location|atob\(|document\.write", text):
                findings.append(Finding("attachments", "high", "HTML attachment with credential form or redirect",
                                        f"'{att.filename}' contains a form, redirect, or obfuscated script. "
                                        f"A common credential-harvesting technique."))
            else:
                findings.append(Finding("attachments", "medium", "HTML attachment",
                                        f"'{att.filename}' opens locally in a browser and bypasses URL filters."))
        elif ext in ARCHIVE_EXT:
            findings.append(Finding("attachments", "low", "Archive attachment",
                                    f"'{att.filename}' may hide malicious files from scanners."))
    return findings


def check_job_scam(e: ParsedEmail) -> list[Finding]:
    body = _visible_text(e)
    # Job context: in the subject, or repeatedly in the body (a lone "Careers" footer link doesn't count)
    if not (re.search(JOB_CONTEXT, e.subject, re.I) or len(re.findall(JOB_CONTEXT, body, re.I)) >= 3):
        return []

    def hits(patterns):
        return sorted({m.group(0).lower() for p in patterns for m in [re.search(p, body, re.I)] if m})

    findings = []
    pay = hits(JOB_PAYMENT)
    if pay:
        findings.append(Finding("job-scam", "high", "Job offer mentions fees or payments",
                                "Real employers don't charge candidates. Found: " + ", ".join(f"'{h}'" for h in pay)))
    chat = hits(JOB_OFFPLATFORM)
    if chat:
        findings.append(Finding("job-scam", "high", "Recruiter pushes a chat app",
                                "Moving the conversation to " + ", ".join(chat) + " is a common scam tactic "
                                "to avoid email filtering."))
    offer = hits(JOB_OFFER)
    if offer:
        findings.append(Finding("job-scam", "medium", "Unsolicited offer or congratulations",
                                "Found: " + ", ".join(f"'{h}'" for h in offer)))
    easy = hits(JOB_EASY)
    if easy:
        findings.append(Finding("job-scam", "medium" if len(easy) >= 2 else "low",
                                "Too-good-to-be-true job perks",
                                "Found: " + ", ".join(f"'{h}'" for h in easy)))
    if domain_of(e.from_addr) in FREE_MAIL:
        findings.append(Finding("job-scam", "medium", "Job email from free webmail account",
                                f"Recruiting email sent from {e.from_addr}; companies use their own domain."))
    return findings


ALL_CHECKS = [check_authentication, check_sender, check_links, check_content, check_attachments, check_job_scam]


def run_all_checks(e: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(e))
    return findings
