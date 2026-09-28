"""Parse raw .eml files into a structured ParsedEmail object."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

URL_RE = re.compile(r"""https?://[^\s<>"'()\[\]]+""", re.IGNORECASE)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# Public suffixes that take three labels to form a registrable domain.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.in", "co.jp",
    "com.br", "co.nz", "com.mx", "co.za",
}


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #
@dataclass
class Link:
    href: str
    text: str = ""
    source: str = "text"  # "html" (from an <a> tag) or "text" (plain-text body)

    @property
    def host(self) -> str:
        try:
            return (urlparse(self.href).hostname or "").lower()
        except ValueError:
            return ""


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    md5: str
    sha256: str
    content: bytes = field(default=b"", repr=False)


@dataclass
class ParsedEmail:
    path: str
    subject: str
    date: str
    from_name: str
    from_addr: str
    reply_to: str
    return_path: str
    message_id: str
    auth_results: list[str]
    received: list[str]
    received_ips: list[str]
    text_body: str
    html_body: str
    links: list[Link]
    attachments: list[Attachment]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def domain_of(address: str) -> str:
    """Return the domain part of an email address (lowercased)."""
    address = (address or "").strip().strip("<>").lower()
    return address.rsplit("@", 1)[1] if "@" in address else ""


def base_domain(host: str) -> str:
    """Approximate the registrable domain, e.g. mail.login.paypal.com -> paypal.com."""
    host = (host or "").lower().strip(".")
    if not host or IPV4_RE.fullmatch(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class _AnchorExtractor(HTMLParser):
    """Collect (href, visible text) pairs from <a> tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self._href, self._text = href.strip(), []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            text = " ".join("".join(self._text).split())
            self.links.append(Link(self._href, text, "html"))
            self._href = None


def _safe_text(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")


def _header(msg, name: str) -> str:
    value = msg.get(name)
    return str(value).strip() if value is not None else ""


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
def parse_email(path: str | Path) -> ParsedEmail:
    raw = Path(path).read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    from_name, from_addr = parseaddr(_header(msg, "From"))
    _, reply_to = parseaddr(_header(msg, "Reply-To"))
    _, return_path = parseaddr(_header(msg, "Return-Path"))

    # Authentication results (SPF / DKIM / DMARC)
    auth_results = [str(v) for v in msg.get_all("Authentication-Results", [])]
    for spf in msg.get_all("Received-SPF", []):
        verdict = str(spf).strip().split()[0] if str(spf).strip() else ""
        if verdict:
            auth_results.append(f"spf={verdict}")

    received = [" ".join(str(v).split()) for v in msg.get_all("Received", [])]
    received_ips = _dedupe(ip for r in received for ip in IPV4_RE.findall(r))

    # Walk MIME parts
    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        ctype = part.get_content_type()
        if filename or part.get_content_disposition() == "attachment":
            data = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=ctype,
                    size=len(data),
                    md5=hashlib.md5(data).hexdigest(),
                    sha256=hashlib.sha256(data).hexdigest(),
                    content=data,
                )
            )
        elif ctype == "text/plain":
            text_parts.append(_safe_text(part))
        elif ctype == "text/html":
            html_parts.append(_safe_text(part))

    text_body, html_body = "\n".join(text_parts), "\n".join(html_parts)

    # Links: HTML anchors first (they carry display text), then bare URLs
    links: list[Link] = []
    if html_body:
        extractor = _AnchorExtractor()
        try:
            extractor.feed(html_body)
        except Exception:
            pass
        links.extend(l for l in extractor.links if l.href.lower().startswith("http"))
    # Remove anchor elements before scanning HTML for bare URLs, so decoy
    # display text (e.g. "https://www.paypal.com") isn't mistaken for a real link.
    html_no_anchors = re.sub(r"<a\b.*?</a>", " ", html_body, flags=re.S | re.I)
    for body in (text_body, html_no_anchors):
        for url in URL_RE.findall(body):
            links.append(Link(url.rstrip(".,;:!?"), "", "text"))

    seen, unique_links = set(), []
    for link in links:
        if link.href not in seen:
            seen.add(link.href)
            unique_links.append(link)

    return ParsedEmail(
        path=str(path),
        subject=_header(msg, "Subject"),
        date=_header(msg, "Date"),
        from_name=from_name,
        from_addr=from_addr,
        reply_to=reply_to,
        return_path=return_path,
        message_id=_header(msg, "Message-ID"),
        auth_results=auth_results,
        received=received,
        received_ips=received_ips,
        text_body=text_body,
        html_body=html_body,
        links=unique_links,
        attachments=attachments,
    )
