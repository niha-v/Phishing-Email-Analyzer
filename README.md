# PhishScan: Phishing Email Analyzer

A static analysis tool that triages suspicious emails (`.eml` files) the way a SOC analyst would. It parses headers, checks sender authentication, inspects links and attachments, scores the risk, and outputs defanged IOCs plus a ready-to-paste case report.

Built in pure Python with no third-party dependencies.

## Features

| Area | What it checks |
|---|---|
| **Authentication** | SPF, DKIM, and DMARC results from `Authentication-Results` / `Received-SPF` |
| **Sender** | Return-Path and Reply-To mismatches, free-webmail reply addresses, display-name brand impersonation, lookalike sender domains, Message-ID origin |
| **Links** | Anchor text vs. real destination, lookalike/typosquat domains (homoglyph + Levenshtein), raw IP URLs, URL shorteners, punycode, high-abuse TLDs, `@` obfuscation, HTTP |
| **Content** | Urgency and pressure language, requests for credentials, generic greetings, embedded forms and scripts |
| **Attachments** | Double extensions (`invoice.pdf.html`), executables, macro-enabled Office files, HTML smuggling / credential forms, archives, MD5/SHA256 hashing |

Each finding carries a severity (low / medium / high) that feeds a 0–100 risk score and a verdict: **Likely Benign**, **Suspicious**, or **Likely Phishing**.

## Quick start

```bash
git clone https://github.com/<your-username>/phishscan.git
cd phishscan

# Analyze one email
python analyze.py samples/phish_sample.eml

# Triage a whole folder: one line per email
python analyze.py samples/ --summary

# Export JSON (for a SIEM/SOAR) and Markdown case reports (for a ticket)
python analyze.py samples/ --json results.json --report-dir reports/
```

Requires Python 3.9+. To run the tests: `pip install pytest && pytest`.

To export an email for analysis: in Outlook, drag the message to your desktop or use *File → Save As*; in Gmail, use *⋮ → Download message*.

## Example output

```
 Verdict     : LIKELY PHISHING   (risk score 100/100)
 Subject     : URGENT: Your account has been suspended - Action Required
 From        : "PayPal Security Team" <security@paypa1-support.com>
 Reply-To    : paypal.verify.center@gmail.com

 Authentication
   SPF: fail  |  DKIM: none  |  DMARC: fail

 Findings (20)
   [HIGH  ] DMARC fail  (authentication)
   [HIGH  ] Brand impersonation in display name  (sender)
   [HIGH  ] Link text doesn't match destination  (links)
             Displays 'https://www.paypal.com/signin' but actually opens
             http://paypa1-secure.xyz/login.php?id=88213
   [HIGH  ] Double file extension  (attachments)
   ...

 Indicators of Compromise (defanged)
   URLs:
     - hxxp://paypa1-secure[.]xyz/login.php?id=88213
     - hxxps://bit[.]ly/3xYzAbC
   Attachments:
     - Invoice_4471.pdf.html
       SHA256 c9e6227e3693fcc19f948a2ee1bbcb4647aaddb7691d6c17c31a774c99bb2f61
```

A full Markdown case report is in [`examples/phish_sample_report.md`](examples/phish_sample_report.md).

```
$ python analyze.py samples/ --summary
LIKELY BENIGN      0/100  legit_sample.eml       |  [GitHub] A new SSH key was added to your account
LIKELY PHISHING  100/100  phish_sample.eml       |  URGENT: Your account has been suspended - Action Required
SUSPICIOUS        35/100  suspicious_sample.eml  |  Payment overdue - invoice #20931
```

## Project structure

```
phishscan/
├── analyze.py            # CLI entry point
├── phishscan/
│   ├── parser.py         # .eml → structured data (headers, bodies, links, attachments)
│   ├── checks.py         # detection rules and reference lists (brands, TLDs, extensions)
│   ├── analyzer.py       # runs checks, scores risk, extracts IOCs
│   └── report.py         # console, JSON, and Markdown output; defanging
├── samples/              # safe test emails (fake domains, RFC 5737 documentation IPs)
├── examples/             # sample generated report
└── tests/                # pytest suite
```

## How scoring works

| Severity | Points |
|---|---|
| High | 30 |
| Medium | 15 |
| Low | 5 |

The score is capped at 100. **≥ 60** means Likely Phishing, **25–59** means Suspicious, and **< 25** means Likely Benign. Weights and thresholds are in `checks.py` and `analyzer.py`, so you can tune them against your own data.

## Limitations

- Static analysis only: it doesn't detonate attachments or visit URLs. Pair it with a sandbox for dynamic analysis.
- The registrable-domain logic is a lightweight approximation, not the full Public Suffix List.
- Authentication results are read from headers added by the receiving server, so they're only as trustworthy as that server.
- Rule-based detection can miss novel techniques and will produce some false positives. Treat the verdict as triage, not a final answer.

## Roadmap

- [ ] QR code extraction and decoding from image attachments (quishing)
- [ ] Full Public Suffix List support via `tldextract`
- [ ] Threat-intel enrichment (VirusTotal, URLScan.io, AbuseIPDB)
- [ ] Parse `.msg` (Outlook) files
- [ ] Web UI (Flask) for drag-and-drop analysis

## Disclaimer

For educational and defensive use. The sample emails use fictional domains and RFC 5737 documentation IP ranges.
