# PhishScan: Phishing Email Analyzer

<img src = "https://github.com/niha-v/Phishing-Email-Analyzer/blob/main/Phishing-email-graphic.jpg" width = 400>

A static analysis tool that triages suspicious emails (`.eml` files) the way a SOC analyst would. It parses headers, checks sender authentication, inspects links and attachments, scores the risk, and outputs defanged IOCs plus a ready-to-paste case report.

Built in pure Python with no third-party dependencies.


## Features

| Area | What it checks |
|---|---|
| **Authentication** | SPF, DKIM and DMARC results from `Authentication-Results` / `Received-SPF` |
| **Sender** | Return-Path and Reply-To mismatches (downgraded when DMARC passes), free-webmail reply addresses, brand impersonation in the display name or subject line, lookalike sender domains, Message-ID origin |
| **Links** | Anchor text vs. real destination, lookalike/typosquat domains (homoglyph + Levenshtein), raw IP URLs, URL shorteners, punycode, high-abuse TLDs, `@` obfuscation, HTTP |
| **Content** | Urgency and pressure language, requests for credentials, generic greetings, embedded forms and scripts |
| **Job scams** | Fees or payments requested from candidates, pushes to WhatsApp/Telegram, unsolicited offers and "congratulations", too-good-to-be-true perks, recruiting from free webmail |
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

A full Markdown case report is in [`example/phish_sample_report.md`](examples/phish_sample_report.md).

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
├── tools/
│   ├── split_mbox.py     # split a Gmail/Takeout .mbox export into .eml files
│   └── stats.py          # summarize a run, or compare two runs before/after
├── samples/              # safe test emails (fake domains, RFC 5737 documentation IPs)
├── example/             # sample generated report
└── tests/                # pytest suite
```


## How scoring works

| Severity | Points |
|---|---|
| High | 30 |
| Medium | 15 |
| Low | 5 |

Each distinct rule counts **once per email** at its highest severity, so an email with ten HTTP links is scored for "Unencrypted HTTP links" one time, not ten. Informational findings (for example, a Return-Path mismatch on mail that passed DMARC) are shown but add 0 points.

The score is capped at 100. **≥ 60** means Likely Phishing, **25–59** means Suspicious, and **< 25** means Likely Benign. Weights and thresholds are in `checks.py` and `analyzer.py`, so you can tune them against your own data.


## Testing on real email

Export a folder of email (for example, Gmail's Spam label via Google Takeout), then:

```bash
python3 tools/split_mbox.py Spam.mbox spam_eml
python3 analyze.py spam_eml/ --json results.json --summary
python3 tools/stats.py results.json
```

To measure the effect of a rule change, save the old results and compare:

```bash
python3 tools/stats.py results_old.json results_new.json
```

Keep real email out of version control; the `.gitignore` already excludes `*.mbox`, `spam_eml/`, and `results*.json`.


## Changelog

**v1.1**, tuned against a real-world set of 82 spam emails:
- Scoring counts each rule once per email, which stopped emails from being flagged just for having many HTTP tracking links
- Return-Path and Message-ID mismatches are informational when DMARC passes (normal for email service providers like SendGrid and Mailchimp)
- HTTP links consolidated into a single finding
- New job-scam detection category (fees, chat-app recruiting, unsolicited offers, free-webmail recruiters)
- Brand impersonation now checked in the subject line; brand list expanded with retail, delivery, and payment brands
- Stricter typo-distance for medium-length brand names to reduce false lookalike matches
- Added `tools/split_mbox.py` and `tools/stats.py`

**v1.0**: initial release


## Limitations

- Static analysis only: it doesn't detonate attachments or visit URLs. Pair it with a sandbox for dynamic analysis.
- The registrable-domain logic is a lightweight approximation, not the full Public Suffix List.
- Authentication results are read from headers added by the receiving server, so they're only as trustworthy as that server.
- Rule-based detection can miss novel techniques and will produce some false positives. Treat the verdict as triage, not a final answer.


## Disclaimer

For educational and defensive use. 
