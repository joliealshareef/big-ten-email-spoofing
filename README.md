# Big Ten Email Spoofing Report

Which Big Ten universities tell the world's inboxes to block email that forges their domain?

This project scans the public DNS records that protect against email spoofing (**DMARC, SPF, MTA-STS, TLS-RPT, BIMI** and MX) for all 18 Big Ten universities, grades each school on a published 100-point rubric, and presents the results as an interactive report.

**Live report:** https://joliealshareef.github.io/big-ten-email-spoofing/
**Author:** Jolie Alshareef · B.S. Cybersecurity Analytics & Operations, Penn State

## Why it matters

Anyone can put any address in an email's `From:` line. Phishing emails that claim to come from a university president, registrar or IT help desk are one of the most common ways student and staff accounts get compromised. DMARC lets a domain owner tell receiving mail servers to **reject** or **quarantine** messages that fail authentication. A domain at `p=none` only asks for reports, so the decision is left to each receiver.

## How it works

```
domains.csv ──► scanner.py ──► scan_results.json ──► build_site.py ──► index.html
               (DNS lookups)    (raw records +        (injects data
                                 grades)               into template)
```

For each domain the scanner:

| Check | DNS query | What it looks for |
|---|---|---|
| DMARC | `TXT _dmarc.<domain>` | Policy (`p`), subdomain policy (`sp`), `pct`, reporting (`rua`) |
| SPF | `TXT <domain>` | Final `all` qualifier, duplicates, recursive DNS lookup count (RFC 7208 limit of 10) |
| MX | `MX <domain>` | Mail provider (Google, Microsoft 365, Proofpoint, ...) |
| MTA-STS | `TXT _mta-sts.<domain>` | Enforced TLS for inbound mail |
| TLS-RPT | `TXT _smtp._tls.<domain>` | TLS failure reporting |
| BIMI | `TXT default._bimi.<domain>` | Verified brand logo |

### Grading (100 points)

| Area | Points |
|---|---|
| DMARC | reject 50 · quarantine 35 · none with reports 20 · none 15 · missing 0 · scaled by `pct` · −5 if `sp=none` |
| SPF | `-all` 30 · `~all` 22 · redirect 15 · `?all` 10 · over 10 lookups 8 · `+all`/missing/duplicate 0 |
| Extras | MTA-STS 10 · TLS-RPT 5 · BIMI 5 |

A ≥ 85 · B ≥ 70 · C ≥ 55 · D ≥ 40 · F < 40

## Run it

```bash
python3 -m pip install dnspython
python3 scanner.py          # writes scan_results.json
python3 build_site.py       # writes index.html
python3 -m pytest           # optional: 11 offline tests with a fake resolver
```

Scan any other list of domains by pointing it at a different CSV with `name,short,domain,state` columns:

```bash
python3 scanner.py --csv my_list.csv --out my_results.json --title "My List"
python3 build_site.py --data my_results.json
```

## Ethics and limits

- **Passive only.** Every check is an ordinary DNS lookup of public records that mail servers read for every message. No email is sent and no school system is touched.
- **A low grade isn't a breach.** Gmail and Outlook run their own filtering, so many forged messages get caught even at `p=none`.
- **DKIM isn't checked.** DKIM keys live under selector names only the domain owner knows.
- **Snapshot.** Results reflect the scan date shown on the report.

## Files

| File | Purpose |
|---|---|
| `scanner.py` | DNS checks, SPF lookup counting, grading |
| `test_scanner.py` | Offline unit tests covering every grading rule |
| `domains.csv` | The 18 Big Ten universities and their primary email domains |
| `scan_results.json` | Raw records and grades from the latest scan |
| `site_template.html` | Report website (HTML/CSS/JS, no frameworks) |
| `build_site.py` | Injects scan results into the template |
| `index.html` | The built report |
