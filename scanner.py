"""
Email Spoofing Protection Scanner
Author: Jolie Alshareef

Checks the public DNS records that protect a domain against email spoofing
(DMARC, SPF, MTA-STS, TLS-RPT, BIMI, MX) and grades each domain.

Everything here is a normal, passive DNS lookup: the same public records any
mail server reads before delivering a message. Nothing is sent to the domains.

Usage:
    pip install dnspython
    python scanner.py                      # scans domains.csv -> scan_results.json
    python scanner.py --csv other.csv --out other.json
"""
import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SPF_LOOKUP_LIMIT = 10          # RFC 7208 section 4.6.4
MAX_SPF_DEPTH = 10


# --------------------------------------------------------------------------
# DNS layer (swappable so the logic can be tested without a network)
# --------------------------------------------------------------------------
class DNSClient:
    def __init__(self, nameserver=None, timeout=5.0):
        import dns.resolver
        self._dns = dns
        self.r = dns.resolver.Resolver()
        if nameserver:
            self.r.nameservers = [nameserver]
        self.r.timeout = timeout
        self.r.lifetime = timeout * 2

    def txt(self, name):
        """List of TXT strings, [] if the name has no TXT records."""
        try:
            ans = self.r.resolve(name, "TXT")
        except (self._dns.resolver.NXDOMAIN, self._dns.resolver.NoAnswer,
                self._dns.resolver.NoNameservers):
            return []
        return [b"".join(rd.strings).decode("utf-8", "replace") for rd in ans]

    def mx(self, name):
        """List of (preference, host) tuples, [] if none."""
        try:
            ans = self.r.resolve(name, "MX")
        except (self._dns.resolver.NXDOMAIN, self._dns.resolver.NoAnswer,
                self._dns.resolver.NoNameservers):
            return []
        return sorted((rd.preference, str(rd.exchange).rstrip(".").lower()) for rd in ans)


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------
def parse_tags(record):
    """'v=DMARC1; p=none; rua=mailto:x' -> {'v': 'DMARC1', 'p': 'none', ...}"""
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_dmarc(dns_client, domain):
    records = [t for t in dns_client.txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    out = {"record": records[0] if records else None, "count": len(records)}
    if len(records) != 1:
        out.update(policy="missing" if not records else "invalid (multiple records)",
                   valid=False)
        return out
    tags = parse_tags(records[0])
    policy = tags.get("p", "").lower()
    if policy not in ("none", "quarantine", "reject"):
        out.update(policy="invalid", valid=False)
        return out
    try:
        pct = int(tags.get("pct", "100"))
    except ValueError:
        pct = 100
    out.update(
        valid=True,
        policy=policy,
        subdomain_policy=tags.get("sp", policy).lower(),
        pct=max(0, min(100, pct)),
        reporting=("rua" in tags),
        adkim=tags.get("adkim", "r"),
        aspf=tags.get("aspf", "r"),
    )
    return out


SPF_LOOKUP_TERMS = re.compile(r"^[+\-~?]?(include:|a\b|a:|a/|mx\b|mx:|mx/|ptr|exists:)", re.I)


def spf_record(dns_client, domain):
    return [t for t in dns_client.txt(domain) if t.lower().startswith("v=spf1")]


def count_spf_lookups(dns_client, domain, depth=0, seen=None):
    """Count DNS-querying terms, following include: and redirect= recursively."""
    seen = seen if seen is not None else set()
    if depth > MAX_SPF_DEPTH or domain in seen:
        return 0
    seen.add(domain)
    recs = spf_record(dns_client, domain)
    if len(recs) != 1:
        return 0
    total = 0
    for term in recs[0].split()[1:]:
        low = term.lower()
        if SPF_LOOKUP_TERMS.match(low):
            total += 1
            if low.lstrip("+-~?").startswith("include:"):
                total += count_spf_lookups(dns_client, term.split(":", 1)[1], depth + 1, seen)
        elif low.startswith("redirect="):
            total += 1
            total += count_spf_lookups(dns_client, term.split("=", 1)[1], depth + 1, seen)
    return total


def check_spf(dns_client, domain):
    recs = spf_record(dns_client, domain)
    out = {"record": recs[0] if recs else None, "count": len(recs)}
    if not recs:
        out.update(valid=False, all="missing")
        return out
    if len(recs) > 1:
        out.update(valid=False, all="invalid (multiple records)")
        return out
    terms = recs[0].split()
    all_term = next((t for t in terms if t.lower().lstrip("+-~?") == "all"), None)
    redirect = next((t for t in terms if t.lower().startswith("redirect=")), None)
    if all_term:
        q = all_term[0] if all_term[0] in "+-~?" else "+"
    elif redirect:
        target = spf_record(dns_client, redirect.split("=", 1)[1])
        q = "redirect"
        if len(target) == 1:
            t_all = next((t for t in target[0].split() if t.lower().lstrip("+-~?") == "all"), None)
            if t_all:
                q = t_all[0] if t_all[0] in "+-~?" else "+"
    else:
        q = "?"   # no all mechanism = neutral by default
    lookups = count_spf_lookups(dns_client, domain)
    out.update(valid=lookups <= SPF_LOOKUP_LIMIT, all=q, lookups=lookups,
               over_limit=lookups > SPF_LOOKUP_LIMIT)
    return out


PROVIDERS = [
    ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
    ("protection.outlook.com", "Microsoft 365"), ("outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint"), ("ppe-hosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"), ("iphmx.com", "Cisco Secure Email"),
    ("barracudanetworks.com", "Barracuda"), ("messagelabs.com", "Broadcom"),
]


def check_mx(dns_client, domain):
    hosts = [h for _, h in dns_client.mx(domain)]
    provider = "None" if not hosts else "Self-hosted / other"
    for suffix, name in PROVIDERS:
        if any(h == suffix or h.endswith("." + suffix) for h in hosts):
            provider = name
            break
    return {"hosts": hosts[:5], "provider": provider}


def check_extras(dns_client, domain):
    mta = [t for t in dns_client.txt(f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
    tls = [t for t in dns_client.txt(f"_smtp._tls.{domain}") if t.lower().startswith("v=tlsrptv1")]
    bimi = [t for t in dns_client.txt(f"default._bimi.{domain}") if t.lower().startswith("v=bimi1")]
    return {"mta_sts": bool(mta), "tls_rpt": bool(tls), "bimi": bool(bimi)}


# --------------------------------------------------------------------------
# Grading (rubric is shown on the website so anyone can check it)
# --------------------------------------------------------------------------
def score(d):
    pts, notes = 0, []
    dm, spf, ex = d["dmarc"], d["spf"], d["extras"]

    # DMARC: 50 points
    if not dm["valid"]:
        notes.append("No valid DMARC record: receivers get no instruction to block spoofed mail.")
    elif dm["policy"] == "none":
        pts += 15 + (5 if dm["reporting"] else 0)
        notes.append("DMARC is set to monitor only (p=none): spoofed mail is reported, not blocked.")
    else:
        base = 35 if dm["policy"] == "quarantine" else 50
        pts += round(base * dm["pct"] / 100) if dm["pct"] < 100 else base
        if dm["pct"] < 100:
            notes.append(f"DMARC policy applies to only {dm['pct']}% of failing mail.")
        if dm["subdomain_policy"] == "none":
            pts -= 5
            notes.append("Subdomains are left at p=none, so they can still be spoofed.")

    # SPF: 30 points
    q = spf["all"]
    if not spf["record"] or spf["count"] > 1:
        notes.append("SPF record is missing or duplicated, so SPF checks fail.")
    else:
        pts += {"-": 30, "~": 22, "?": 10, "+": 0, "redirect": 15}.get(q, 0)
        if q == "+":
            notes.append("SPF ends in +all, which authorizes every server on the internet.")
        if spf.get("over_limit"):
            pts = pts - {"-": 30, "~": 22, "?": 10, "+": 0, "redirect": 15}.get(q, 0) + 8
            notes.append(f"SPF needs {spf['lookups']} DNS lookups (limit is 10), which makes it fail.")

    # Transport and brand extras: 20 points
    pts += 10 if ex["mta_sts"] else 0
    pts += 5 if ex["tls_rpt"] else 0
    pts += 5 if ex["bimi"] else 0

    pts = max(0, min(100, pts))
    grade = "A" if pts >= 85 else "B" if pts >= 70 else "C" if pts >= 55 else "D" if pts >= 40 else "F"
    return pts, grade, notes


def verdict(dm):
    """Plain-English answer to: what happens to a forged email from this domain?"""
    if not dm["valid"] or dm["policy"] == "none":
        return "not_blocked"
    if dm["policy"] == "quarantine":
        return "spam"
    return "rejected" if dm["pct"] == 100 else "partly_rejected"


def scan_domain(dns_client, row):
    domain = row["domain"].strip().lower()
    result = {**row, "domain": domain}
    try:
        result["dmarc"] = check_dmarc(dns_client, domain)
        result["spf"] = check_spf(dns_client, domain)
        result["mx"] = check_mx(dns_client, domain)
        result["extras"] = check_extras(dns_client, domain)
        result["score"], result["grade"], result["notes"] = score(result)
        result["verdict"] = verdict(result["dmarc"])
        result["error"] = None
    except Exception as e:  # timeouts, SERVFAIL: record it rather than guess
        result["error"] = f"{type(e).__name__}: {e}"
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", default="domains.csv")
    ap.add_argument("--out", default="scan_results.json")
    ap.add_argument("--title", default="Big Ten Conference")
    ap.add_argument("--nameserver", default=None, help="e.g. 1.1.1.1 (default: your system resolver)")
    args = ap.parse_args(argv)

    rows = list(csv.DictReader(open(args.csv, newline="", encoding="utf-8")))
    client = DNSClient(args.nameserver)
    results = []
    for row in rows:
        r = scan_domain(client, row)
        results.append(r)
        if r["error"]:
            print(f"  !! {r['domain']:<20} {r['error']}")
        else:
            print(f"  {r['grade']}  {r['score']:>3}  {r['domain']:<20} DMARC={r['dmarc']['policy']:<10} SPF={r['spf']['all']}")

    failed = [r for r in results if r["error"]]
    out = {
        "title": args.title,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "resolver": args.nameserver or "system default",
        "scanner_version": "1.0",
        "sample_data": False,
        "domains": results,
    }
    Path(args.out).write_text(json.dumps(out, indent=1))
    print(f"\nSaved {len(results)} results to {args.out}" + (f" ({len(failed)} failed, rerun later)" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
