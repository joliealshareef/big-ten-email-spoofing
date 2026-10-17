"""Offline tests for scanner.py using a fake DNS client."""
import scanner as s


class FakeDNS:
    def __init__(self, txt=None, mx=None):
        self._txt, self._mx = txt or {}, mx or {}
    def txt(self, name): return self._txt.get(name, [])
    def mx(self, name): return self._mx.get(name, [])


def scan(txt, mx=None, domain="ex.edu"):
    return s.scan_domain(FakeDNS(txt, mx), {"name": "Ex", "short": "Ex", "domain": domain, "state": "PA"})


def test_strong_domain():
    r = scan({"_dmarc.ex.edu": ["v=DMARC1; p=reject; rua=mailto:a@ex.edu"],
              "ex.edu": ["v=spf1 include:_spf.google.com -all", "google-site-verification=x"],
              "_spf.google.com": ["v=spf1 include:_netblocks.google.com ~all"],
              "_netblocks.google.com": ["v=spf1 ip4:1.2.3.0/24 ~all"],
              "_mta-sts.ex.edu": ["v=STSv1; id=1"], "_smtp._tls.ex.edu": ["v=TLSRPTv1; rua=mailto:t@ex.edu"],
              "default._bimi.ex.edu": ["v=BIMI1; l=https://ex.edu/logo.svg"]},
             {"ex.edu": [(1, "aspmx.l.google.com")]})
    assert r["error"] is None and r["score"] == 100 and r["grade"] == "A"
    assert r["verdict"] == "rejected" and r["spf"]["lookups"] == 2 and r["mx"]["provider"] == "Google Workspace"


def test_psu_like_monitor_only():
    r = scan({"_dmarc.ex.edu": ["v=DMARC1; p=none; fo=1; rua=mailto:a@ex.edu,mailto:b@vali.email"],
              "ex.edu": ["v=spf1 ip4:1.1.1.1 ~all"]},
             {"ex.edu": [(10, "ex-edu.mail.protection.outlook.com")]})
    assert r["dmarc"]["policy"] == "none" and r["dmarc"]["reporting"]
    assert r["score"] == 20 + 22 and r["grade"] == "D" and r["verdict"] == "not_blocked"
    assert r["mx"]["provider"] == "Microsoft 365"


def test_missing_everything():
    r = scan({})
    assert r["score"] == 0 and r["dmarc"]["policy"] == "missing" and r["spf"]["all"] == "missing"
    assert r["mx"]["provider"] == "None"


def test_quarantine_partial_pct_and_weak_subdomain():
    r = scan({"_dmarc.ex.edu": ["v=DMARC1; p=quarantine; pct=50; sp=none"],
              "ex.edu": ["v=spf1 mx -all"]})
    assert r["score"] == round(35 * .5) - 5 + 30
    assert r["verdict"] == "spam"


def test_spf_over_limit():
    txt = {"_dmarc.ex.edu": ["v=DMARC1; p=reject"],
           "ex.edu": ["v=spf1 " + " ".join(f"include:i{i}.ex.edu" for i in range(11)) + " -all"]}
    r = scan(txt)
    assert r["spf"]["lookups"] == 11 and r["spf"]["over_limit"]
    assert r["score"] == 50 + 8


def test_duplicate_spf_and_plus_all():
    r = scan({"ex.edu": ["v=spf1 -all", "v=spf1 ~all"]})
    assert r["spf"]["count"] == 2 and r["score"] == 0
    r2 = scan({"ex.edu": ["v=spf1 +all"]})
    assert r2["spf"]["all"] == "+" and r2["score"] == 0


def test_redirect_and_no_all():
    r = scan({"ex.edu": ["v=spf1 redirect=_spf.ex.edu"], "_spf.ex.edu": ["v=spf1 ip4:1.1.1.1 -all"]})
    assert r["spf"]["all"] == "-" and r["spf"]["lookups"] == 1
    r2 = scan({"ex.edu": ["v=spf1 ip4:1.1.1.1"]})
    assert r2["spf"]["all"] == "?"


def test_include_loop_terminates():
    r = scan({"ex.edu": ["v=spf1 include:a.ex.edu -all"], "a.ex.edu": ["v=spf1 include:ex.edu -all"]})
    assert r["spf"]["lookups"] == 2


def test_invalid_dmarc_policy():
    r = scan({"_dmarc.ex.edu": ["v=DMARC1; p=block"]})
    assert r["dmarc"]["policy"] == "invalid" and r["verdict"] == "not_blocked"


def test_a_term_not_confused_with_all():
    r = scan({"ex.edu": ["v=spf1 a mx ip4:1.1.1.1 -all"]})
    assert r["spf"]["lookups"] == 2


def test_grade_cutoffs():
    # reject + ~all, no extras = 72 -> B ; quarantine + ~all = 57 -> C
    r = scan({"_dmarc.ex.edu": ["v=DMARC1; p=reject"], "ex.edu": ["v=spf1 ip4:1.1.1.1 ~all"]})
    assert (r["score"], r["grade"]) == (72, "B")
    r = scan({"_dmarc.ex.edu": ["v=DMARC1; p=quarantine"], "ex.edu": ["v=spf1 ip4:1.1.1.1 ~all"]})
    assert (r["score"], r["grade"]) == (57, "C")
