"""DNS finding logic exercised directly with synthetic records (§11)."""

from __future__ import annotations

from webrecon.modules.dns.analysis import DnsData
from webrecon.modules.dns.module import DnsModule


def _findings(data: DnsData, host="example.com"):
    mod = DnsModule()
    result = mod.new_result()
    mod._build_findings(result, host, data)
    return {f.check_id for f in result.findings}


def test_missing_spf_when_mx_present() -> None:
    data = DnsData(records={"MX": ["10 mail.example.com."]})
    assert "dns.spf.missing" in _findings(data)


def test_permissive_spf() -> None:
    data = DnsData(records={"MX": ["10 mail."]}, spf="v=spf1 +all")
    checks = _findings(data)
    assert "dns.spf.permissive" in checks
    assert "dns.spf.missing" not in checks


def test_missing_dmarc_when_mx_present() -> None:
    data = DnsData(records={"MX": ["10 mail."]}, spf="v=spf1 -all")
    assert "dns.dmarc.missing" in _findings(data)


def test_dangling_cname_flagged() -> None:
    data = DnsData(records={"CNAME": ["gone.example.net."]}, dangling_cnames=["gone.example.net"])
    checks = _findings(data)
    assert "dns.cname.dangling" in checks


def test_no_mx_no_email_findings() -> None:
    # Without MX we don't nag about SPF/DMARC.
    checks = _findings(DnsData(records={"A": ["1.2.3.4"]}))
    assert "dns.spf.missing" not in checks and "dns.dmarc.missing" not in checks


def test_dangling_cname_is_potential_observation() -> None:
    mod = DnsModule()
    result = mod.new_result()
    mod._build_findings(result, "example.com",
                        DnsData(records={"CNAME": ["x."]}, dangling_cnames=["x"]))
    f = next(f for f in result.findings if f.check_id == "dns.cname.dangling")
    assert str(f.observation) == "potential"  # unproven — must not claim it exists
