"""Curated, offline known-vulnerable-version database for common libraries.

This is NOT a live CVE feed — it is a small, hand-curated set of well-known
"upgrade past this version" advisories for widely fingerprinted libraries. It
lets the security engine flag a *reliably detected* version that is below a
known-fixed version, with a reference. Conservative by design: only fires when
the technology module reports a concrete version at medium+ confidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...core.enums import Severity


@dataclass(frozen=True)
class KnownVuln:
    fixed_in: tuple[int, ...]  # versions strictly below this are affected
    severity: Severity
    summary: str
    reference: str


# name (as emitted by the technology module) -> advisories
KNOWN_VULNS: dict[str, tuple[KnownVuln, ...]] = {
    "jQuery": (
        KnownVuln((3, 5, 0), Severity.MEDIUM,
                  "XSS via jQuery.htmlPrefilter (CVE-2020-11022 / CVE-2020-11023)",
                  "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"),
        KnownVuln((3, 0, 0), Severity.MEDIUM,
                  "Multiple XSS/selector issues fixed in 3.x",
                  "https://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/"),
    ),
    "jQuery UI": (
        KnownVuln((1, 13, 2), Severity.MEDIUM,
                  "XSS in datepicker/checkboxradio (CVE-2022-31160)",
                  "https://nvd.nist.gov/vuln/detail/CVE-2022-31160"),
    ),
    "Bootstrap": (
        KnownVuln((3, 4, 0), Severity.MEDIUM,
                  "XSS in data-target/data-template (CVE-2018-14041 et al.)",
                  "https://nvd.nist.gov/vuln/detail/CVE-2018-14041"),
        KnownVuln((4, 3, 1), Severity.MEDIUM,
                  "XSS in tooltip/popover data-template (CVE-2019-8331)",
                  "https://nvd.nist.gov/vuln/detail/CVE-2019-8331"),
    ),
    "Lodash": (
        KnownVuln((4, 17, 21), Severity.HIGH,
                  "Prototype pollution / command injection (CVE-2021-23337, CVE-2020-8203)",
                  "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"),
    ),
    "Moment.js": (
        KnownVuln((2, 29, 4), Severity.MEDIUM,
                  "Path traversal / ReDoS (CVE-2022-31129, CVE-2022-24785)",
                  "https://nvd.nist.gov/vuln/detail/CVE-2022-31129"),
    ),
    "Angular": (
        KnownVuln((1, 8, 0), Severity.MEDIUM,
                  "AngularJS 1.x is end-of-life; multiple XSS/sandbox issues",
                  "https://docs.angularjs.org/misc/version-support-status"),
    ),
    "Vue.js": (
        KnownVuln((2, 7, 0), Severity.MEDIUM,
                  "Vue 2 < 2.7 ReDoS / XSS in template compiler; 2.x is EOL",
                  "https://github.com/vuejs/vue"),
    ),
    "Axios": (
        KnownVuln((1, 6, 0), Severity.HIGH,
                  "SSRF / credential leak on redirect (CVE-2023-45857)",
                  "https://nvd.nist.gov/vuln/detail/CVE-2023-45857"),
        KnownVuln((0, 21, 1), Severity.HIGH,
                  "SSRF via follow-redirects (CVE-2020-28168)",
                  "https://nvd.nist.gov/vuln/detail/CVE-2020-28168"),
    ),
    "PHP": (
        KnownVuln((7, 4, 0), Severity.MEDIUM,
                  "PHP < 7.4 is end-of-life (no security fixes)",
                  "https://www.php.net/supported-versions.php"),
    ),
}
