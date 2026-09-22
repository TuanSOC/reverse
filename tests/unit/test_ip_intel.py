"""Unit tests for ip_intel analysis (ASN/Geo parsing, provider, exposure)."""

from __future__ import annotations

from webrecon.modules.ip_intel.analysis import (
    cdn_from_headers,
    classify_provider,
    cymru_origin_name,
    detect_origin_exposure,
    is_private_ip,
    parse_cymru_asname,
    parse_cymru_origin,
    parse_ipapi,
    reverse_pointer,
)


def test_is_private_ip() -> None:
    assert is_private_ip("127.0.0.1")
    assert is_private_ip("10.0.0.5")
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("::1")
    assert not is_private_ip("104.16.0.1")
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("not-an-ip")


def test_reverse_pointer_and_cymru_name() -> None:
    assert reverse_pointer("1.2.3.4") == "4.3.2.1.in-addr.arpa"
    assert cymru_origin_name("1.2.3.4") == "4.3.2.1.origin.asn.cymru.com"
    assert cymru_origin_name("::1").endswith(".origin6.asn.cymru.com")
    assert cymru_origin_name("bad") is None


def test_parse_cymru_origin() -> None:
    o = parse_cymru_origin('"13335 | 104.16.0.0/12 | US | arin | 2010-07-14"')
    assert o["asn"] == "13335"
    assert o["prefix"] == "104.16.0.0/12"
    assert o["country_code"] == "US"
    assert o["registry"] == "arin"


def test_parse_cymru_asname() -> None:
    a = parse_cymru_asname('"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"')
    assert a["asn"] == "13335"
    assert a["as_name"] == "CLOUDFLARENET, US"


def test_parse_ipapi_success_and_fail() -> None:
    g = parse_ipapi({
        "status": "success", "country": "United States", "countryCode": "US",
        "regionName": "California", "city": "San Francisco", "lat": 37.77,
        "lon": -122.4, "timezone": "America/Los_Angeles", "isp": "Cloudflare",
        "org": "Cloudflare", "as": "AS13335 Cloudflare, Inc.",
    })
    assert g["country_code"] == "US"
    assert g["city"] == "San Francisco"
    assert g["latitude"] == 37.77 and g["longitude"] == -122.4
    assert g["timezone"] == "America/Los_Angeles"
    assert parse_ipapi({"status": "fail", "message": "reserved range"}) == {}


def test_classify_provider() -> None:
    assert classify_provider("CLOUDFLARENET, US") == "Cloudflare"
    assert classify_provider(None, "Amazon.com, Inc.") == "AWS"
    assert classify_provider("GOOGLE") == "GCP"
    assert classify_provider("MICROSOFT-CORP-MSN-AS-BLOCK") == "Azure"
    assert classify_provider("AKAMAI-AS") == "Akamai"
    assert classify_provider("DIGITALOCEAN-ASN") == "DigitalOcean"
    assert classify_provider("OVH SAS") is None


def test_cdn_from_headers() -> None:
    assert cdn_from_headers({"CF-RAY": "abc-SIN", "Server": "cloudflare"}) == "Cloudflare"
    assert cdn_from_headers({"Server": "cloudflare"}) == "Cloudflare"
    assert cdn_from_headers({"X-Amz-Cf-Id": "xyz"}) == "CloudFront"
    assert cdn_from_headers({"Server": "nginx"}) is None


def test_detect_origin_exposure() -> None:
    # edge is Cloudflare but the resolved IP is on DigitalOcean → exposed origin
    assert detect_origin_exposure("Cloudflare", "DigitalOcean") is True
    assert detect_origin_exposure("Cloudflare", None) is True  # unknown network
    # edge Cloudflare + IP also Cloudflare → normal, not exposed
    assert detect_origin_exposure("Cloudflare", "Cloudflare") is False
    # no CDN on the edge → nothing to expose
    assert detect_origin_exposure(None, "DigitalOcean") is False
