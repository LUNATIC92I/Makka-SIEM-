import pytest

from app.services.indicators import classify_ip, extract_from_text, guess_type, refang, validate_indicator


@pytest.mark.parametrize("ip,scope", [
    ("154.73.112.25", "public"), ("8.8.8.8", "public"), ("10.1.2.3", "private"), ("172.16.5.4", "private"),
    ("192.168.1.1", "private"), ("127.0.0.1", "loopback"), ("169.254.169.254", "link_local"),
    ("100.64.1.1", "cgnat"), ("192.0.2.10", "documentation"), ("198.51.100.23", "documentation"),
    ("203.0.113.77", "documentation"), ("198.18.0.1", "benchmarking"), ("224.0.0.1", "multicast"),
    ("0.0.0.0", "unspecified"), ("240.0.0.1", "reserved"), ("::1", "loopback"), ("fe80::1", "link_local"),
    ("fd00::1", "private"), ("2001:db8::1", "documentation"), ("2606:4700:4700::1111", "public"),
    ("::ffff:10.0.0.1", "private"),
])
def test_ip_scope(ip, scope):
    assert classify_ip(ip)[0] == scope


@pytest.mark.parametrize("bad", ["256.1.1.1", "1.2.3", "abc", "1.2.3.4.5", "", "999::zz"])
def test_invalid_ip_rejected(bad):
    with pytest.raises(ValueError):
        validate_indicator("ipv4", bad)


def test_only_public_indicators_are_enrichable():
    assert validate_indicator("ipv4", "154.73.112.25").enrichable
    assert not validate_indicator("ipv4", "10.0.0.1").enrichable
    assert not validate_indicator("domain", "portal.example.com").enrichable  # RFC 2606
    assert not validate_indicator("domain", "malware.test").enrichable
    idn = validate_indicator("domain", "Exämple-Corp.FR").value
    assert idn.startswith("xn--") and idn.endswith(".fr") and idn.isascii()


def test_refang_and_extraction():
    text = ("Blocked hxxp://evil-site[.]com/path?a=1 from 154.73.112.25 to 10.0.0.5 ; "
            "hash 44d88612fea8a8f36de82e1278abb02f sha256 " + "a" * 64 + " file setup.exe log.txt")
    found = {(i.type, i.value) for i in extract_from_text(text)}
    assert ("url", "http://evil-site.com/path?a=1") in found
    assert ("domain", "evil-site.com") in found
    assert ("ipv4", "154.73.112.25") in found and ("ipv4", "10.0.0.5") in found
    assert ("md5", "44d88612fea8a8f36de82e1278abb02f") in found
    assert ("sha256", "a" * 64) in found
    assert not any(v in ("setup.exe", "log.txt") for _, v in found)
    assert refang("1.2.3[.]4") == "1.2.3.4"


def test_hash_validation_and_guess():
    assert guess_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert guess_type("2001:db8::1") == "ipv6"
    assert guess_type("https://a.b/c") == "url"
    with pytest.raises(ValueError):
        validate_indicator("sha1", "xyz")
    with pytest.raises(ValueError):
        validate_indicator("unknown", "x")
