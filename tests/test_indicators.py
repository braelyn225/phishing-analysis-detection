from phishguard.indicators import extract_iocs, has_punycode


def test_extract_iocs():
    text = "Visit hxxp://example[.]com/login and hash d41d8cd98f00b204e9800998ecf8427e"
    iocs = extract_iocs(text)
    assert "http://example.com/login" in iocs.urls
    assert "example.com" in iocs.domains
    assert "d41d8cd98f00b204e9800998ecf8427e" in iocs.hashes


def test_punycode():
    assert has_punycode(["xn--paypa1-5ve.com"])
