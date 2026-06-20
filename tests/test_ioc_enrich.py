from cybercrime_monitor.enrich import ioc as ioc_enrich


def test_extract_ipv4():
    text = "The C2 server was hosted at 192.168.10.5 during the campaign."
    assert ioc_enrich.extract_iocs(text) == ["192.168.10.5"]


def test_extract_defanged_ipv4():
    text = "Beacon traffic observed to 1[.]2[.]3[.]4 and 5(.)6(.)7(.)8."
    found = ioc_enrich.extract_iocs(text)
    assert "1.2.3.4" in found
    assert "5.6.7.8" in found


def test_extract_btc_address():
    text = "Ransom demanded to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq."
    found = ioc_enrich.extract_iocs(text)
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in found
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in found


def test_extract_eth_address():
    text = "Funds moved to 0x1234567890abcdef1234567890abcdef12345678 shortly after."
    assert ioc_enrich.extract_iocs(text) == ["0x1234567890abcdef1234567890abcdef12345678"]


def test_extract_onion_v3():
    text = "Leak site: http://lockbitapt2d73krlbewgv27tquljgxr2eolge4tj2qstgbdczgzkqyd.onion/"
    found = ioc_enrich.extract_iocs(text)
    assert any(v.endswith(".onion") for v in found)


def test_extract_hashes():
    text = (
        "SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 "
        "MD5: 5d41402abc4b2a76b9719d911017c592"
    )
    found = ioc_enrich.extract_iocs(text)
    assert "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" in found
    assert "5d41402abc4b2a76b9719d911017c592" in found


def test_extract_iocs_dedupes_case_insensitively():
    text = "Hash ABCDEF1234567890ABCDEF1234567890 and abcdef1234567890abcdef1234567890 repeated."
    found = ioc_enrich.extract_iocs(text)
    assert len(found) == 1


def test_extract_iocs_empty_for_clean_text():
    assert ioc_enrich.extract_iocs("Just a regular news headline about a breach.") == []
    assert ioc_enrich.extract_iocs("", None) == []


def test_merge_iocs_unions_and_dedupes_preserving_order():
    merged = ioc_enrich.merge_iocs(["1.2.3.4", "Hash1"], ["hash1", "5.6.7.8"])
    assert merged == ["1.2.3.4", "Hash1", "5.6.7.8"]


def test_merge_iocs_caps_at_fifty():
    many = [f"1.2.3.{i}" for i in range(60)]
    merged = ioc_enrich.merge_iocs(many)
    assert len(merged) == 50
