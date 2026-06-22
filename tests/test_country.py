from cybercrime_monitor.country import country_name, normalize_country


def test_alpha2_passthrough_any_case():
    assert normalize_country("DE") == "DE"
    assert normalize_country("de") == "DE"
    assert normalize_country("Mn") == "MN"


def test_full_name_to_code():
    assert normalize_country("Germany") == "DE"
    assert normalize_country("germany") == "DE"
    assert normalize_country("  Mongolia  ") == "MN"


def test_aliases():
    assert normalize_country("UK") == "GB"
    assert normalize_country("USA") == "US"
    assert normalize_country("Russia") == "RU"
    assert normalize_country("South Korea") == "KR"
    assert normalize_country("UAE") == "AE"


def test_unrecognized_returns_none():
    assert normalize_country("Atlantis") is None
    assert normalize_country("???") is None


def test_empty_and_none():
    assert normalize_country(None) is None
    assert normalize_country("") is None
    assert normalize_country("   ") is None


def test_country_name_lookup():
    assert country_name("DE") == "Germany"
    assert country_name("mn") == "Mongolia"
    assert country_name(None) is None
    assert country_name("ZZ") is None
