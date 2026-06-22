from cybercrime_monitor.enrich import mitre as mitre_enrich


def test_extract_single_technique():
    text = "The actor gained initial access via T1190 (exploit public-facing application)."
    assert mitre_enrich.extract_mitre_ids(text) == ["T1190"]


def test_extract_subtechnique():
    text = "Execution observed via T1059.001 (PowerShell)."
    assert mitre_enrich.extract_mitre_ids(text) == ["T1059.001"]


def test_extract_multiple_distinct_first_seen_order():
    text = "Chain: T1190 then T1059.001 then T1078, with T1190 mentioned again later."
    assert mitre_enrich.extract_mitre_ids(text) == ["T1190", "T1059.001", "T1078"]


def test_extract_across_multiple_texts():
    found = mitre_enrich.extract_mitre_ids("title mentions T1110", "snippet mentions T1486")
    assert found == ["T1110", "T1486"]


def test_extract_none_found():
    assert mitre_enrich.extract_mitre_ids("just a regular incident report, no techniques cited") == []


def test_extract_normalizes_case():
    assert mitre_enrich.extract_mitre_ids("technique t1190 was used") == ["T1190"]


def test_extract_ignores_non_technique_tokens():
    # Not all "T" + digits strings are ATT&CK technique ids (must be T1xxx).
    text = "Order T2024 was shipped; unrelated to any technique."
    assert mitre_enrich.extract_mitre_ids(text) == []


def test_merge_dedupes_and_normalizes():
    merged = mitre_enrich.merge_mitre_ids(["T1190", "t1059.001"], ["T1190", "T1078"])
    assert merged == ["T1190", "T1059.001", "T1078"]


def test_merge_handles_empty_lists():
    assert mitre_enrich.merge_mitre_ids([], None, ["T1190"]) == ["T1190"]
