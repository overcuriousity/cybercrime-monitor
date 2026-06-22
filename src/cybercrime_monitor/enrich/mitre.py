"""MITRE ATT&CK technique-ID extraction — a cheap, deterministic, token-free
signal alongside enrich/cve.py's CVE regex (issue #18). Write-ups and forum
posts often cite technique IDs directly (e.g. "T1190" for exploit-public-
-facing-application); this catches those mentions without spending any LLM
tokens, the same "regex backstop" reasoning as enrich/cve.py and
enrich/ioc.py.
"""
import re

# ATT&CK (Enterprise + Mobile + ICS) technique IDs are all "T" followed by
# 4 digits, with an optional ".NNN" sub-technique suffix (e.g. "T1059.001").
# No upper bound enforced — MITRE periodically adds new top-level IDs.
_MITRE_PATTERN = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b", re.IGNORECASE)


def extract_mitre_ids(*texts: str) -> list[str]:
    """Find all distinct ATT&CK technique ids across one or more text blobs
    (title, snippet, research findings, ...), normalized to uppercase, in
    first-seen order. Returns [] if none found."""
    seen: list[str] = []
    seen_set: set[str] = set()
    for text in texts:
        if not text:
            continue
        for match in _MITRE_PATTERN.finditer(text):
            technique_id = match.group(0).upper()
            if technique_id not in seen_set:
                seen_set.add(technique_id)
                seen.append(technique_id)
    return seen


def merge_mitre_ids(*lists: list[str]) -> list[str]:
    """Union multiple technique-id lists, normalized and deduplicated,
    first-seen order preserved — same convention as enrich/cve.merge_cve_ids."""
    seen: list[str] = []
    seen_set: set[str] = set()
    for lst in lists:
        for raw in lst or []:
            technique_id = str(raw).strip().upper()
            if technique_id and technique_id not in seen_set:
                seen_set.add(technique_id)
                seen.append(technique_id)
    return seen
