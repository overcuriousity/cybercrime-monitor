"""CVE identifier extraction — a cheap, deterministic backstop alongside the
LLM extraction layer's cve_ids field (see llm/backend.py). Regex catches CVE
mentions the model might drop or that show up in items processed before the
LLM layer existed (e.g. via a future backfill).
"""
import re

# Official CVE ID syntax: CVE-YYYY-NNNN+ (4+ digit sequence number, no upper
# bound — see cve.org's ID syntax spec).
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def extract_cve_ids(*texts: str) -> list[str]:
    """Find all distinct CVE ids across one or more text blobs (title,
    snippet, LLM reasoning, ...), normalized to uppercase, in first-seen
    order. Returns [] if none found."""
    seen: list[str] = []
    seen_set: set[str] = set()
    for text in texts:
        if not text:
            continue
        for match in _CVE_PATTERN.finditer(text):
            cve_id = match.group(0).upper()
            if cve_id not in seen_set:
                seen_set.add(cve_id)
                seen.append(cve_id)
    return seen


def merge_cve_ids(*lists: list[str]) -> list[str]:
    """Union multiple cve_ids lists (e.g. LLM-extracted + regex-extracted),
    normalized and deduplicated, first-seen order preserved."""
    seen: list[str] = []
    seen_set: set[str] = set()
    for lst in lists:
        for raw in lst or []:
            cve_id = str(raw).strip().upper()
            if cve_id and cve_id not in seen_set:
                seen_set.add(cve_id)
                seen.append(cve_id)
    return seen
