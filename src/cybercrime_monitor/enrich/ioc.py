"""Indicator-of-compromise extraction — a cheap, deterministic backstop
alongside the LLM extraction layer's iocs field (see llm/backend.py and
research/agent.py), mirroring enrich/cve.py's CVE regex backstop.

Deliberately scoped to indicator *types* that are unambiguous from pattern
alone: cryptocurrency addresses, IPv4/IPv6 addresses, onion v3 addresses,
and file hashes. Domains/URLs are NOT regex-extracted here — a news article
links to dozens of unrelated domains, so "looks like a domain" is far too
noisy a signal; domain/URL IoCs are left to the LLM's judgment, which can
tell a leak-site URL from a citation link.

Malware write-ups (BleepingComputer, The DFIR Report, vendor threat-intel
blogs) routinely defang indicators so they aren't clickable/live —
"1[.]2[.]3[.]4", "1(.)2(.)3(.)4" — so text is refanged before matching.
"""
import ipaddress
import re

_DEFANG_DOT = re.compile(r"\[\.\]|\(\.\)")


def _refang(text: str) -> str:
    return _DEFANG_DOT.sub(".", text)


# IPv4/IPv6 — deliberately permissive *candidate* patterns (e.g. the IPv4
# one accepts any \d{1,3} octet, including out-of-range ones like "999", and
# the IPv6 one accepts plain hex:colon runs without fully encoding "::"
# compression rules). Precision is enforced afterwards in extract_iocs via
# ipaddress.ip_address() — much less error-prone than a hand-rolled regex
# trying to fully encode RFC 4291, and it rejects both invalid IPv4 octets
# and IPv6-shaped non-addresses (e.g. a 6-group MAC-like token) in one place.
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_IP_PATTERNS = {_IPV4_PATTERN, _IPV6_PATTERN}
# Bitcoin: legacy base58 (1.../3...) and bech32 (bc1...).
_BTC_PATTERN = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,90})\b")
# Ethereum (and any EVM chain reusing the same address format): 0x + 40 hex.
_ETH_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
# Monero: standard (4...) or integrated/subaddress (8...) form, 95 base58 chars.
_XMR_PATTERN = re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}\b")
# Tor v3 hidden-service address: 56 base32 chars + .onion.
_ONION_PATTERN = re.compile(r"\b[a-z2-7]{56}\.onion\b", re.IGNORECASE)
# File hashes — longest first so 32/40-char patterns can't fire on a
# substring (moot in practice: \b requires a non-hex boundary on both sides,
# which a same-alphabet substring inside a longer hex blob never has, but
# checking longest-first keeps the type label assignment unambiguous too).
_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")

_PATTERNS = [
    _IPV4_PATTERN,
    _IPV6_PATTERN,
    _ONION_PATTERN,
    _BTC_PATTERN,
    _ETH_PATTERN,
    _XMR_PATTERN,
    _SHA256_PATTERN,
    _SHA1_PATTERN,
    _MD5_PATTERN,
]


def extract_iocs(*texts: str) -> list[str]:
    """Find all distinct high-precision IoCs across one or more text blobs
    (title, snippet, write-up excerpt, ...), in first-seen order. Returns
    [] if none found. Each text is refanged before matching so defanged
    indicators in technical write-ups are still caught."""
    seen: list[str] = []
    seen_set: set[str] = set()
    for text in texts:
        if not text:
            continue
        refanged = _refang(text)
        for pattern in _PATTERNS:
            for match in pattern.finditer(refanged):
                value = match.group(0)
                if pattern in _IP_PATTERNS:
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        continue
                key = value.lower()
                if key not in seen_set:
                    seen_set.add(key)
                    seen.append(value)
    return seen


def merge_iocs(*lists: list[str]) -> list[str]:
    """Union multiple iocs lists (e.g. LLM-extracted + regex-extracted +
    research-found), deduplicated case-insensitively, first-seen order
    preserved, capped at 50 — mirrors llm/backend._coerce_str_list's cap so
    no single source can blow out a case's indicator list."""
    seen: list[str] = []
    seen_set: set[str] = set()
    for lst in lists:
        for raw in lst or []:
            value = str(raw).strip()
            key = value.lower()
            if value and key not in seen_set:
                seen_set.add(key)
                seen.append(value)
            if len(seen) >= 50:
                return seen
    return seen
