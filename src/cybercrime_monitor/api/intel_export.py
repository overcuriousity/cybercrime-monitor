"""
Pure-function renderers for interoperable threat-intel export formats —
MISP event JSON and CSV/flat-IOC list.

No I/O, no LLM calls. Every function is deterministic computation over the
case bundle already produced by _load_case_bundle (routes.py) or the list
of case dicts returned by fetch_cases (db.py). Token-free by construction.

Machine confidence scoring (case_export_confidence) replaces a human curation
layer with existing machine signals: source_count, attribution_confidence,
significance_score, in_kev. This value drives MISP's threat_level_id field
and the /api/feed/misp gate (cases below settings.intel_feed_min_confidence
are excluded from the feed without any human intervention).

Campaign hand-off (roadmap #3): case_to_misp_event accepts an optional
campaign_id so that, once machine-derived campaign clustering lands, member
cases can emit MISP RelatedEvent links without reworking this renderer.
"""
import csv
import io
import ipaddress
import re
import uuid


# ── IOC type classification ──────────────────────────────────────────────────
# Matches the _PATTERNS priority order in enrich/ioc.py — longest/most-
# specific patterns checked first so a SHA256 hash isn't misclassified as
# an IPv4 address etc.

_IPV4_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
_IPV6_RE = re.compile(r'^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')
_SHA256_RE = re.compile(r'^[a-fA-F0-9]{64}$')
_SHA1_RE = re.compile(r'^[a-fA-F0-9]{40}$')
_MD5_RE = re.compile(r'^[a-fA-F0-9]{32}$')
_BTC_RE = re.compile(r'^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,90})$')
_ETH_RE = re.compile(r'^0x[a-fA-F0-9]{40}$')
_XMR_RE = re.compile(r'^[48][1-9A-HJ-NP-Za-km-z]{94}$')


def _classify_ioc(value: str) -> tuple[str, str, bool]:
    """Return (misp_type, misp_category, to_ids) for one IOC value.

    to_ids=True marks the indicator for automated IDS/firewall matching
    (actionable network/payload indicators); False is used for contextual
    attributes (crypto addresses, links) that a TIP should not auto-push to
    detection systems.
    """
    # File hashes — longest pattern first to avoid mis-classifying a hash
    # prefix as a shorter hash type.
    if _SHA256_RE.match(value):
        return "sha256", "Payload delivery", True
    if _SHA1_RE.match(value):
        return "sha1", "Payload delivery", True
    if _MD5_RE.match(value):
        return "md5", "Payload delivery", True
    # Ethereum/EVM (40 hex chars with 0x prefix — must come before bare hex
    # patterns that could match the unprefixed part).
    if _ETH_RE.match(value):
        return "cryptocurrency-address", "Financial fraud", False
    # Monero (long base58, checked before BTC to avoid length ambiguity).
    if _XMR_RE.match(value):
        return "cryptocurrency-address", "Financial fraud", False
    if _BTC_RE.match(value):
        return "btc", "Financial fraud", False
    # IPv4/IPv6 — use ipaddress to reject out-of-range octets etc.
    if _IPV4_RE.match(value):
        try:
            ipaddress.ip_address(value)
            return "ip-dst", "Network activity", True
        except ValueError:
            pass
    if _IPV6_RE.match(value):
        try:
            ipaddress.ip_address(value)
            return "ip-dst", "Network activity", True
        except ValueError:
            pass
    # Onion / URL
    if value.lower().endswith(".onion"):
        return "url", "Network activity", True
    if value.startswith(("http://", "https://", "ftp://")):
        return "url", "Network activity", True
    # Email (before domain — '@' takes priority over '.')
    if "@" in value and "." in value:
        return "email-src", "Payload delivery", True
    # Domain heuristic — has a dot, no spaces or slashes.
    if "." in value and " " not in value and "/" not in value:
        return "domain", "Network activity", True
    # Fallback — keep the value in the event as opaque text.
    return "text", "External analysis", False


# ── Deterministic UUID derivation ────────────────────────────────────────────
# MISP de-dupes on event UUID; UUIDv5 from a fixed namespace + the case_key
# means re-exporting the same case produces the same event UUID so a TIP
# updates rather than creates a duplicate. Attribute UUIDs are similarly
# stable. The namespace is configurable (settings.intel_export_namespace_uuid)
# so operators can choose their own seed without colliding with anyone else's.
# Default: the RFC 4122 DNS namespace UUID.

_DEFAULT_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


def _event_uuid(case_key: str, ns: uuid.UUID) -> str:
    return str(uuid.uuid5(ns, f"case:{case_key}"))


def _attr_uuid(case_key: str, role: str, value: str, ns: uuid.UUID) -> str:
    """Stable attribute UUID — role disambiguates two attributes with the
    same value but different types (e.g. a SHA1 that also matches an MD5
    pattern in a different context, though in practice the IOC classifier
    prevents that)."""
    return str(uuid.uuid5(ns, f"attr:{case_key}:{role}:{value[:200]}"))


# ── Machine confidence scoring ───────────────────────────────────────────────
# Replaces a human "this case is good enough to export" verdict with a
# deterministic combination of existing machine signals that are already on
# every case dict from fetch_cases / _load_case_bundle — no extra DB queries.

def case_export_confidence(case: dict) -> float:
    """Return a 0..100 machine-confidence score for export worthiness.

    Components (all token-free, all from existing case fields):
    - significance_score (0..1 → 0..40 pts, largest weight — the LLM's
      own assessment of how specific/ongoing/impactful the incident is).
    - source_count corroboration (capped at 5 → 0..25 pts — multiple
      independent sources reduce the chance of a single bad actor or a
      misclassified benign article).
    - attribution_confidence (0..1 → 0..20 pts — research-verified attribution
      raises score even for lower-significance cases worth tracking).
    - CISA KEV membership (+10 pts — deterministic external confirmation of
      active exploitation, a strong "this matters" signal).
    - base floor (+5 pts — any correlated case has passed at least the
      extraction + correlation pipeline, which filters out false positives).
    """
    sig_pts = (case.get("significance_score") or 0.0) * 40.0
    src_pts = min(case.get("source_count") or 0, 5) * 5.0   # 0..25
    attr_pts = (case.get("attribution_confidence") or 0.0) * 20.0
    kev_pts = 10.0 if case.get("in_kev") else 0.0
    return min(100.0, sig_pts + src_pts + attr_pts + kev_pts + 5.0)


def _threat_level_id(significance: str, confidence: float) -> str:
    """MISP threat_level_id: 1=High, 2=Medium, 3=Low, 4=Undefined."""
    if significance == "critical" or confidence >= 70:
        return "1"
    if significance == "warn" or confidence >= 40:
        return "2"
    if significance == "info":
        return "3"
    return "4"


def _analysis(status: str, significance: str) -> str:
    """MISP analysis: 0=Initial, 1=Ongoing, 2=Completed."""
    if status == "confirmed":
        return "2"
    if significance == "critical":
        return "1"
    return "0"


# ── TLP tag map ──────────────────────────────────────────────────────────────
_TLP_TAGS: dict[str, str] = {
    "clear": "tlp:clear",
    "white": "tlp:clear",  # legacy alias
    "green": "tlp:green",
    "amber": "tlp:amber",
    "amber+strict": "tlp:amber+strict",
    "red": "tlp:red",
}


# ── MISP event renderer ──────────────────────────────────────────────────────

def case_to_misp_event(
    case: dict,
    items: list[dict],
    research_runs: list[dict],
    related: list[dict],
    *,
    tlp: str = "amber",
    campaign_id: str | None = None,
    namespace: uuid.UUID | None = None,
) -> dict:
    """Render one case bundle as a MISP Event dict, ready for JSON
    serialization and direct import into MISP or compatible TIPs.

    Covers: IOCs as typed attributes (ip-dst/domain/sha256/…), CVEs as
    vulnerability attributes, MITRE ATT&CK techniques as text attributes,
    threat actor via threat-actor attribute, corroborating source URLs as
    link attributes, victim sector/country/crime-type as tags, TLP + admiralty
    confidence as tags, and a summary text attribute from the AI-generated
    case summary.

    campaign_id is reserved for roadmap #3 (machine campaign clustering): when
    provided, a RelatedEvent entry is added so all campaign members link to
    the same cluster event in MISP — no renderer changes needed at that point.

    Token-free — pure dict construction over already-decoded case fields.
    """
    ns = namespace or _DEFAULT_NAMESPACE
    # case_key is the stable dedup identifier produced by pipeline/correlate.py;
    # fall back to string(id) only for legacy rows that predate it.
    case_key = case.get("case_key") or str(case["id"])
    confidence = case_export_confidence(case)
    sig = case.get("significance", "info")
    status = case.get("status", "new")

    tlp_tag = _TLP_TAGS.get(tlp.lower(), "tlp:amber")

    attributes: list[dict] = []

    # Case summary — goes first so it's visible at the top of the event.
    if case.get("summary"):
        attributes.append({
            "uuid": _attr_uuid(case_key, "summary", "summary", ns),
            "type": "text",
            "category": "Internal reference",
            "value": case["summary"],
            "to_ids": False,
            "comment": "AI-generated case summary",
            "distribution": "5",
        })

    # IOCs — classify each to the correct MISP attribute type.
    for ioc_value in case.get("iocs") or []:
        misp_type, category, to_ids = _classify_ioc(ioc_value)
        attributes.append({
            "uuid": _attr_uuid(case_key, misp_type, ioc_value, ns),
            "type": misp_type,
            "category": category,
            "value": ioc_value,
            "to_ids": to_ids,
            "comment": "",
            "distribution": "5",
        })

    # CVEs — carry CVSS/EPSS/KEV context in the comment so it's visible in MISP
    # without the analyst needing to re-look it up.
    for cve in case.get("cve_ids") or []:
        comment_parts = []
        if case.get("cvss_max") is not None:
            comment_parts.append(f"CVSS max: {case['cvss_max']}")
        if case.get("epss_max") is not None:
            comment_parts.append(f"EPSS max: {case['epss_max']:.3f}")
        if case.get("in_kev"):
            comment_parts.append("In CISA KEV")
        attributes.append({
            "uuid": _attr_uuid(case_key, "vulnerability", cve, ns),
            "type": "vulnerability",
            "category": "External analysis",
            "value": cve,
            "to_ids": False,
            "comment": "; ".join(comment_parts),
            "distribution": "5",
        })

    # MITRE ATT&CK technique IDs — stored as text so they show up as
    # searchable attributes; MISP's ATT&CK galaxy correlation can link them.
    for technique in case.get("mitre_techniques") or []:
        attributes.append({
            "uuid": _attr_uuid(case_key, "mitre", technique, ns),
            "type": "text",
            "category": "External analysis",
            "value": technique,
            "to_ids": False,
            "comment": "MITRE ATT&CK technique",
            "distribution": "5",
        })

    # Attribution — threat-actor attribute with confidence in the comment.
    if case.get("attribution"):
        attr_conf = case.get("attribution_confidence")
        attr_comment = f"Confidence: {attr_conf:.0%}" if attr_conf is not None else ""
        attributes.append({
            "uuid": _attr_uuid(case_key, "threat-actor", case["attribution"], ns),
            "type": "threat-actor",
            "category": "Attribution",
            "value": case["attribution"],
            "to_ids": False,
            "comment": attr_comment,
            "distribution": "5",
        })

    # Source URLs from corroborating reports — capped at 20 so large multi-
    # source cases don't bloat the event with dozens of near-identical links.
    for item in (items or [])[:20]:
        url = item.get("url")
        if not url:
            continue
        source = item.get("source_name") or item.get("source_id") or ""
        attributes.append({
            "uuid": _attr_uuid(case_key, "link", str(url), ns),
            "type": "link",
            "category": "External analysis",
            "value": str(url),
            "to_ids": False,
            "comment": f"Source: {source}" if source else "",
            "distribution": "5",
        })

    # ── Tags ──
    tags: list[dict] = [{"name": tlp_tag}]
    if case.get("damaged_party_sector"):
        tags.append({"name": f"sector:{case['damaged_party_sector'].lower()}"})
    if case.get("damaged_party_country"):
        tags.append({"name": f"country:{case['damaged_party_country'].lower()}"})
    if case.get("crime_type"):
        tags.append({"name": f"cybercrime-monitor:crime-type={case['crime_type']}"})
    if case.get("in_kev"):
        tags.append({"name": "cisa:kev"})
    # Admiralty source reliability scale — machine-derived from confidence score.
    if confidence >= 85:
        rel_tag = 'admiralty-scale:source-reliability="a-completely-reliable"'
    elif confidence >= 65:
        rel_tag = 'admiralty-scale:source-reliability="b-usually-reliable"'
    elif confidence >= 45:
        rel_tag = 'admiralty-scale:source-reliability="c-fairly-reliable"'
    else:
        rel_tag = 'admiralty-scale:source-reliability="d-not-usually-reliable"'
    tags.append({"name": rel_tag})

    # ── Related events (campaign hand-off for roadmap #3 + cross-case links) ──
    related_events: list[dict] = []
    if campaign_id:
        related_events.append({
            "id": campaign_id,
            "relationship_type": "part-of-campaign",
        })
    for rel in (related or [])[:5]:
        rel_case_key = rel.get("case_key") or str(rel.get("case_id", ""))
        if rel_case_key:
            related_events.append({
                "id": _event_uuid(rel_case_key, ns),
                "relationship_type": "related-to",
                "comment": ", ".join(rel.get("reasons") or []),
            })

    event: dict = {
        "uuid": _event_uuid(case_key, ns),
        "info": case.get("title", ""),
        "date": (case.get("first_seen") or "")[:10] or None,
        "threat_level_id": _threat_level_id(sig, confidence),
        "analysis": _analysis(status, sig),
        # distribution=0 (Your organisation only) — the analyst sets the sharing
        # level before pushing to MISP's sync network; we never auto-publish
        # machine-produced output to connected communities.
        "distribution": "0",
        "published": False,
        "Attribute": attributes,
        "Tag": tags,
    }
    if related_events:
        event["RelatedEvent"] = related_events

    return {"Event": event}


# ── Batch export: minimal per-case MISP events ───────────────────────────────

def cases_to_misp_response(
    cases: list[dict],
    *,
    tlp: str = "amber",
    namespace: uuid.UUID | None = None,
) -> dict:
    """Wrap multiple case dicts (from fetch_cases — not full bundles) as a
    MISP REST-API-style response. Each event contains IOCs, CVEs, ATT&CK
    techniques, and attribution but NOT corroborating source URLs or research
    findings (those require per-case DB queries not done for bulk export).

    Use GET /api/cases/{id}/export?format=misp for the full single-case event
    that includes source URLs and research run findings.
    """
    events = [
        case_to_misp_event(case, [], [], [], tlp=tlp, namespace=namespace)
        for case in cases
    ]
    return {"response": events}


# ── CSV export ───────────────────────────────────────────────────────────────

_CSV_FIELDS = [
    "id", "title", "crime_type", "significance", "status",
    "damaged_party", "damaged_party_sector", "damaged_party_country",
    "attribution", "attribution_confidence",
    "first_seen", "last_seen", "source_count", "in_kev",
    "cve_ids", "cvss_max", "epss_max", "cwe_ids", "mitre_techniques", "iocs",
]


def cases_to_csv(cases: list[dict]) -> str:
    """Flat CSV — one row per case. List-valued fields (iocs, cve_ids,
    mitre_techniques, cwe_ids) are pipe-separated within a single cell so
    the file opens correctly in Excel/LibreOffice without losing structure."""
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=_CSV_FIELDS, extrasaction="ignore", lineterminator="\n"
    )
    writer.writeheader()
    for case in cases:
        row = dict(case)
        for list_field in ("iocs", "cve_ids", "mitre_techniques", "cwe_ids"):
            val = row.get(list_field)
            row[list_field] = "|".join(val) if isinstance(val, list) else (val or "")
        row["in_kev"] = "yes" if row.get("in_kev") else "no"
        if row.get("attribution_confidence") is not None:
            row["attribution_confidence"] = f"{row['attribution_confidence']:.3f}"
        else:
            row["attribution_confidence"] = ""
        row["cvss_max"] = (
            f"{row['cvss_max']:.1f}" if row.get("cvss_max") is not None else ""
        )
        row["epss_max"] = (
            f"{row['epss_max']:.3f}" if row.get("epss_max") is not None else ""
        )
        writer.writerow(row)
    return buf.getvalue()


def cases_to_ioc_list(cases: list[dict]) -> str:
    """Deduplicated flat IOC list (one value per line) across all provided
    cases. Suitable for direct import into blocklists, firewall deny-lists,
    and other indicator-consumption tools that expect a plain-text feed."""
    seen: set[str] = set()
    lines: list[str] = []
    for case in cases:
        for ioc in case.get("iocs") or []:
            normalized = ioc.strip().lower()
            if normalized and normalized not in seen:
                seen.add(normalized)
                lines.append(ioc.strip())
    return "\n".join(lines)
