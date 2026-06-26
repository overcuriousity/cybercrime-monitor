"""
Pure-function renderers for interoperable threat-intel export formats —
MISP event JSON and CSV/flat-IOC list.

No LLM calls. Every function is deterministic computation over the case bundle
already produced by _load_case_bundle (routes.py) or the list of case dicts
returned by fetch_cases (db.py). Token-free by construction.

Machine confidence scoring (case_export_confidence) replaces a human curation
layer with machine signals: source_count, attribution_confidence,
significance_score, in_kev, analyst/agent feedback verdicts (weighted by
settings.feedback_agent_weight), and extractions.false_positive ratio.

The feedback and false_positive signals are pre-attached to the case dict by
routes.py's _attach_confidence_signals() helper before scoring — this batches
the DB queries across all cases so the feed path stays O(1) queries regardless
of case count. Case dicts that have not been through _attach_confidence_signals
(i.e. their "feedback_score" / "fp_ratio" keys are absent) default to neutral
(no penalty, no bonus) so callers that skip the attach step still get a valid
score from the base signals alone.

Campaign clustering (roadmap #3): case_to_misp_event accepts an optional
campaign_id so member cases emit a MISP part-of-campaign RelatedEvent.
campaign_to_misp_event() emits the synthetic cluster event.
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
    # SHA256 first: 64 hex chars — no crypto address is this long, safe to
    # check before the address patterns.
    if _SHA256_RE.match(value):
        return "sha256", "Payload delivery", True
    # Crypto addresses before shorter hashes: ETH addresses (40 hex, with or
    # without 0x prefix) would match _SHA1_RE if checked later. Check all
    # wallet formats here to prevent misclassification as file hashes.
    if _ETH_RE.match(value):
        return "cryptocurrency-address", "Financial fraud", False
    # Monero (long base58, checked before BTC to avoid length ambiguity).
    if _XMR_RE.match(value):
        return "cryptocurrency-address", "Financial fraud", False
    if _BTC_RE.match(value):
        return "btc", "Financial fraud", False
    # SHA1 / MD5 — after crypto addresses so 40-hex ETH (no 0x prefix) and
    # 32-hex values aren't silently re-classified as file hashes.
    if _SHA1_RE.match(value):
        return "sha1", "Payload delivery", True
    if _MD5_RE.match(value):
        return "md5", "Payload delivery", True
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
# deterministic combination of machine signals — no LLM, no human input.
#
# The feedback and false_positive signals are pre-attached by routes.py's
# _attach_confidence_signals() before scoring bulk case lists (two batch DB
# queries rather than N per-case round-trips).  Absent keys default to neutral
# so this function never raises on a bare case dict.

_POSITIVE_VERDICTS = frozenset({"useful"})
_NEGATIVE_VERDICTS = frozenset({"not_useful", "noise", "wrong_attribution"})


def feedback_score(by_origin: dict[str, dict[str, int]]) -> float | None:
    """Weighted net-positive feedback score in 0..1, or None if no feedback.

    Mirrors sources/value.py's _component_feedback weighting:
    - human verdicts count at weight 1.0
    - agent verdicts (research/evaluator.py) count at settings.feedback_agent_weight (0.5)

    Returns None when there are no feedback rows at all (so the caller can
    apply neutral adjustment rather than penalising absence of feedback).
    """
    from ..settings import settings as _settings

    origin_weights = {"human": 1.0, "agent": _settings.feedback_agent_weight}
    weighted_pos = 0.0
    weighted_total = 0.0

    for origin, verdicts in by_origin.items():
        w = origin_weights.get(origin, 0.5)
        for verdict, n in verdicts.items():
            wn = w * n
            if verdict in _POSITIVE_VERDICTS:
                weighted_pos += wn
            if verdict in _POSITIVE_VERDICTS | _NEGATIVE_VERDICTS:
                weighted_total += wn

    if weighted_total == 0.0:
        return None
    return weighted_pos / weighted_total


def case_export_confidence(case: dict) -> float:
    """Return a 0..100 machine-confidence score for export worthiness.

    Base signals (always available from the case dict):
    - significance_score (0..1 → 0..35 pts) — LLM assessment of incident specificity.
    - source_count corroboration (capped at 5 → 0..20 pts) — multiple sources
      reduce single-source noise risk.
    - attribution_confidence (0..1 → 0..15 pts) — research-verified attribution.
    - CISA KEV membership (+10 pts) — external confirmation of active exploitation.
    - base floor (+5 pts) — any correlated case has passed extraction + correlation.

    Enrichment signals (pre-attached by _attach_confidence_signals; absent = neutral):
    - feedback adjustment: (feedback_score − 0.5) × 30 → −15..+15 pts.
      A case where analysts/evaluators mostly said "useful" earns a bonus; mostly
      "noise" or "wrong_attribution" earns a penalty. Agent verdicts count at
      settings.feedback_agent_weight (default 0.5) of a human verdict.
    - false_positive penalty: fp_ratio × 25 → 0..25 pts deducted.
      A case where most of its extractions were flagged false_positive by the LLM
      loses up to 25 pts — enough to push it below the 50-pt feed gate.

    Score is clamped to [0, 100].
    """
    sig_pts = (case.get("significance_score") or 0.0) * 35.0
    src_pts = min(case.get("source_count") or 0, 5) * 4.0    # 0..20
    attr_pts = (case.get("attribution_confidence") or 0.0) * 15.0
    kev_pts = 10.0 if case.get("in_kev") else 0.0
    base = 5.0

    # Feedback adjustment (pre-attached by _attach_confidence_signals)
    fb_val = case.get("feedback_score")
    fb_pts = (fb_val - 0.5) * 30.0 if fb_val is not None else 0.0  # −15..+15

    # False-positive penalty (pre-attached by _attach_confidence_signals)
    fp_val = case.get("fp_ratio")
    fp_pts = (fp_val * 25.0) if fp_val is not None else 0.0  # 0..25

    raw = sig_pts + src_pts + attr_pts + kev_pts + base + fb_pts - fp_pts
    return max(0.0, min(100.0, raw))


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


# ── Campaign MISP export (roadmap #3) ────────────────────────────────────────

def campaign_to_misp_event(
    campaign: dict,
    member_cases: list[dict],
    *,
    tlp: str = "amber",
    namespace: uuid.UUID | None = None,
) -> dict:
    """Render a machine-derived campaign as a synthetic MISP cluster event.

    The cluster event:
    - UUID derived deterministically from campaign_key so re-exporting the
      same campaign updates rather than duplicates the MISP event.
    - Union of all member IOCs and CVEs as attributes.
    - Sector/country/crime-type/actor tags from aggregate fields.
    - RelatedEvent links to each member case's stable MISP event UUID.
    - threat_level_id from the campaign's max member significance.

    Token-free — pure dict construction.
    """
    ns = namespace or _DEFAULT_NAMESPACE
    campaign_key = campaign.get("campaign_key", str(campaign.get("id", "")))
    # Stable UUID: same scheme as _event_uuid but with "campaign:" prefix so
    # it can never collide with a case UUID sharing the same key string.
    campaign_uuid = str(uuid.uuid5(ns, f"campaign:{campaign_key}"))

    tlp_tag = _TLP_TAGS.get(tlp.lower(), "tlp:amber")
    sig = campaign.get("significance", "info")

    # Synthetic confidence: start from member count, but cap at the highest
    # member case_export_confidence so a large cluster of low-confidence cases
    # doesn't score artificially high.
    n = campaign.get("case_count", len(member_cases)) or 1
    base_confidence = min(100.0, 30.0 + n * 10.0)
    max_member_confidence = max(
        (case_export_confidence(c) for c in member_cases),
        default=0.0,
    )
    synthetic_confidence = min(base_confidence, max_member_confidence)

    attributes: list[dict] = []

    # Campaign summary
    if campaign.get("summary"):
        attributes.append({
            "uuid": str(uuid.uuid5(ns, f"campaign-summary:{campaign_key}")),
            "type": "text",
            "category": "Internal reference",
            "value": campaign["summary"],
            "to_ids": False,
            "comment": "Machine-derived campaign summary",
            "distribution": "5",
        })

    # Union of all member IOCs
    all_iocs: set[str] = set(campaign.get("iocs") or [])
    for case in member_cases:
        all_iocs.update(case.get("iocs") or [])
    for ioc_value in sorted(all_iocs):
        misp_type, category, to_ids = _classify_ioc(ioc_value)
        attributes.append({
            "uuid": _attr_uuid(campaign_key, misp_type, ioc_value, ns),
            "type": misp_type,
            "category": category,
            "value": ioc_value,
            "to_ids": to_ids,
            "comment": "Campaign-level IOC (union of member cases)",
            "distribution": "5",
        })

    # Union of all member CVEs
    all_cves: set[str] = set(campaign.get("cve_ids") or [])
    for case in member_cases:
        all_cves.update(case.get("cve_ids") or [])
    for cve in sorted(all_cves):
        attributes.append({
            "uuid": _attr_uuid(campaign_key, "vulnerability", cve, ns),
            "type": "vulnerability",
            "category": "External analysis",
            "value": cve,
            "to_ids": False,
            "comment": "Campaign-level CVE (union of member cases)",
            "distribution": "5",
        })

    # Dominant actor as threat-actor attribute
    if campaign.get("dominant_actor"):
        attributes.append({
            "uuid": str(uuid.uuid5(ns, f"campaign-actor:{campaign_key}")),
            "type": "threat-actor",
            "category": "Attribution",
            "value": campaign["dominant_actor"],
            "to_ids": False,
            "comment": "Machine-derived dominant actor (majority vote over member cases)",
            "distribution": "5",
        })

    # Tags
    tags: list[dict] = [{"name": tlp_tag}]
    for sector in (campaign.get("sectors") or [])[:3]:
        tags.append({"name": f"sector:{sector.lower()}"})
    for country in (campaign.get("countries") or [])[:3]:
        tags.append({"name": f"country:{country.lower()}"})
    for crime_type in (campaign.get("crime_types") or [])[:2]:
        tags.append({"name": f"cybercrime-monitor:crime-type={crime_type}"})
    if campaign.get("in_kev"):
        tags.append({"name": "cisa:kev"})
    tags.append({"name": "cybercrime-monitor:cluster=campaign"})

    # RelatedEvent: one entry per member case, linking to its stable event UUID
    related_events: list[dict] = []
    for case in member_cases:
        case_key = case.get("case_key") or str(case.get("id", ""))
        if case_key:
            related_events.append({
                "id": _event_uuid(case_key, ns),
                "relationship_type": "contains",
                "comment": case.get("title", ""),
            })

    event: dict = {
        "uuid": campaign_uuid,
        "info": campaign.get("title", f"Campaign cluster {campaign_key}"),
        "date": (campaign.get("first_seen") or "")[:10] or None,
        "threat_level_id": _threat_level_id(sig, synthetic_confidence),
        "analysis": "1",  # Ongoing — machine-derived clusters are continuously refined
        "distribution": "0",
        "published": False,
        "Attribute": attributes,
        "Tag": tags,
    }
    if related_events:
        event["RelatedEvent"] = related_events

    return {"Event": event}
