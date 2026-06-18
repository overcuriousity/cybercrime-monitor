"""OpenAI-compatible HTTP classifier backend (default target: a local
LMStudio instance). One function, no ABC/registry — settings.classifier_backend
is checked by the caller (job.py / collectors/base.py), not here; this module
only implements the one backend that exists today. A future local-model
backend would be a second module with the same classify() signature.
"""
import json
import logging
import re
from dataclasses import dataclass

import httpx

from ..settings import settings
from . import health as classifier_health

log = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a triage analyst for a data-exfiltration and breach-for-sale \
monitoring feed. The goal is to surface ONLY concrete, specific incidents \
— exactly when data was exfiltrated or is being sold, from which victim, \
and by whom — and to eliminate noise such as generic security news, \
industry trend commentary, and vague mentions with no identifiable victim \
or actor. You will be shown one scraped item (title, snippet, source) plus \
a regex-derived hint that is NOT authoritative — keyword matching produces \
many false positives.

Classify the item:
- "critical": an active data-for-sale offering — a named victim AND a \
  named seller/threat actor, with sale evidence (a price, a marketplace or \
  forum, a leak sample, or an explicit "for sale"/"selling" claim).
- "warn": a confirmed exfiltration/breach/ransomware incident with a named \
  victim and/or a named threat actor (e.g. a ransomware group's leak-site \
  posting, a confirmed breach disclosure) but without explicit sale \
  evidence — exfiltration is established, just not (yet) a sale listing.
- "info": breach-related content that names neither a clear victim nor a \
  clear actor — real, but too vague to act on.

Set false_positive=true for anything that is NOT a specific, identifiable \
incident: generic security/cybercrime news, industry trend pieces, opinion \
or analysis articles, vague "X were breached" mentions you can't pin to an \
incident, or empty/uninformative posts. The bar: would a reader learn \
*which* victim and/or *which* actor this is about? If not, it's noise — \
eliminate it.

Respond with ONLY a single-line JSON object, no markdown fencing, no \
commentary, exactly these keys:
{"priority": "info"|"warn"|"critical", "false_positive": true|false, \
"confidence": <0.0-1.0>, "reasoning": "<one short sentence>"}
"""


@dataclass
class Verdict:
    priority: str
    false_positive: bool
    confidence: float | None
    reasoning: str | None
    model: str


def _build_user_prompt(title: str, snippet: str, source_name: str, regex_priority: str, regex_tags: list[str]) -> str:
    return (
        f"Source: {source_name}\n"
        f"Title: {title}\n"
        f"Snippet: {snippet[:800]}\n"
        f"Regex hint (not authoritative): priority={regex_priority or 'none'}, tags={regex_tags}"
    )


_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)
_VALID_PRIORITIES = {"info", "warn", "critical"}


def _parse_verdict(content: str, *, model: str) -> Verdict | None:
    # Local models often wrap JSON in markdown fences or add stray text
    # despite instructions — extract the first {...} block rather than
    # requiring the whole response to be valid JSON.
    match = _JSON_OBJECT.search(content)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None

    priority = str(data.get("priority", "")).lower()
    if priority not in _VALID_PRIORITIES:
        return None

    confidence = data.get("confidence")
    try:
        confidence = float(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        confidence = None

    return Verdict(
        priority=priority,
        false_positive=bool(data.get("false_positive", False)),
        confidence=confidence,
        reasoning=str(data.get("reasoning", ""))[:500] or None,
        model=model,
    )


async def classify(
    *, title: str, snippet: str, source_name: str, regex_priority: str, regex_tags: list[str]
) -> Verdict | None:
    """Classify one item via the OpenAI-compatible /chat/completions endpoint.
    Returns None on any failure (timeout, malformed JSON, non-2xx) — the
    caller leaves the item unclassified and it's retried next batch; no
    internal retry loop needed since the unclassified-items query is
    naturally self-healing."""
    url = settings.classifier_base_url.rstrip("/") + "/chat/completions"
    headers = _auth_headers()

    payload = {
        "model": settings.classifier_model or "local-model",
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(title, snippet, source_name, regex_priority, regex_tags)},
        ],
        "temperature": 0,
        "max_tokens": 300,
        # Strict structured output — the server enforces this shape rather
        # than just being asked nicely for JSON in the prompt, which matters
        # a lot for small/edge models (verified against LM Studio: without
        # this, a 2B-class model reliably returned empty content for every
        # request; with it, well-formed verdicts came back immediately). If
        # a given backend doesn't support this response_format at all, that
        # surfaces as a normal request failure here — same retry-with-
        # backoff path as any other error (job.py never gives up, just
        # backs off so a failing item can't blockade the queue).
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "verdict",
                "strict": True,
                "schema": _VERDICT_SCHEMA,
            },
        },
    }

    try:
        async with httpx.AsyncClient(timeout=settings.classifier_timeout_seconds) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        content = data["choices"][0]["message"]["content"]
        model_name = data.get("model") or settings.classifier_model or "unknown"
        verdict = _parse_verdict(content, model=model_name)
        if verdict is None:
            classifier_health.record_error(f"unparseable response: {content[:200]!r}")
            return None
        return verdict
    except Exception as exc:
        classifier_health.record_error(str(exc) or repr(exc))
        return None


def _auth_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if settings.classifier_api_key:
        headers["Authorization"] = f"Bearer {settings.classifier_api_key}"
    return headers


_VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "priority": {"type": "string", "enum": ["info", "warn", "critical"]},
        "false_positive": {"type": "boolean"},
        "confidence": {"type": "number"},
        "reasoning": {"type": "string"},
    },
    "required": ["priority", "false_positive", "confidence", "reasoning"],
    "additionalProperties": False,
}

# Same fields as _VERDICT_SCHEMA plus "index" — the model echoes back which
# input item (0-based, matching the order items were listed in the prompt)
# each verdict belongs to. This is more robust than relying on output-array
# position matching input-array position: a model that skips/reorders one
# item under batch load still produces verdicts we can correctly attribute,
# instead of silently misclassifying item N+1 as item N's verdict.
_BATCH_VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"index": {"type": "integer"}, **_VERDICT_SCHEMA["properties"]},
                "required": ["index", *_VERDICT_SCHEMA["required"]],
                "additionalProperties": False,
            },
        },
    },
    "required": ["verdicts"],
    "additionalProperties": False,
}

_BATCH_SYSTEM_PROMPT = _SYSTEM_PROMPT + (
    "\n\nYou will be shown MULTIPLE items, each prefixed with its index "
    "(e.g. \"[2] Title: ...\"). Classify EVERY item independently — they are "
    "unrelated incidents, not a single story. Respond with ONLY a single-line "
    "JSON object, no markdown fencing, no commentary, exactly this shape:\n"
    '{"verdicts": [{"index": <int>, "priority": "info"|"warn"|"critical", '
    '"false_positive": true|false, "confidence": <0.0-1.0>, "reasoning": '
    '"<one short sentence>"}, ...]}\n'
    "Include exactly one verdict object per item shown, using its given index."
)


def _build_batch_user_prompt(items: list[dict]) -> str:
    blocks = []
    for i, it in enumerate(items):
        blocks.append(
            f"[{i}] Source: {it['source_name']}\n"
            f"[{i}] Title: {it['title']}\n"
            f"[{i}] Snippet: {it['snippet'][:800]}\n"
            f"[{i}] Regex hint (not authoritative): "
            f"priority={it.get('regex_priority') or 'none'}, tags={it.get('regex_tags') or []}"
        )
    return "\n\n".join(blocks)


def _parse_batch_verdicts(content: str, *, model: str, n: int) -> dict[int, Verdict]:
    match = _JSON_OBJECT.search(content)
    if not match:
        return {}
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}

    raw_verdicts = data.get("verdicts")
    if not isinstance(raw_verdicts, list):
        return {}

    out: dict[int, Verdict] = {}
    for entry in raw_verdicts:
        if not isinstance(entry, dict):
            continue
        try:
            idx = int(entry.get("index"))
        except (TypeError, ValueError):
            continue
        if idx < 0 or idx >= n or idx in out:
            continue  # out-of-range or duplicate index — skip rather than guess

        priority = str(entry.get("priority", "")).lower()
        if priority not in _VALID_PRIORITIES:
            continue
        confidence = entry.get("confidence")
        try:
            confidence = float(confidence) if confidence is not None else None
        except (TypeError, ValueError):
            confidence = None

        out[idx] = Verdict(
            priority=priority,
            false_positive=bool(entry.get("false_positive", False)),
            confidence=confidence,
            reasoning=str(entry.get("reasoning", ""))[:500] or None,
            model=model,
        )
    return out


async def classify_batch(items: list[dict]) -> list[Verdict | None]:
    """Classify N items in a single /chat/completions call. Returns a list
    parallel to `items` — entries are None where the model omitted that
    item's verdict or the whole call failed, exactly like classify()'s
    single-item None contract, so job.py's per-item backoff logic is
    unchanged. Caller should fall back to per-item classify() if a backend
    doesn't support this (surfaces here as a normal failure — every entry
    comes back None, same retry-with-backoff path as any other error)."""
    if not items:
        return []

    url = settings.classifier_base_url.rstrip("/") + "/chat/completions"
    headers = _auth_headers()

    payload = {
        "model": settings.classifier_model or "local-model",
        "messages": [
            {"role": "system", "content": _BATCH_SYSTEM_PROMPT},
            {"role": "user", "content": _build_batch_user_prompt(items)},
        ],
        "temperature": 0,
        "max_tokens": 300 * len(items),
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "batch_verdict", "strict": True, "schema": _BATCH_VERDICT_SCHEMA},
        },
    }

    try:
        async with httpx.AsyncClient(timeout=settings.classifier_timeout_seconds) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        content = data["choices"][0]["message"]["content"]
        model_name = data.get("model") or settings.classifier_model or "unknown"
        verdicts_by_idx = _parse_batch_verdicts(content, model=model_name, n=len(items))
        if not verdicts_by_idx:
            classifier_health.record_error(f"unparseable batch response: {content[:200]!r}")
        return [verdicts_by_idx.get(i) for i in range(len(items))]
    except Exception as exc:
        classifier_health.record_error(str(exc) or repr(exc))
        return [None] * len(items)
