"""Keyword/regex matcher with hot-reload from keywords.yaml."""
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import regex as re  # drop-in re replacement that supports a match timeout (ReDoS guard)
import yaml

from .models import Item, Match
from .settings import settings

log = logging.getLogger(__name__)

_PRIORITY_RANK = {"info": 1, "warn": 2, "critical": 3}

# Items are fetched/scraped from hostile sources, and keyword patterns can be
# edited via the (gated) PUT /api/keywords endpoint — both are attacker-
# reachable inputs, so every match runs under a wall-clock budget rather than
# trusting the pattern not to catastrophically backtrack.
_MATCH_TIMEOUT_SECONDS = 1.0
_MAX_PATTERN_LENGTH = 300


@dataclass
class Rule:
    pattern: str
    compiled: "re.Pattern"
    priority: str
    tags: list[str]
    notes: str = ""


class Matcher:
    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._mtime: float = 0.0
        self._path = settings.keywords_config
        self.reload()

    # ── public ────────────────────────────────────────────────────────────────

    def reload(self) -> None:
        try:
            mtime = self._path.stat().st_mtime
        except FileNotFoundError:
            log.warning("keywords.yaml not found at %s", self._path)
            return
        if mtime <= self._mtime:
            return
        try:
            rules = _load_rules(self._path)
            self._rules = rules
            self._mtime = mtime
            log.info("Loaded %d keyword rules from %s", len(rules), self._path)
            if not any(r.priority == "critical" for r in rules):
                log.warning(
                    "No 'critical' priority rules loaded — the regex-only "
                    "Gotify alert path will never fire (the LLM extraction "
                    "layer can still alert independently). Add a 'critical' "
                    "rule to %s if you want regex-level alerting too.",
                    self._path,
                )
        except Exception as exc:
            log.error("Failed to reload keywords.yaml: %s", exc)

    def maybe_reload(self) -> None:
        """Check mtime and reload if changed — called before each collector run."""
        try:
            mtime = self._path.stat().st_mtime
        except FileNotFoundError:
            return
        if mtime > self._mtime:
            self.reload()

    def match(self, item: Item) -> list[Match]:
        """Run all rules against title + snippet; return Match objects with spans."""
        self.maybe_reload()
        haystack = item.title + "\n" + item.snippet
        title_len = len(item.title) + 1  # +1 for '\n'
        results: list[Match] = []
        for rule in self._rules:
            spans: list[tuple[int, int]] = []
            try:
                for m in rule.compiled.finditer(haystack, timeout=_MATCH_TIMEOUT_SECONDS):
                    spans.append((m.start(), m.end()))
            except TimeoutError:
                log.warning(
                    "Rule pattern exceeded %.1fs match budget — skipped for this item: %r",
                    _MATCH_TIMEOUT_SECONDS,
                    rule.pattern,
                )
                continue
            if spans:
                results.append(
                    Match(
                        item_id=item.id,
                        keyword_pattern=rule.pattern,
                        priority=rule.priority,
                        tags=list(rule.tags),
                        spans=spans,
                    )
                )
        return results

    def validate_yaml(self, raw_yaml: str) -> tuple[bool, str]:
        """Validate and dry-compile rules from a YAML string. Returns (ok, error_msg)."""
        try:
            rules = _load_rules_from_text(raw_yaml)
            return True, f"OK — {len(rules)} rules compiled"
        except Exception as exc:
            return False, str(exc)

    def reload_from_text(self, raw_yaml: str) -> tuple[bool, str]:
        ok, msg = self.validate_yaml(raw_yaml)
        if not ok:
            return False, msg
        self._path.write_text(raw_yaml, encoding="utf-8")
        self._mtime = 0.0  # force reload
        self.reload()
        return True, msg

    @property
    def has_critical_rules(self) -> bool:
        return any(r.priority == "critical" for r in self._rules)

    @property
    def rules_raw(self) -> str:
        try:
            return self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return ""


# ── helpers ────────────────────────────────────────────────────────────────────

def _load_rules(path: Path) -> list[Rule]:
    text = path.read_text(encoding="utf-8")
    return _load_rules_from_text(text)


def _load_rules_from_text(text: str) -> list[Rule]:
    data = yaml.safe_load(text) or []
    rules: list[Rule] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        pattern = entry.get("pattern", "")
        if not pattern:
            continue
        if len(pattern) > _MAX_PATTERN_LENGTH:
            raise ValueError(
                f"Pattern exceeds max length of {_MAX_PATTERN_LENGTH} chars: {pattern[:60]}..."
            )
        compiled = re.compile(pattern)  # raises re.error on bad pattern
        rules.append(
            Rule(
                pattern=pattern,
                compiled=compiled,
                priority=entry.get("priority", "info"),
                tags=entry.get("tags", []),
                notes=entry.get("notes", ""),
            )
        )
    return rules


def highlight_text(text: str, spans: list[tuple[int, int]], priority: str) -> str:
    """Insert <mark> tags into text at the given char offsets."""
    if not spans:
        return text
    out: list[str] = []
    prev = 0
    for start, end in sorted(spans):
        out.append(text[prev:start])
        out.append(f'<mark class="prio-{priority}">{text[start:end]}</mark>')
        prev = end
    out.append(text[prev:])
    return "".join(out)


# ── module-level singleton ─────────────────────────────────────────────────────
matcher = Matcher()
