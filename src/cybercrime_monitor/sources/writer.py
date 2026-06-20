"""Safe, comment-preserving writer for config/sources.yaml — the prerequisite
that lets research/heal.py and research/discover.py actually apply their
proposals instead of just logging them (see those modules' docstrings for
why that stance changed from the original advisory-only design).

config/sources.yaml.example is densely hand-annotated (every disabled
source has a `# needs: ...` comment explaining why) — plain
`yaml.safe_dump` would silently destroy all of that on the first autonomous
edit. ruamel.yaml's round-trip mode preserves comments, key order and
quoting style, so an autonomous edit looks like a human made a single
surgical change, not a wholesale file rewrite.

Every write is preceded by a timestamped backup so any autonomous change is
trivially revertible (`cp sources.yaml.bak-<ts> sources.yaml`), and the
write itself is atomic (temp file + os.replace) so a crash mid-write can
never leave a half-written, unparseable sources.yaml behind.
"""
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from ..settings import settings

log = logging.getLogger(__name__)

_yaml = YAML()
_yaml.preserve_quotes = True
_yaml.indent(mapping=2, sequence=4, offset=2)
_yaml.width = 4096  # don't auto-wrap long URLs


def _now_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _path() -> Path:
    return settings.sources_config


def _load() -> CommentedMap:
    path = _path()
    with path.open("r", encoding="utf-8") as f:
        data = _yaml.load(f)
    if data is None:
        data = CommentedMap({"sources": []})
    return data


def _backup(path: Path) -> Path:
    backup_path = path.with_name(f"{path.name}.bak-{_now_tag()}")
    backup_path.write_bytes(path.read_bytes())
    return backup_path


def _atomic_write(path: Path, data: CommentedMap) -> None:
    tmp_path = path.with_name(f"{path.name}.tmp-{_now_tag()}")
    with tmp_path.open("w", encoding="utf-8") as f:
        _yaml.dump(data, f)
    tmp_path.replace(path)  # atomic on POSIX


def _find_source(data: CommentedMap, source_id: str) -> CommentedMap | None:
    for src in data.get("sources", []):
        if isinstance(src, CommentedMap) and src.get("id") == source_id:
            return src
    return None


class SourceWriteError(Exception):
    pass


def update_field(source_id: str, *, reason: str, **fields: Any) -> tuple[dict, dict]:
    """Set one or more fields on an existing source entry (e.g. url=...,
    enabled=True). Returns (before, after) snapshots of just the changed
    fields, for the audit trail (db.record_applied_change)."""
    path = _path()
    data = _load()
    src = _find_source(data, source_id)
    if src is None:
        raise SourceWriteError(f"source {source_id!r} not found in {path}")

    before = {k: src.get(k) for k in fields}
    _backup(path)
    for k, v in fields.items():
        src[k] = v
    src["_auto_note"] = f"[auto] {reason} ({_now_tag()})"
    _atomic_write(path, data)
    after = {k: src.get(k) for k in fields}
    log.info("[sources/writer] updated %s: %s -> %s (%s)", source_id, before, after, reason)
    return before, after


def disable(source_id: str, *, reason: str) -> tuple[dict, dict]:
    return update_field(source_id, reason=reason, enabled=False)


def enable(source_id: str, *, reason: str) -> tuple[dict, dict]:
    return update_field(source_id, reason=reason, enabled=True)


def remove(source_id: str, *, reason: str) -> dict:
    """Delete a source entry outright (used after a prune grace period of
    continued non-value following disable() — see research/heal.py).
    Returns the removed entry's snapshot for the audit trail."""
    path = _path()
    data = _load()
    sources = data.get("sources", [])
    idx = next(
        (i for i, s in enumerate(sources) if isinstance(s, CommentedMap) and s.get("id") == source_id),
        None,
    )
    if idx is None:
        raise SourceWriteError(f"source {source_id!r} not found in {path}")
    before = dict(sources[idx])
    _backup(path)
    del sources[idx]
    _atomic_write(path, data)
    log.info("[sources/writer] removed %s (%s)", source_id, reason)
    return before


def add(entry: dict, *, reason: str) -> dict:
    """Append a new source entry (research/discover.py) — added as
    probationary (caller should set tags/source_tags to mark it so, e.g.
    "probationary") so sources/value.py can evaluate and the loop can prune
    it automatically if it doesn't pan out within the evaluation window."""
    path = _path()
    data = _load()
    sources = data.setdefault("sources", [])
    if _find_source(data, entry["id"]) is not None:
        raise SourceWriteError(f"source id {entry['id']!r} already exists")
    _backup(path)
    new_entry = CommentedMap(entry)
    new_entry["_auto_note"] = f"[auto] {reason} ({_now_tag()})"
    sources.append(new_entry)
    _atomic_write(path, data)
    log.info("[sources/writer] added new source %s (%s)", entry["id"], reason)
    return dict(entry)
