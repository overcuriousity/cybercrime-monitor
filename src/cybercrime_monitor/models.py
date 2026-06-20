from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Item:
    source_id: str
    source_name: str
    title: str
    url: str
    snippet: str = ""
    published_at: datetime | None = None
    # SHA256(source_id + url) — computed in base collector
    dedupe_key: str = ""
    # Cross-source clustering signal — computed in base collector from
    # normalized title (or extra.actor+victim when structured data is
    # available). Two items from DIFFERENT sources sharing a content_key are
    # presumed to be the same underlying incident reported twice. Empty
    # string means "don't cluster this item" (e.g. blank title).
    content_key: str = ""
    # injected after DB insert
    id: int = 0
    seen_at: datetime | None = None
    # tags from sources.yaml (e.g. ["tor", "forum"])
    source_tags: list[str] = field(default_factory=list)
    # raw extras (json-serialisable dict for future extension)
    extra: dict[str, Any] = field(default_factory=dict)
