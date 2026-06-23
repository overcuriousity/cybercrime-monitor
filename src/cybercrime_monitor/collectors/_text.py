"""Shared text/date helpers for collectors — strip_html and parse_date were
copy-pasted with minor drift across nitter.py/mastodon.py/hibp.py (HTML
stripping) and html_forum.py/hibp.py/rss.py/nitter.py/mastodon.py/
ransomware_live.py (date parsing). This is the single shared implementation;
parse_date tries each collector's original format strategy in turn, so it's
a superset of what every individual collector previously accepted.
"""
import re
from datetime import datetime
from email.utils import parsedate_to_datetime

_HTML_TAG_RE = re.compile(r"<[^>]+>")

# Fallback strptime formats, tried after the RFC822 (parsedate_to_datetime)
# and ISO8601 (fromisoformat) attempts below — covers html_forum.py's
# space-separated, US-slash, and dd-mm-yyyy listing-page date formats.
_STRPTIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y, %I:%M %p",
    "%d-%m-%Y",
    "%Y-%m-%d",
)


def strip_html(s: str) -> str:
    """Strip HTML tags and surrounding whitespace from a snippet/summary."""
    return _HTML_TAG_RE.sub("", s).strip()


def parse_date(s: str) -> datetime | None:
    """Parse a timestamp string from any collector's source format. Tries,
    in order: RFC822 (email/RSS dates, e.g. nitter/rss feeds), ISO8601 (with
    a trailing "Z" normalized to "+00:00", e.g. mastodon/ransomware_live),
    then a list of stricter strptime formats (html_forum listing pages,
    hibp's plain "YYYY-MM-DD"). Returns None if nothing matches."""
    if not s:
        return None
    s = s.strip()
    try:
        return parsedate_to_datetime(s)
    except Exception:
        pass
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        pass
    for fmt in _STRPTIME_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None
