"""collectors/_text.py — strip_html and parse_date, the shared helpers that
replaced near-identical copies in nitter.py/mastodon.py/hibp.py (HTML
stripping) and html_forum.py/hibp.py/rss.py/nitter.py/mastodon.py/
ransomware_live.py (date parsing). parse_date must keep accepting every
format each original collector relied on."""
from datetime import datetime, timezone

from cybercrime_monitor.collectors._text import parse_date, strip_html


def test_strip_html_removes_tags_and_trims_whitespace():
    assert strip_html("<p>hello <b>world</b></p>  ") == "hello world"


def test_strip_html_empty_string():
    assert strip_html("") == ""


def test_parse_date_rfc822_rss_format():
    # nitter.py / rss.py's RSS <pubDate> format.
    dt = parse_date("Wed, 02 Oct 2002 13:00:00 GMT")
    assert dt is not None
    assert dt.year == 2002 and dt.month == 10 and dt.day == 2


def test_parse_date_iso8601_with_z_suffix():
    # mastodon.py / ransomware_live.py's API timestamp format.
    dt = parse_date("2023-06-15T12:30:00Z")
    assert dt is not None
    assert dt.astimezone(timezone.utc).hour == 12


def test_parse_date_plain_yyyy_mm_dd():
    # hibp.py's breach-date format.
    dt = parse_date("2023-01-15")
    assert dt is not None
    assert (dt.year, dt.month, dt.day) == (2023, 1, 15)


def test_parse_date_space_separated():
    # html_forum.py's listing-page format.
    dt = parse_date("2023-01-01 08:30:00")
    assert dt == datetime(2023, 1, 1, 8, 30, 0)


def test_parse_date_us_slash_format():
    dt = parse_date("01/02/2023, 03:04 PM")
    assert dt == datetime(2023, 1, 2, 15, 4)


def test_parse_date_dd_mm_yyyy():
    dt = parse_date("15-03-2024")
    assert dt == datetime(2024, 3, 15)


def test_parse_date_empty_or_unparseable_returns_none():
    assert parse_date("") is None
    assert parse_date("not a date") is None
