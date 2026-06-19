"""httpx client factory — clearnet and Tor-routed variants."""
import random
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx
from httpx_socks import AsyncProxyTransport

from .settings import settings

_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

_BASE_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",  # no br — httpx can't decompress Brotli without extra dep
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


def _random_headers() -> dict[str, str]:
    return {**_BASE_HEADERS, "User-Agent": random.choice(_USER_AGENTS)}


@asynccontextmanager
async def clearnet_client(timeout: float = 30.0) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        headers=_random_headers(),
        timeout=timeout,
        follow_redirects=True,
        limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
    ) as client:
        yield client


@asynccontextmanager
async def tor_client(timeout: float = 90.0) -> AsyncIterator[httpx.AsyncClient]:
    """httpx client routed through the Tor SOCKS proxy.

    rdns=True is required so .onion hostnames are resolved by Tor, not locally.
    socks5h:// is not supported by this version of httpx-socks; use socks5:// + rdns.
    """
    # Strip socks5h:// scheme — rdns=True handles remote DNS resolution instead
    proxy_url = settings.tor_socks.replace("socks5h://", "socks5://")
    # verify=False: .onion sites use self-signed certs; Tor addressing is the authenticator
    transport = AsyncProxyTransport.from_url(proxy_url, rdns=True, verify=False)
    async with httpx.AsyncClient(
        transport=transport,
        headers=_random_headers(),
        timeout=timeout,
        follow_redirects=True,
    ) as client:
        yield client
