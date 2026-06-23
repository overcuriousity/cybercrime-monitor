import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .. import health
from ..db import load_health_snapshot, open_db
from ..scheduler import build_scheduler, load_sources
from ..settings import settings
from ..sources.value import validate_sources
from .sse import broadcaster
from .routes import router

log = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"


class _TokenBucket:
    """Per-IP rate limit on /api/* — this dashboard is meant for one
    analyst's browser, not arbitrary public traffic (see admin_token's
    docstring in settings.py for the same publicly-reachable assumption).
    A plain in-memory dict is fine for a single-worker process (the app
    already requires single-worker — see settings.py / README note); it
    resets on restart, which is an acceptable tradeoff for "throttle abuse,"
    not a security boundary in itself."""

    def __init__(self, rate_per_minute: int) -> None:
        self.capacity = max(1, rate_per_minute)
        self.refill_per_second = self.capacity / 60.0
        self._buckets: dict[str, tuple[float, float]] = {}  # ip -> (tokens, last_refill_monotonic)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(key, (float(self.capacity), now))
        tokens = min(self.capacity, tokens + (now - last) * self.refill_per_second)
        if tokens < 1.0:
            self._buckets[key] = (tokens, now)
            return False
        self._buckets[key] = (tokens - 1.0, now)
        return True


def _assert_no_data_under_static() -> None:
    """StaticFiles is mounted at "/" — anything placed under this directory is
    served to the public with zero gating. A stray static/data/items.db once
    shipped here and was reachable at /data/items.db. Fail loudly at startup
    instead of silently re-leaking the DB if a future copy/deploy step drops
    a data file back in here."""
    bad = [p for p in _STATIC_DIR.rglob("*") if p.is_file() and p.suffix.startswith(".db")]
    if bad:
        raise RuntimeError(
            f"Refusing to start: {len(bad)} *.db file(s) found under the publicly-served "
            f"static directory ({_STATIC_DIR}) — e.g. {bad[0]}. Remove them; the live DB "
            f"belongs under settings.db_path, never under api/static/."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db = await open_db()
    validate_sources(load_sources())
    # Restore health.py's in-memory registry from its last periodic snapshot
    # (see scheduler.py's "_health_persist" job) BEFORE the scheduler starts
    # ticking, so the first /api/sources response after a restart already
    # reflects pre-restart health instead of every source showing "unknown".
    health.restore(await load_health_snapshot(app.state.db))
    scheduler = build_scheduler(app.state.db, broadcaster)
    scheduler.start()
    app.state.scheduler = scheduler  # exposed for /healthz (routes.py)
    log.info("Scheduler started")
    yield
    scheduler.shutdown(wait=False)
    await app.state.db.close()
    log.info("Shutdown complete")


def create_app() -> FastAPI:
    _assert_no_data_under_static()
    app = FastAPI(title="Cybercrime Monitor", lifespan=lifespan)

    if settings.rate_limit_per_minute > 0:
        bucket = _TokenBucket(settings.rate_limit_per_minute)

        @app.middleware("http")
        async def rate_limit_middleware(request: Request, call_next):
            if request.url.path.startswith("/api/"):
                client_ip = request.client.host if request.client else "unknown"
                if not bucket.allow(client_ip):
                    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
            return await call_next(request)

    app.include_router(router)
    app.mount("/", StaticFiles(directory=str(_STATIC_DIR), html=True), name="static")
    return app
