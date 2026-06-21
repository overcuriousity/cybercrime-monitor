"""Embedding backend — two interchangeable transports behind one API,
selected by settings.embed_backend (see that setting's docstring for the
full rationale):
  - "local": fastembed (ONNX, no torch) running settings.embed_local_model
    in-process. Zero external config; the model downloads once on first use
    and is cached on disk after that.
  - "openai": a plain OpenAI-compatible /embeddings endpoint — reuses
    llm_base_url/llm_api_key unless embed_base_url/embed_api_key override
    them.
  - "none": embeddings disabled entirely.

This is deliberately a separate module from llm/backend.py: embeddings are
a different call shape (/embeddings, not /chat/completions) and the default
transport doesn't depend on any LLM server being reachable at all.

INTEGRITY: active_fingerprint() identifies "how vectors currently in the DB
were produced" (backend + model/endpoint). embeddings/index.py compares this
against what's stored in the embedding_meta table on every startup and
forces a full re-index on any mismatch — see that module's docstring. Never
weaken or bypass that check; mixing vectors from two different embedding
spaces makes every similarity score meaningless without any visible error.
"""
import asyncio
import hashlib
import logging

import httpx

from ..settings import settings

log = logging.getLogger(__name__)

# Lazy singleton — loading/downloading the ONNX model is expensive, so it
# only happens on the first actual embed call (not at import time), and is
# reused across calls as long as the configured model name doesn't change.
_local_model = None
_local_model_name: str | None = None

# Per-fingerprint dimension cache (process-local) — see active_dim().
_dim_cache: dict[str, int] = {}


class EmbeddingUnavailable(Exception):
    """Raised when embed_backend == "none", or the configured backend fails
    outright (unreachable endpoint, model load failure). Callers (the
    embedding job, the semantic-search route) MUST surface this as
    "semantic search unavailable" — never silently fall back to keyword
    search. The two modes are distinct by design (see settings.embed_backend's
    docstring); a silent fallback would make a real misconfiguration look
    like "semantic search just doesn't find anything," which is far harder
    to notice and debug."""


# ── Local (fastembed) transport ─────────────────────────────────────────────

def _register_bge_m3_if_needed() -> None:
    """fastembed's built-in model registry doesn't include BAAI/bge-m3 (as
    of fastembed 0.8) even though the official BAAI/bge-m3 HF repo ships an
    onnx/model.onnx export — register it as a custom model on first use.
    Idempotent: skip if already registered (fastembed raises on a duplicate
    add_custom_model call, e.g. if this somehow runs twice in one
    process)."""
    from fastembed import TextEmbedding
    from fastembed.common.model_description import ModelSource, PoolingType

    if any(m["model"] == "BAAI/bge-m3" for m in TextEmbedding.list_supported_models()):
        return
    TextEmbedding.add_custom_model(
        model="BAAI/bge-m3",
        pooling=PoolingType.CLS,
        normalization=True,
        sources=ModelSource(hf="BAAI/bge-m3"),
        dim=1024,
        model_file="onnx/model.onnx",
        additional_files=["onnx/model.onnx_data"],
        description="BGE-M3 multilingual dense embedding (custom-registered — not in fastembed's built-in list)",
        license="mit",
        size_in_gb=2.3,
    )


def _get_local_model():
    global _local_model, _local_model_name
    from fastembed import TextEmbedding

    if _local_model is not None and _local_model_name == settings.embed_local_model:
        return _local_model
    if settings.embed_local_model == "BAAI/bge-m3":
        _register_bge_m3_if_needed()
    log.info(
        "[embeddings] loading local model %s (first use downloads it — may take a while)",
        settings.embed_local_model,
    )
    _local_model = TextEmbedding(model_name=settings.embed_local_model)
    _local_model_name = settings.embed_local_model
    return _local_model


def _embed_local_sync(texts: list[str]) -> list[list[float]]:
    try:
        model = _get_local_model()
        return [vec.tolist() for vec in model.embed(texts, batch_size=settings.embed_batch_size)]
    except Exception as e:  # model load/download failure, OOM, etc.
        raise EmbeddingUnavailable(f"local embedding backend failed: {e}") from e


async def _embed_local(texts: list[str]) -> list[list[float]]:
    # fastembed is sync/CPU-bound (ONNX runtime) — run off the event loop so
    # a batch embed never blocks ingest/SSE/other requests.
    return await asyncio.to_thread(_embed_local_sync, texts)


# ── OpenAI-compatible transport ─────────────────────────────────────────────

def _embed_auth_headers() -> dict[str, str]:
    key = settings.embed_api_key or settings.llm_api_key
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


async def _embed_openai(texts: list[str]) -> list[list[float]]:
    base = (settings.embed_base_url or settings.llm_base_url).rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{base}/embeddings",
                headers=_embed_auth_headers(),
                json={"model": settings.embed_model, "input": texts},
            )
            resp.raise_for_status()
            data = resp.json()
        by_index = {item["index"]: item["embedding"] for item in data["data"]}
        return [by_index[i] for i in range(len(texts))]
    except (httpx.HTTPError, KeyError, ValueError) as e:
        raise EmbeddingUnavailable(f"openai-compatible embeddings endpoint {base} failed: {e}") from e


# ── Public API ───────────────────────────────────────────────────────────────

async def embed_texts(texts: list[str]) -> list[list[float]]:
    """Embed a batch of strings with whatever backend is configured.
    Raises EmbeddingUnavailable if embed_backend == "none" or the backend
    call fails — see that exception's docstring for why callers must not
    catch-and-fall-back-to-keyword here."""
    if not texts:
        return []
    if settings.embed_backend == "none":
        raise EmbeddingUnavailable("embed_backend is 'none' — semantic search is disabled")
    if settings.embed_backend == "local":
        return await _embed_local(texts)
    if settings.embed_backend == "openai":
        return await _embed_openai(texts)
    raise EmbeddingUnavailable(f"unknown embed_backend: {settings.embed_backend!r}")


def active_fingerprint() -> str:
    """Identity of 'how vectors currently in the DB were produced.' Any
    change to embed_backend or the active model/endpoint changes this value
    — embeddings/index.py uses it to detect drift and force a full
    re-index on next startup rather than silently mixing two incompatible
    embedding spaces."""
    if settings.embed_backend == "local":
        key = f"local:{settings.embed_local_model}"
    elif settings.embed_backend == "openai":
        base = settings.embed_base_url or settings.llm_base_url
        key = f"openai:{base}:{settings.embed_model}"
    else:
        key = "none"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


async def active_dim() -> int:
    """Embedding dimensionality of the active backend/model — discovered
    with a one-off probe embed rather than a hardcoded per-model table, so
    any model the backend happens to support works without this module
    needing advance knowledge of its dimension. Cached per fingerprint for
    the life of the process (a fingerprint change means a different model,
    so the cache is never stale for a given key)."""
    fp = active_fingerprint()
    if fp not in _dim_cache:
        probe = await embed_texts(["dimension probe"])
        _dim_cache[fp] = len(probe[0])
    return _dim_cache[fp]
