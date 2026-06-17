import logging
import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.config import settings
from app.detector import detect_indicator_type, normalize, IndicatorType
from app.cache import cache_key, get_cached, set_cached, delete_cached
from app.aggregator import aggregate

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI(title="Threat Intelligence Lookup Service", version="1.0.0")

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins.split(",") if settings.allowed_origins else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure static directory exists
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")


class LookupRequest(BaseModel):
    indicator: str
    force_refresh: bool = False


@app.get("/")
async def index():
    index_path = "static/index.html"
    if os.path.exists(index_path):
        return FileResponse(index_path)
    raise HTTPException(status_code=404, detail="Index HTML not found")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "vt_configured": bool(settings.vt_api_key),
        "otx_configured": bool(settings.otx_api_key),
        "redis_configured": settings.redis_url and not settings.redis_url.startswith("memory://")
    }


@app.post("/lookup")
async def lookup(req: LookupRequest):
    value = req.indicator.strip()
    if not value:
        raise HTTPException(400, "Indicator is required")

    kind = detect_indicator_type(value)
    if kind == IndicatorType.UNKNOWN:
        raise HTTPException(400, "Could not detect indicator type. Must be a URL, domain, IP address, or file hash (MD5, SHA-1, SHA-256)")

    normalized = normalize(value, kind)
    key = cache_key(kind.value, normalized)

    # 1. Try cache
    if not req.force_refresh:
        cached = get_cached(key)
        if cached:
            cached["served_from_cache"] = True
            logger.info("Cache hit for indicator [%s] type [%s]", normalized, kind.value)
            return cached

    # 2. Run fresh aggregation
    logger.info("Cache miss or force refresh for indicator [%s] type [%s]. Querying APIs...", normalized, kind.value)
    result = await aggregate(normalized, kind)
    result["served_from_cache"] = False

    # 3. Save to cache
    set_cached(key, result, ttl=settings.cache_ttl_seconds)
    return result


@app.get("/lookup/{indicator:path}")
async def lookup_get(indicator: str, force_refresh: bool = False):
    return await lookup(LookupRequest(indicator=indicator, force_refresh=force_refresh))


@app.delete("/cache/{indicator_type}/{indicator}")
async def clear_cache(indicator_type: str, indicator: str):
    key = cache_key(indicator_type, indicator.lower().strip())
    deleted = delete_cached(key)
    logger.info("Cache eviction for key [%s]: success=%s", key, deleted)
    return JSONResponse({"deleted": deleted, "key": key})
