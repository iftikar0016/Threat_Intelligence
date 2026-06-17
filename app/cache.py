import time
import json
import logging
from typing import Optional

try:
    import redis
except ImportError:
    redis = None

from app.config import settings

logger = logging.getLogger("cache")


class InMemoryCache:
    def __init__(self):
        self._store: dict[str, tuple[str, float]] = {}
        logger.info("Initialized InMemoryCache")

    def get(self, key: str) -> Optional[str]:
        item = self._store.get(key)
        if not item:
            return None
        value, expires_at = item
        if expires_at < time.time():
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: str, ttl: int) -> None:
        self._store[key] = (value, time.time() + ttl)

    def delete(self, key: str) -> bool:
        return self._store.pop(key, None) is not None


class RedisCache:
    def __init__(self, url: str):
        self._client = redis.from_url(url, decode_responses=True)
        # Validate connection on startup
        self._client.ping()
        logger.info("Successfully connected to Redis cache at %s", url)

    def get(self, key: str) -> Optional[str]:
        try:
            return self._client.get(key)
        except Exception as e:
            logger.warning("Redis GET failed, returning None: %s", e)
            return None

    def set(self, key: str, value: str, ttl: int) -> None:
        try:
            self._client.setex(key, ttl, value)
        except Exception as e:
            logger.warning("Redis SETEX failed: %s", e)

    def delete(self, key: str) -> bool:
        try:
            return bool(self._client.delete(key))
        except Exception as e:
            logger.warning("Redis DELETE failed: %s", e)
            return False


# Determine which cache backend to use
if redis and settings.redis_url and not settings.redis_url.startswith("memory://"):
    try:
        _cache = RedisCache(settings.redis_url)
    except Exception as e:
        logger.warning("Redis init/ping failed, falling back to in-memory cache: %s", e)
        _cache = InMemoryCache()
else:
    _cache = InMemoryCache()


def cache_key(indicator_type: str, value: str) -> str:
    return f"ti:{indicator_type}:{value.lower().strip()}"


def get_cached(key: str) -> Optional[dict]:
    raw = _cache.get(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception as e:
        logger.error("Failed to decode cached JSON for key %s: %s", key, e)
        return None


def set_cached(key: str, payload: dict, ttl: Optional[int] = None) -> None:
    ttl = ttl if ttl is not None else settings.cache_ttl_seconds
    try:
        _cache.set(key, json.dumps(payload), ttl)
    except Exception as e:
        logger.error("Failed to cache payload for key %s: %s", key, e)


def delete_cached(key: str) -> bool:
    return _cache.delete(key)
