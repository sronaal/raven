import time
import logging

logger = logging.getLogger(__name__)

_cache = {}

def get_or_compute(key: str, ttl_seconds: int, compute_fn):
    now = time.time()
    entry = _cache.get(key)
    if entry and (now - entry["timestamp"]) < ttl_seconds:
        logger.debug(f"Cache hit for key: {key}")
        return entry["result"]
    logger.debug(f"Cache miss for key: {key}, computing...")
    result = compute_fn()
    _cache[key] = {"result": result, "timestamp": now}
    return result

async def get_or_compute_async(key: str, ttl_seconds: int, compute_fn):
    now = time.time()
    entry = _cache.get(key)
    if entry and (now - entry["timestamp"]) < ttl_seconds:
        logger.debug(f"Cache hit for key: {key}")
        return entry["result"]
    logger.debug(f"Cache miss for key: {key}, computing...")
    result = await compute_fn()
    _cache[key] = {"result": result, "timestamp": now}
    return result

def invalidate(key: str):
    _cache.pop(key, None)

def clear():
    _cache.clear()

def get_stats():
    return {
        "entries": len(_cache),
        "keys": list(_cache.keys()),
    }
