"""
Redis Connection Factory (OSS).

Supports standalone Redis only. Sentinel/HA is not available in OSS.

Usage:
    from .redis_client import get_redis_client, get_redis_config
    
    redis = await get_redis_client()
    await redis.ping()

Environment Variables:
    REDIS_HOST=localhost
    REDIS_PORT=6379
    REDIS_DB=0
    REDIS_PASSWORD=<optional>
    REDIS_TIMEOUT=0.5
"""
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

# Redis - optional dependency
try:
    import redis.asyncio as aioredis
    HAS_REDIS = True
except ImportError:
    aioredis = None
    HAS_REDIS = False


@dataclass
class RedisConfig:
    """Redis connection configuration."""
    
    # Standalone mode
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    timeout: float = 0.5


@lru_cache
def get_redis_config() -> RedisConfig:
    """
    Load Redis configuration from environment.
    
    Returns cached config - call get_redis_config.cache_clear() to reload.
    """
    return RedisConfig(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        db=int(os.getenv("REDIS_DB", "0")),
        password=os.getenv("REDIS_PASSWORD"),
        timeout=float(os.getenv("REDIS_TIMEOUT", "0.5")),
    )


async def get_redis_client(
    config: Optional[RedisConfig] = None,
    decode_responses: bool = True,
) -> "aioredis.Redis":
    """
    Get standalone Redis client.
    
    Args:
        config: Optional config override (uses env vars if None)
        decode_responses: Return strings instead of bytes
        
    Returns:
        Async Redis client
        
    Raises:
        ImportError: If redis package not installed
        ConnectionError: If unable to connect
    """
    if not HAS_REDIS:
        raise ImportError("redis package not installed: pip install redis")
    
    cfg = config or get_redis_config()
    
    return await _get_standalone_client(cfg, decode_responses)


async def _get_standalone_client(
    cfg: RedisConfig,
    decode_responses: bool,
) -> "aioredis.Redis":
    """Create standalone Redis client."""
    client = aioredis.Redis(
        host=cfg.host,
        port=cfg.port,
        db=cfg.db,
        password=cfg.password,
        socket_timeout=cfg.timeout,
        socket_connect_timeout=cfg.timeout,
        decode_responses=decode_responses,
    )
    
    # Test connection
    await client.ping()
    
    return client


def create_sync_redis_client(
    config: Optional[RedisConfig] = None,
) -> "aioredis.Redis":
    """
    Create synchronous Redis client (for non-async contexts).
    """
    import redis
    
    cfg = config or get_redis_config()

    return redis.Redis(
        host=cfg.host,
        port=cfg.port,
        db=cfg.db,
        password=cfg.password,
        socket_timeout=cfg.timeout,
    )
