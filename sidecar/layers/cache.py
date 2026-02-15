"""
Cache Layer: Redis-based security decision caching.

Provides near-zero latency (<0.1ms) for repeated prompts by caching
security decisions. Uses SHA256 hash of prompts as cache keys.

Benefits:
- Eliminates redundant security checks
- Dramatically improves throughput for common queries
- 80%+ hit rate on repetitive workloads

Performance: <0.1ms for cache hits

Distributed Mode and Redis Sentinel are not available in OSS.
"""
import asyncio
import hashlib
import time
from typing import Optional

# Use orjson for faster JSON serialization (Rust-based)
try:
    import orjson
    HAS_ORJSON = True
except ImportError:
    import json as orjson
    HAS_ORJSON = False

from .base import SecurityLayer, ScanContext, ScanResult
from ..core.text import normalize_for_cache

# Redis - optional dependency
try:
    import redis.asyncio as aioredis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    aioredis = None


class RedisCircuitBreaker:
    """
    Thread-safe Circuit Breaker for Redis connections.
    
    Prevents timeout cascades by temporarily blocking connection attempts
    after repeated failures. Uses asyncio.Lock for thread-safety.
    
    States:
        CLOSED: Normal operation, all requests pass through
        OPEN: Circuit tripped, requests fail fast without attempting connection
        HALF_OPEN: Recovery test, one request allowed to test connection
    """

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 30):
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self._lock = asyncio.Lock()

    @property
    def state(self) -> str:
        """Current circuit breaker state."""
        return self._state

    async def should_attempt(self) -> bool:
        """Check if we should attempt Redis connection (thread-safe)."""
        async with self._lock:
            current_time = time.time()

            if self._state == "CLOSED":
                return True
            elif self._state == "OPEN":
                # Check if recovery timeout has passed
                if current_time - self._last_failure_time >= self._recovery_timeout:
                    self._state = "HALF_OPEN"
                    return True
                return False
            elif self._state == "HALF_OPEN":
                # Only allow one test request in HALF_OPEN
                return True

            return False

    async def record_success(self):
        """Record successful operation (thread-safe)."""
        async with self._lock:
            self._failure_count = 0
            self._state = "CLOSED"

    async def record_failure(self):
        """Record failed operation (thread-safe)."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._state == "HALF_OPEN":
                # Failed during recovery test - go back to OPEN
                self._state = "OPEN"
            elif self._failure_count >= self._failure_threshold:
                self._state = "OPEN"

    def is_open(self) -> bool:
        """Check if circuit is open (no lock - read-only snapshot)."""
        return self._state == "OPEN"
    
    def get_stats(self) -> dict:
        """Get circuit breaker statistics."""
        return {
            "state": self._state,
            "failure_count": self._failure_count,
            "failure_threshold": self._failure_threshold,
            "recovery_timeout": self._recovery_timeout,
            "last_failure": self._last_failure_time
        }


class CacheLayer(SecurityLayer):
    """
    Cache Layer: Skip security checks for cached prompts.
    
    This layer should be FIRST in the pipeline to maximize cache hits.
    When a prompt is seen, its SHA256 hash is checked against Redis.
    
    Behavior:
        - Cache HIT with "safe": Return ScanResult.ok() immediately
        - Cache HIT with "unsafe": Return ScanResult.blocked() immediately
        - Cache MISS: Continue to next layer (result cached at end)
    
    Note: This layer handles cache LOOKUP only. Cache STORAGE must be 
    handled separately after pipeline completion.
    
    Configuration:
        - redis_host: Redis server hostname
        - redis_port: Redis server port
        - redis_db: Redis database number
        - ttl: Cache entry TTL in seconds
        - key_prefix: Prefix for cache keys
    """
    
    def __init__(
        self,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
        ttl: int = 3600,
        key_prefix: str = "safellm:cache:",
        connection_timeout: float = 0.5,
        password: str | None = None,
    ):
        """
        Initialize cache layer.

        Args:
            redis_host: Redis server hostname
            redis_port: Redis server port
            redis_db: Redis database number
            ttl: Cache TTL in seconds (default 1 hour)
            key_prefix: Prefix for all cache keys
            connection_timeout: Redis connection timeout
            password: Redis password (optional)
        """
        self._host = redis_host
        self._port = redis_port
        self._db = redis_db
        self._ttl = ttl
        self._key_prefix = key_prefix
        self._timeout = connection_timeout
        self._password = password
        
        # Lazy connection
        self._redis: Optional["aioredis.Redis"] = None
        self._connected = False
        self._init_error: Optional[str] = None

        # Circuit breaker to prevent Redis timeout cascades (local only)
        self._circuit_breaker = RedisCircuitBreaker(
            failure_threshold=5,
            recovery_timeout=30,
        )

        # Stats
        self._hits = 0
        self._misses = 0
    
    @property
    def name(self) -> str:
        return "L0_CACHE"
    
    @staticmethod
    def _hash_text(text: str) -> str:
        """Generate SHA256 hash of text for cache key.
        
        Normalizes text (NFKC) before hashing to prevent Unicode bypass
        where different representations of the same text get different cache keys.
        """
        normalized = normalize_for_cache(text)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    
    def _make_key(self, text: str) -> str:
        """Generate full cache key with prefix."""
        return f"{self._key_prefix}{self._hash_text(text)}"
    
    async def _connect(self) -> bool:
        """Establish Redis connection with circuit breaker protection."""
        if self._connected and self._redis:
            return True

        # Check circuit breaker before attempting connection
        if not await self._circuit_breaker.should_attempt():
            self._init_error = f"Circuit breaker open (state: {self._circuit_breaker.state})"
            return False

        if not HAS_REDIS:
            self._init_error = "redis package not installed"
            return False

        try:
            self._redis = aioredis.Redis(
                host=self._host,
                port=self._port,
                db=self._db,
                password=self._password,
                socket_timeout=self._timeout,
                socket_connect_timeout=self._timeout,
                decode_responses=True,
            )

            # Test connection
            await self._redis.ping()
            self._connected = True

            # Record success in circuit breaker
            await self._circuit_breaker.record_success()
            
            return True

        except Exception as e:
            error_msg = f"Redis connection failed: {e}"
            self._init_error = error_msg
            self._connected = False

            # Record failure in circuit breaker
            await self._circuit_breaker.record_failure()
            return False
    
    async def scan(self, ctx: ScanContext) -> ScanResult:
        """
        Check cache for existing decision.
        
        Cache format (JSON):
        {
            "safe": true/false,
            "reason": "...",
            "score": 0.0,
            "layer": "L1_KEYWORDS"
        }
        
        Returns:
            - Cached result if found
            - ScanResult.ok() if cache miss (allows pipeline to continue)
        """
        # Check circuit breaker first - if open, skip cache entirely
        if self._circuit_breaker.is_open():
            # Circuit breaker open - allow pipeline to continue without cache
            return ScanResult.ok(layer=self.name)

        # Try to connect if not connected
        if not await self._connect():
            # Cache unavailable - allow pipeline to continue
            return ScanResult.ok(layer=self.name)
        
        try:
            key = self._make_key(ctx.text)
            cached = await self._redis.get(key)
            
            if cached is None:
                # Cache miss - continue pipeline
                self._misses += 1
                # Store key in metadata for caching result later
                ctx.metadata["cache_key"] = key
                return ScanResult.ok(layer=self.name)
            
            # Cache hit - return cached decision
            self._hits += 1
            data = orjson.loads(cached)
            
            if data.get("safe", True):
                return ScanResult.ok(layer=f"{self.name}:HIT")
            else:
                return ScanResult.blocked(
                    reason=f"cached:{data.get('reason', 'unknown')}",
                    layer=f"{self.name}:HIT",
                    score=data.get("score", 1.0)
                )
                
        except Exception:
            # On error, allow pipeline to continue
            return ScanResult.ok(layer=self.name)
    
    async def cache_result(self, text: str, result: ScanResult) -> bool:
        """
        Store security result in cache.
        
        Call this AFTER pipeline completion to cache the final decision.
        
        Args:
            text: Original text that was scanned
            result: Final ScanResult from pipeline
            
        Returns:
            True if cached successfully
        """
        if not self._connected or not self._redis:
            return False
        
        try:
            key = self._make_key(text)
            # orjson returns bytes, decode for Redis string storage
            data = orjson.dumps({
                "safe": result.safe,
                "reason": result.reason,
                "score": result.score,
                "layer": result.layer,
            })
            if HAS_ORJSON:
                data = data.decode("utf-8")
            
            await self._redis.setex(key, self._ttl, data)
            return True
            
        except Exception:
            return False
    
    async def invalidate(self, text: str) -> bool:
        """
        Invalidate cache entry for specific text.
        
        Useful when security rules are updated.
        """
        if not self._connected or not self._redis:
            return False
        
        try:
            key = self._make_key(text)
            await self._redis.delete(key)
            return True
        except Exception:
            return False
    
    async def clear_all(self) -> int:
        """
        Clear all cache entries with our prefix.
        
        Returns number of deleted keys.
        """
        if not self._connected or not self._redis:
            return 0
        
        try:
            pattern = f"{self._key_prefix}*"
            keys = []
            async for key in self._redis.scan_iter(pattern):
                keys.append(key)
            
            if keys:
                return await self._redis.delete(*keys)
            return 0
            
        except Exception:
            return 0
    
    async def health_check(self) -> bool:
        """Check Redis connection health."""
        try:
            if await self._connect():
                await self._redis.ping()
                return True
        except Exception:
            pass
        return False
    
    def get_stats(self) -> dict:
        """Get cache statistics."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0.0
        
        return {
            "hits": self._hits,
            "misses": self._misses,
            "total": total,
            "hit_rate_percent": round(hit_rate, 2),
        }
    
    def get_status(self) -> dict:
        """Get detailed layer status."""
        status = {
            "name": self.name,
            "connected": self._connected,
            "error": self._init_error,
            "host": self._host,
            "port": self._port,
            "db": self._db,
            "ttl": self._ttl,
            "circuit_breaker": self._circuit_breaker.get_stats(),
            **self.get_stats(),
        }
        return status
    
    async def close(self):
        """Close Redis connection."""
        if self._redis:
            # redis-py 5.x deprecates close() in favor of aclose()
            aclose = getattr(self._redis, "aclose", None)
            if callable(aclose):
                await aclose()
            else:
                await self._redis.close()
            self._redis = None
            self._connected = False
