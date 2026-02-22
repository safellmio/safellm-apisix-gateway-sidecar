"""
AuthService - Orchestrates security pipeline.

Waterfall Pipeline Architecture:
    L0: Cache (Redis SHA256) - <0.1ms
    L1: Keywords (FlashText) - <0.01ms  
    L1.5: PII (Presidio regex) - ~6-8ms

Request Coalescing:
    Deduplicates concurrent requests with the same prompt.
    Prevents the "thundering herd" effect when many users
    send the same prompt at the same time.
    
"""
import hashlib
from ..models import Decision
from ..core.settings import Settings, get_settings
from ..core.providers import (
    get_ai_guard_layer,
    get_request_coalescer,
    get_pii_layer,
    cleanup_ai_guard_models,
)

# Import pipeline components
from ..layers.keywords import KeywordLayer
from ..layers.cache import CacheLayer
from ..pipeline.engine import SecurityPipeline, PipelineResult


class AuthService:
    """
    Security orchestration service.
    
    Executes all enabled security layers in waterfall order.
    Short-circuits on first unsafe result.
    
    Features:
        - Waterfall pipeline (cache → keywords → PII)
        - Request coalescing (dedup concurrent identical requests)
        - Short-circuit on first unsafe result
    
    Usage:
        service = AuthService(settings)
        decision = await service.decide_async(body, uri, request_id)
    """
    
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._pipeline: SecurityPipeline | None = None
        
        # Request coalescer - deduplicates concurrent requests
        self._coalescer, _ = get_request_coalescer(self.settings)
        
        self._init_pipeline()
    
    def _init_pipeline(self) -> None:
        """
        Initialize security pipeline with enabled layers.
        
        Layer order (waterfall):
            1. L0_CACHE - Skip if cached result exists
            2. L1_KEYWORDS - Fast pattern matching
            3. L1.5_PII - PII detection (optional)
        """
        layers = []
        enabled = set()
        
        # L0: Cache (first - to short-circuit on cache hits)
        if self.settings.ENABLE_CACHE:
            cache = CacheLayer(
                redis_host=self.settings.REDIS_HOST,
                redis_port=self.settings.REDIS_PORT,
                redis_db=self.settings.REDIS_DB,
                ttl=self.settings.REDIS_TTL,
                connection_timeout=self.settings.REDIS_TIMEOUT,
                password=(
                    self.settings.REDIS_PASSWORD.get_secret_value()
                    if self.settings.REDIS_PASSWORD
                    else None
                ),
            )
            layers.append(cache)
            enabled.add("L0_CACHE")
        
        # L1: Keywords (ultra-fast FlashText)
        if self.settings.ENABLE_L1_KEYWORDS:
            keywords = KeywordLayer(self.settings.L1_BLOCKED_PHRASES)
            layers.append(keywords)
            enabled.add("L1_KEYWORDS")
        
        # L1.5: PII Detection
        # USE_FAST_PII=true: Fast regex (~1-2ms) - basic PII only (OSS)
        # OSS uses fast regex PII only
        pii = get_pii_layer(self.settings)
        if pii is not None:
            layers.append(pii)
            enabled.add(pii.name)  # Dynamic: "L1_PII_FAST_REGEX" or "L1_PII_GLINER"
        
        # L2: AI Guard (not available in OSS)
        ai_guard = get_ai_guard_layer(self.settings)
        if ai_guard is not None:
            layers.append(ai_guard)
            enabled.add("L2_AI_GUARD")
        
        if layers:
            self._pipeline = SecurityPipeline(
                layers=layers, 
                enabled_layers=enabled,
                cache_results=self.settings.ENABLE_CACHE,
                shadow_mode=self.settings.SHADOW_MODE,
                fail_open=self.settings.FAIL_OPEN,
            )
    
    async def decide_async(self, body: str, uri: str, request_id: str = "") -> PipelineResult:
        """
        Execute security pipeline on request.
        
        Uses request coalescing to deduplicate concurrent identical requests.
        When multiple users submit the same prompt simultaneously, only one
        scan is performed and all waiting requests get the result.
        
        Args:
            body: Request body text
            uri: Request URI (for context)
            request_id: Correlation ID for logging
            
        Returns:
            PipelineResult with decision, latency, and layer info
        """
        text = f"{uri} {body}".strip()
        
        if not self._pipeline:
            # No layers enabled - return minimal result
            return PipelineResult(
                decision=Decision(allowed=True, reason="no_layers_enabled"),
                total_latency_ms=0.0,
                layers_executed=0,
                stopping_layer=None
            )
        
        # Generate hash for request deduplication
        request_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        
        # Use coalescer to deduplicate concurrent identical requests
        # If another request with same hash is in-flight, we wait for it
        return await self._coalescer.coalesce(
            request_hash,
            lambda: self._pipeline.execute(text, request_id)
        )
    
    async def shutdown(self):
        """Graceful shutdown - cleanup coalescer, connections, and models."""
        await self._coalescer.shutdown()
        if self._pipeline and self._pipeline._cache_layer:
            await self._pipeline._cache_layer.close()
            
        # Cleanup heavy models
        try:
            from ..layers.pii_fast import cleanup_models as pii_cleanup
            pii_cleanup()
        except Exception:
            pass
            
        try:
            cleanup_ai_guard_models()
        except Exception:
            pass

        # Cleanup executors for other layers
        try:
            from ..layers.dlp import DLPScanner
            DLPScanner.cleanup_executor()
        except Exception:
            pass

        try:
            from ..layers.keywords import KeywordLayer
            KeywordLayer.cleanup_executor()
        except Exception:
            pass

        # Note: pii.py (Presidio layer) is not used in OSS pipeline,
        # but cleanup its executor if it was loaded by tests or imports.
        try:
            import sys
            if "sidecar.layers.pii" in sys.modules:
                from ..layers.pii import PIILayer as OldPIILayer
                OldPIILayer.cleanup_executor()
        except Exception:
            pass
    
    def get_stats(self) -> dict:
        """Get service statistics."""
        from ..edition import get_edition_info
        
        stats = {
            "edition": get_edition_info(),
            "shadow_mode": self.settings.SHADOW_MODE,
            "coalescer": self._coalescer.get_stats(),
        }
        if self._pipeline:
            stats["pipeline"] = {
                "layers_count": len(self._pipeline.layers),
                "enabled_layers": list(self._pipeline.enabled_layers),
                "shadow_mode": self._pipeline._shadow_mode,
            }
            if self._pipeline._cache_layer:
                stats["cache"] = self._pipeline._cache_layer.get_stats()
        return stats
