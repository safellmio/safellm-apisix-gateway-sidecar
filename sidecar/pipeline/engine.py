"""Security Pipeline - Waterfall execution of security layers."""
import time
from dataclasses import dataclass
from typing import Optional

from ..layers.base import SecurityLayer, ScanContext, ScanResult
from ..core.settings import get_settings
from ..layers.cache import CacheLayer
from ..models import Decision

# Use structured logging if available
try:
    from ..core.logger import get_logger, PipelineLogger
    logger = get_logger(__name__)
    pipeline_logger = PipelineLogger(logger)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)
    pipeline_logger = None

# Audit logging (OSS no-op)
from ..core.providers import log_audit_event
HAS_AUDIT = True


@dataclass(slots=True)
class PipelineResult:
    """Extended result with pipeline metadata."""
    decision: Decision
    total_latency_ms: float
    layers_executed: int
    stopping_layer: str | None = None


class SecurityPipeline:
    """
    Executes security layers in waterfall order.
    
    Short-circuit behavior:
    - If any layer returns unsafe, pipeline stops immediately
    - Remaining layers are not executed (saves latency)
    
    Cache integration:
    - If CacheLayer is first, cache hits skip all other layers
    - After pipeline completion, results are cached for future requests
    
    Example:
        pipeline = SecurityPipeline([
            CacheLayer(redis_host="localhost"),
            KeywordLayer(blocked_phrases),
            PIILayer(entities)
        ])
        result = await pipeline.execute("user prompt", request_id="abc123")
    """
    
    def __init__(
        self,
        layers: list[SecurityLayer],
        enabled_layers: set[str] | None = None,
        cache_results: bool = True,
        shadow_mode: bool = False,
        fail_open: bool | None = None,
    ):
        self.layers = layers
        self.enabled_layers = enabled_layers or {layer.name for layer in layers}
        self._cache_results = cache_results
        self._shadow_mode = shadow_mode
        if fail_open is None:
            try:
                fail_open = get_settings().FAIL_OPEN
            except Exception:
                fail_open = False
        self._fail_open = bool(fail_open)
        
        # Find cache layer for result caching
        self._cache_layer: Optional[CacheLayer] = None
        for layer in layers:
            if isinstance(layer, CacheLayer):
                self._cache_layer = layer
                break
    
    def _is_enabled(self, layer: SecurityLayer) -> bool:
        """Check if layer is enabled in configuration."""
        return layer.name in self.enabled_layers
    
    async def execute(
        self,
        text: str,
        request_id: str = ""
    ) -> PipelineResult:
        """
        Execute the security pipeline on input text.
        
        Args:
            text: Input text to scan
            request_id: Correlation ID for logging
            
        Returns:
            PipelineResult with decision and metadata
        """
        ctx = ScanContext(text=text, request_id=request_id)
        start_total = time.perf_counter()
        layers_executed = 0
        last_result: Optional[ScanResult] = None
        cache_hit = False
        shadow_had_detections = False  # Track if shadow mode had any detections
        
        # Log pipeline start
        if pipeline_logger:
            pipeline_logger.start(
                request_id=request_id,
                text_length=len(text),
                enabled_layers=list(self.enabled_layers)
            )
        
        for layer in self.layers:
            if not self._is_enabled(layer):
                continue
            
            layers_executed += 1
            start_layer = time.perf_counter()
            
            try:
                result = await layer.scan(ctx)
            except Exception as e:
                # Fail-safe: log error but don't crash
                logger.error(
                    "layer_error",
                    layer=layer.name,
                    error=str(e),
                    request_id=request_id,
                )
                if self._fail_open:
                    result = ScanResult.ok(layer=f"{layer.name}_ERROR")
                else:
                    result = ScanResult.blocked(
                        reason=f"layer_error: {layer.name}",
                        layer=layer.name
                    )
            
            result.latency_ms = (time.perf_counter() - start_layer) * 1000
            last_result = result

            # Record scan latency in telemetry
            from ..core.telemetry import SCAN_LATENCY
            if SCAN_LATENCY is not None:  # Only if metrics are enabled
                SCAN_LATENCY.labels(layer=layer.name).observe(result.latency_ms / 1000)  # Convert to seconds
            
            # Structured logging for layer completion
            logger.info(
                "layer_complete",
                layer=layer.name,
                safe=result.safe,
                latency_ms=round(result.latency_ms, 2),
                request_id=request_id,
            )
            
            # Check for cache hit (result.layer contains ":HIT" suffix, not layer.name)
            if result.layer and result.layer.endswith(":HIT"):
                cache_hit = True
                if pipeline_logger:
                    pipeline_logger.cache_hit(request_id, "safe" if result.safe else "unsafe")
                # Early exit on cache hit - no need to run other layers
                if result.safe:
                    total_latency = (time.perf_counter() - start_total) * 1000
                    return PipelineResult(
                        decision=Decision(allowed=True, reason="cache_hit"),
                        total_latency_ms=total_latency,
                        layers_executed=layers_executed,
                        stopping_layer=result.layer
                    )
            
            if not result.safe:
                # Record blocked request in telemetry
                # CRITICAL: Use normalize_reason_label to prevent cardinality explosion!
                from ..core.telemetry import BLOCKED_REQUESTS, normalize_reason_label
                if BLOCKED_REQUESTS is not None:  # Only if metrics are enabled
                    reason_label = normalize_reason_label(result.reason)
                    # In shadow mode, use different label to distinguish
                    metric_layer = f"shadow:{layer.name}" if self._shadow_mode else layer.name
                    BLOCKED_REQUESTS.labels(layer=metric_layer, reason=reason_label).inc()

                # SHADOW MODE: Log "would_block" but continue pipeline
                if self._shadow_mode:
                    shadow_had_detections = True  # Mark that we had detections
                    logger.warning(
                        "shadow_would_block",
                        layer=layer.name,
                        reason=result.reason,
                        score=result.score,
                        latency_ms=round(result.latency_ms, 2),
                        request_id=request_id,
                        shadow_mode=True,
                    )
                    # Audit log shadow block (non-blocking)
                    if HAS_AUDIT and log_audit_event:
                        await log_audit_event(
                            request_id=request_id,
                            prompt=text,
                            allowed=True,  # Shadow = allowed
                            layer=f"shadow:{layer.name}",
                            reason=f"shadow_would_block:{normalize_reason_label(result.reason)}",
                            latency_ms=result.latency_ms,
                        )
                    # Continue to next layer instead of short-circuit
                    continue

                # NORMAL MODE: Short-circuit on first unsafe result
                total_latency = (time.perf_counter() - start_total) * 1000
                
                # Cache the result if caching enabled and not a cache hit
                if self._cache_results and self._cache_layer and not cache_hit:
                    await self._cache_layer.cache_result(text, result)
                
                # Log pipeline completion
                if pipeline_logger:
                    pipeline_logger.complete(
                        request_id=request_id,
                        allowed=False,
                        layers_executed=layers_executed,
                        total_latency_ms=total_latency,
                        stopping_layer=layer.name,
                        reason=result.reason,
                    )
                
                # Audit log (async, non-blocking)
                if HAS_AUDIT and log_audit_event:
                    await log_audit_event(
                        request_id=request_id,
                        prompt=text,
                        allowed=False,
                        layer=layer.name,
                        reason=normalize_reason_label(result.reason),
                        latency_ms=total_latency,
                    )
                
                return PipelineResult(
                    decision=Decision(
                        allowed=False,
                        reason=result.reason
                    ),
                    total_latency_ms=total_latency,
                    layers_executed=layers_executed,
                    stopping_layer=layer.name
                )
        
        # All layers passed
        total_latency = (time.perf_counter() - start_total) * 1000
        
        # Create final safe result
        final_result = ScanResult.ok(layer="PASSED_ALL")
        
        # Cache the result if caching enabled and not a cache hit
        # IMPORTANT: Do NOT cache if shadow mode had detections (prevents cache pollution)
        if self._cache_results and self._cache_layer and not cache_hit and not shadow_had_detections:
            await self._cache_layer.cache_result(text, final_result)
        
        # Log pipeline completion
        if pipeline_logger:
            pipeline_logger.complete(
                request_id=request_id,
                allowed=True,
                layers_executed=layers_executed,
                total_latency_ms=total_latency,
            )
        
        # Audit log (async, non-blocking)
        if HAS_AUDIT and log_audit_event:
            await log_audit_event(
                request_id=request_id,
                prompt=text,
                allowed=True,
                layer="PASSED_ALL",
                reason=None,
                latency_ms=total_latency,
            )
        
        return PipelineResult(
            decision=Decision(allowed=True, reason="clean"),
            total_latency_ms=total_latency,
            layers_executed=layers_executed,
            stopping_layer=None
        )
    
    async def health_check(self) -> dict[str, bool]:
        """Check health of all layers."""
        results = {}
        for layer in self.layers:
            try:
                results[layer.name] = await layer.health_check()
            except Exception:
                results[layer.name] = False
        return results
