"""
Structured JSON Logging using structlog.

Provides consistent, queryable JSON logs with:
- Automatic request ID (correlation ID) tracking
- Per-layer latency metrics
- Structured event data

Configuration:
- LOG_LEVEL: DEBUG, INFO, WARNING, ERROR
- LOG_FORMAT: "json" (production) or "text" (development)

Usage:
    from .logger import get_logger, configure_logging
    
    # Configure at app startup
    configure_logging(level="INFO", format="json")
    
    # Get logger and use
    logger = get_logger()
    logger.info("request_started", request_id="abc123", method="POST")
    logger.info("layer_complete", layer="L1_KEYWORDS", latency_ms=0.5)
"""
import logging
import sys
from functools import lru_cache
from typing import Any, Optional, TextIO

# structlog - optional but recommended
try:
    import structlog
    from structlog.types import Processor
    HAS_STRUCTLOG = True
except ImportError:
    HAS_STRUCTLOG = False
    structlog = None


# === Processors for structlog ===

def add_layer_context(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Add security layer context to log events."""
    # Auto-categorize events
    event = event_dict.get("event", "")
    
    if "layer" in event_dict:
        event_dict["component"] = "security_pipeline"
    elif "request_id" in event_dict:
        event_dict["component"] = "http"
    else:
        event_dict["component"] = "app"
    
    return event_dict


def format_latency(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Format latency values to 2 decimal places."""
    if "latency_ms" in event_dict:
        event_dict["latency_ms"] = round(event_dict["latency_ms"], 2)
    if "total_latency_ms" in event_dict:
        event_dict["total_latency_ms"] = round(event_dict["total_latency_ms"], 2)
    return event_dict


# === Configuration ===

def configure_logging(
    level: str = "INFO",
    format: str = "json",
    service_name: str = "safellm-sidecar",
    stream: TextIO | None = None,
) -> None:
    """
    Configure structured logging for the application.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        format: Output format ("json" for production, "text" for dev)
        service_name: Service identifier for logs
    
    Call this ONCE at application startup, before any logging.
    """
    log_stream = stream or sys.stdout

    if not HAS_STRUCTLOG:
        # Fallback to basic logging if structlog not installed
        logging.basicConfig(
            level=getattr(logging, level.upper(), logging.INFO),
            format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            stream=log_stream,
            force=True,
        )
        return
    
    # Common processors for all formats
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,  # Merge context vars
        structlog.stdlib.add_log_level,            # Add level
        structlog.stdlib.add_logger_name,          # Add logger name
        structlog.processors.TimeStamper(fmt="iso"), # ISO timestamp
        structlog.processors.StackInfoRenderer(),  # Stack info
        add_layer_context,                         # Custom: layer context
        format_latency,                            # Custom: format latency
    ]
    
    if format.lower() == "json":
        # Production: JSON output
        processors = shared_processors + [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Development: Colored console output
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True),
        ]
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Also configure stdlib logging for libraries
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        handlers=[logging.StreamHandler(log_stream)],
        force=True,
    )


@lru_cache
def get_logger(name: Optional[str] = None) -> Any:
    """
    Get a structured logger instance.
    
    Args:
        name: Logger name (optional, for stdlib compatibility)
        
    Returns:
        structlog logger (or stdlib logger if structlog unavailable)
    """
    if HAS_STRUCTLOG:
        return structlog.get_logger(name or "safellm")
    else:
        return logging.getLogger(name or "safellm")


# === Context Management ===

def bind_request_context(
    request_id: str,
    **extra: Any
) -> None:
    """
    Bind request context to all subsequent log calls in this async context.
    
    Uses contextvars for async-safe context propagation.
    
    Args:
        request_id: Unique request identifier
        **extra: Additional context to bind
    
    Usage:
        bind_request_context(request_id="abc123", user_id="user456")
        logger.info("processing")  # Automatically includes request_id, user_id
    """
    if HAS_STRUCTLOG:
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            **extra
        )


def unbind_request_context() -> None:
    """Clear request context after request completion."""
    if HAS_STRUCTLOG:
        structlog.contextvars.clear_contextvars()


# === Specialized Loggers ===

class LayerLogger:
    """
    Specialized logger for security layer events.
    
    Provides consistent logging interface for layer scan results.
    
    Usage:
        layer_log = LayerLogger(get_logger())
        layer_log.scan_start("L1_KEYWORDS", request_id="abc")
        layer_log.scan_complete("L1_KEYWORDS", safe=True, latency_ms=0.5)
    """
    
    def __init__(self, logger: Any):
        self._logger = logger
    
    def scan_start(
        self,
        layer: str,
        request_id: str = "",
        text_length: int = 0
    ) -> None:
        """Log layer scan start."""
        self._logger.debug(
            "layer_scan_start",
            layer=layer,
            request_id=request_id,
            text_length=text_length,
        )
    
    def scan_complete(
        self,
        layer: str,
        safe: bool,
        latency_ms: float,
        reason: str = "",
        score: float = 0.0,
        request_id: str = "",
    ) -> None:
        """Log layer scan completion."""
        log_method = self._logger.info if safe else self._logger.warning
        log_method(
            "layer_scan_complete",
            layer=layer,
            safe=safe,
            latency_ms=latency_ms,
            reason=reason if not safe else None,
            score=score if not safe else None,
            request_id=request_id,
        )
    
    def scan_error(
        self,
        layer: str,
        error: str,
        request_id: str = "",
    ) -> None:
        """Log layer scan error."""
        self._logger.error(
            "layer_scan_error",
            layer=layer,
            error=error,
            request_id=request_id,
        )


class PipelineLogger:
    """
    Specialized logger for pipeline execution events.
    
    Usage:
        pipe_log = PipelineLogger(get_logger())
        pipe_log.start(request_id="abc", text_length=100)
        pipe_log.complete(allowed=True, layers_executed=2, total_latency_ms=5.0)
    """
    
    def __init__(self, logger: Any):
        self._logger = logger
    
    def start(
        self,
        request_id: str,
        text_length: int,
        enabled_layers: list[str] | None = None,
    ) -> None:
        """Log pipeline execution start."""
        self._logger.info(
            "pipeline_start",
            request_id=request_id,
            text_length=text_length,
            enabled_layers=enabled_layers,
        )
    
    def complete(
        self,
        request_id: str,
        allowed: bool,
        layers_executed: int,
        total_latency_ms: float,
        stopping_layer: str | None = None,
        reason: str = "",
    ) -> None:
        """Log pipeline execution completion."""
        log_method = self._logger.info if allowed else self._logger.warning
        log_method(
            "pipeline_complete",
            request_id=request_id,
            allowed=allowed,
            layers_executed=layers_executed,
            total_latency_ms=total_latency_ms,
            stopping_layer=stopping_layer,
            reason=reason if not allowed else None,
        )
    
    def cache_hit(
        self,
        request_id: str,
        cached_result: str,
    ) -> None:
        """Log cache hit."""
        self._logger.info(
            "pipeline_cache_hit",
            request_id=request_id,
            cached_result=cached_result,
        )


# === Request ID Generation ===

def generate_request_id() -> str:
    """
    Generate a unique request ID.
    
    Uses UUID4 for uniqueness. Call this if X-Request-Id header not present.
    """
    import uuid
    return uuid.uuid4().hex[:16]


# === Middleware Helper ===

class RequestLoggingContext:
    """
    Context manager for request-scoped logging.
    
    Usage:
        async with RequestLoggingContext(request_id="abc") as ctx:
            logger.info("handling request")  # Includes request_id
    """
    
    def __init__(self, request_id: str, **extra: Any):
        self.request_id = request_id
        self.extra = extra
    
    async def __aenter__(self):
        bind_request_context(self.request_id, **self.extra)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        unbind_request_context()
        return False
