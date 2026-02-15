"""
Prometheus Telemetry Module for SafeLLM Gateway.

This module is the ONLY place where Prometheus metrics are defined.
This prevents circular imports (app.py -> layers -> app.py).

Layers (layers/) can safely import:
    from .telemetry import BLOCKED_REQUESTS, SCAN_LATENCY, normalize_reason_label

⚠️ CARDINALITY EXPLOSION WARNING:
    Prometheus creates a separate time series for each label combination.
    NEVER use dynamic values (user input, prompt text) as labels.

    ✅ ALLOWED: layer="keywords", reason="jailbreak_detected"
    ❌ FORBIDDEN: reason=user_prompt[:50], user_id=request.user_id

    Allowed values for `reason` (ENUM - finite set):
    - "keyword_match" - L1 keyword blocking
    - "pii_detected" - L1.5 PII blocking  
    - "jailbreak_detected" - L2 AI jailbreak detection
    - "injection_detected" - L2 AI injection detection
    - "cache_hit_blocked" - L0 cache returned blocked result
    - "layer_error" - Layer failed during scan
    - "other" - Fallback for unknown reasons
"""
import os
from prometheus_client import Counter, Histogram, Gauge
from typing import Literal


# === REASON LABEL NORMALIZATION ===
# Map dynamic reason strings to fixed enum values
# This prevents Prometheus cardinality explosion.
#
# Usage:
#     from .telemetry import normalize_reason_label
#     label = normalize_reason_label(result.reason)
#     BLOCKED_REQUESTS.labels(layer=layer.name, reason=label).inc()
#
ReasonLabel = Literal[
    "keyword_match",
    "pii_detected", 
    "jailbreak_detected",
    "injection_detected",
    "cache_hit_blocked",
    "layer_error",
    "other"
]


def normalize_reason_label(reason: str) -> ReasonLabel:
    """
    Normalizes a dynamic reason string to a fixed Prometheus label.

    CRITICAL: This function MUST return a value from a limited set.
    Dynamic values (user text, score, etc.) = cardinality explosion.

    Args:
        reason: Raw reason string from the security layer (may contain user input)
        
    Returns:
        Normalized label from ReasonLabel enum
        
    Examples:
        >>> normalize_reason_label("blocked: DROP TABLE users")
        "keyword_match"
        >>> normalize_reason_label("jailbreak_detected (score: 0.95)")
        "jailbreak_detected"
        >>> normalize_reason_label("Detected PII: EMAIL_ADDRESS, PHONE")
        "pii_detected"
    """
    reason_lower = reason.lower()
    
    # L1 Keywords: "blocked: {keyword}"
    if reason_lower.startswith("blocked:"):
        return "keyword_match"
    
    # L2 AI Guard: jailbreak
    if "jailbreak" in reason_lower:
        return "jailbreak_detected"
    
    # L2 AI Guard: injection
    if "injection" in reason_lower:
        return "injection_detected"
    
    # L1.5 PII: "Detected PII: {types}"
    if "pii" in reason_lower or "detected pii" in reason_lower:
        return "pii_detected"
    
    # L0 Cache hit (blocked)
    if "cache" in reason_lower:
        return "cache_hit_blocked"
    
    # Layer errors: "layer_error: {name}", "ai_guard_unavailable: {msg}"
    if "error" in reason_lower or "unavailable" in reason_lower:
        return "layer_error"
    
    # Fallback - unknown reason type
    return "other"

# Check if metrics are enabled (avoid registering metrics in tests)
_METRICS_ENABLED = os.getenv('ENABLE_METRICS', 'true').lower() == 'true'


def _get_or_create_counter(name: str, description: str, labels: list[str]) -> Counter | None:
    """
    Get existing counter or create new one.
    
    Handles the case where metrics are already registered (e.g., in tests).
    Returns None if metrics are disabled.
    """
    if not _METRICS_ENABLED:
        return None
    
    from prometheus_client import REGISTRY
    
    # Check if metric already exists
    try:
        # Try to get existing metric from registry
        for collector in REGISTRY._names_to_collectors.values():
            if hasattr(collector, '_name') and collector._name == name:
                return collector
    except Exception:
        pass
    
    # Create new metric
    try:
        return Counter(name, description, labels)
    except ValueError:
        # Already registered - find and return it
        for collector in REGISTRY._names_to_collectors.values():
            if hasattr(collector, '_name') and collector._name == name:
                return collector
        return None


def _get_or_create_histogram(name: str, description: str, labels: list[str] | None = None, 
                              buckets: list[float] | None = None) -> Histogram | None:
    """
    Get existing histogram or create new one.
    
    Handles the case where metrics are already registered (e.g., in tests).
    Returns None if metrics are disabled.
    """
    if not _METRICS_ENABLED:
        return None
    
    from prometheus_client import REGISTRY
    
    # Check if metric already exists
    try:
        for collector in REGISTRY._names_to_collectors.values():
            if hasattr(collector, '_name') and collector._name == name:
                return collector
    except Exception:
        pass
    
    # Create new metric
    try:
        kwargs = {"documentation": description}
        if labels:
            kwargs["labelnames"] = labels
        if buckets:
            kwargs["buckets"] = buckets
        return Histogram(name, **kwargs)
    except ValueError:
        # Already registered - find and return it
        for collector in REGISTRY._names_to_collectors.values():
            if hasattr(collector, '_name') and collector._name == name:
                return collector
        return None


def _get_or_create_gauge(name: str, description: str) -> Gauge | None:
    """Get existing gauge or create new one."""
    if not _METRICS_ENABLED:
        return None
    
    from prometheus_client import REGISTRY
    
    try:
        for collector in REGISTRY._names_to_collectors.values():
            if hasattr(collector, '_name') and collector._name == name:
                return collector
    except Exception:
        pass
    
    try:
        return Gauge(name, description)
    except ValueError:
        for collector in REGISTRY._names_to_collectors.values():
            if hasattr(collector, '_name') and collector._name == name:
                return collector
        return None


# === BLOCKED REQUESTS COUNTER ===
# Counts how many requests were blocked by each layer
#
# Example usage in layers/keywords.py:
#     BLOCKED_REQUESTS.labels(layer="keywords", reason="keyword_match").inc()
#
BLOCKED_REQUESTS = _get_or_create_counter(
    "safellm_blocked_requests_total",
    "Total number of requests blocked by security layers",
    ["layer", "reason"]
)

# === SCAN LATENCY HISTOGRAM ===
# Measures execution time of each security layer
#
# Buckety dostosowane do SafeLLM:
#   - L0 Cache: 0.0001s (0.1ms)
#   - L1 Keywords: 0.0005s (0.5ms)
#   - L1.5 PII: 0.005-0.01s (5-10ms)
#   - L2 AI: 0.05-0.1s (50-100ms)
#
# Example usage:
#     with SCAN_LATENCY.labels(layer="ai_guard").time():
#         result = model.predict(prompt)
#
SCAN_LATENCY = _get_or_create_histogram(
    "safellm_scan_duration_seconds",
    "Time spent scanning prompts in each layer",
    labels=["layer"],
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
)

# === PROMPT LENGTH HISTOGRAM ===
# Monitors length of incoming prompts
#
PROMPT_LENGTH = _get_or_create_histogram(
    "safellm_prompt_length_chars",
    "Length of incoming prompts in characters",
    buckets=[50, 100, 250, 500, 1000, 2000, 5000, 10000]
)

# === ACTIVE REQUESTS GAUGE ===
# Number of requests currently in progress (useful for load balancing)
#
ACTIVE_REQUESTS = _get_or_create_gauge(
    "safellm_active_requests",
    "Number of requests currently being processed"
)

# === CACHE STATS ===
CACHE_HITS = _get_or_create_counter(
    "safellm_cache_hits_total",
    "Number of cache hits",
    ["result"]  # result="allowed" or result="blocked"
)

CACHE_MISSES = _get_or_create_counter(
    "safellm_cache_misses_total",
    "Number of cache misses",
    []
)

# === DLP AUDIT TRUNCATIONS ===
# Counts how many audit-mode response bodies were truncated for scanning
DLP_AUDIT_TRUNCATIONS = _get_or_create_counter(
    "safellm_dlp_audit_truncated_total",
    "Number of audit response bodies truncated before scanning",
    []
)
