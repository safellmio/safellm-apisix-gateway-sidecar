"""
Edition management for SafeLLM - OSS vs Enterprise feature gating.

Usage:
    from sidecar.edition import is_feature_available, get_edition, EDITION
    
    if is_feature_available("ai_guard"):
        # Load expensive ONNX model
        ...

Environment:
    SAFELLM_EDITION=oss        # Only supported in OSS build
"""
import logging
import os

_requested_edition = os.getenv("SAFELLM_EDITION", "oss").lower()
if _requested_edition != "oss":
    logging.getLogger(__name__).warning(
        "Enterprise edition is not available in OSS build. Forcing SAFELLM_EDITION=oss."
    )
EDITION = "oss"

# Feature availability matrix per edition
# OSS: Free, open-source features
FEATURES = {
    "oss": {
        # PII Detection
        "pii_gliner": False,          # GLiNER PII detector (25+ types, ~20ms)
        "pii_fast_regex": True,       # Fast regex PII (basic types, ~1ms)
        
        # AI Models
        "ai_guard": False,            # ONNX prompt injection model
        
        # Infrastructure
        "redis_sentinel": False,      # Redis HA with Sentinel
        "distributed_coalescer": False,  # Cross-pod request dedup
        
        # DLP
        "dlp_block_mode": False,      # DLP blocking (audit only in OSS)
        "dlp_audit_mode": True,       # DLP audit/logging
        
        # Compliance
        "audit_logs": False,          # Compliance audit logging
        
        # Monitoring
        "prometheus_metrics": True,   # Basic Prometheus metrics
    }
}


def is_feature_available(feature: str) -> bool:
    """
    Check if feature is available in current OSS build.
    
    Args:
        feature: Feature name from FEATURES matrix
        
    Returns:
        True if feature is available, False otherwise
        
    Example:
        if is_feature_available("pii_fast_regex"):
            ...
    """
    # First check edition features matrix
    edition_features = FEATURES.get(EDITION, FEATURES["oss"])
    if not edition_features.get(feature, False):
        return False
    
    return True


def get_edition() -> str:
    """Get current edition (oss only in OSS build)."""
    return EDITION


def get_available_features() -> list[str]:
    """Get list of features available in current edition and license."""
    edition_features = FEATURES.get(EDITION, FEATURES["oss"])
    # Use is_feature_available to respect both edition AND license
    return [f for f in edition_features.keys() if is_feature_available(f)]


def get_edition_info() -> dict:
    """
    Get edition info for health/status endpoints.
    
    Returns dict with:
        - edition: "oss"
        - features: list of available feature names
        - all_features: dict of all features with availability
    """
    result = {
        "edition": EDITION,
        "features": get_available_features(),
        "all_features": FEATURES.get(EDITION, FEATURES["oss"]),
    }
    return result
