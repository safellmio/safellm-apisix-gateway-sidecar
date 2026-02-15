"""Security layers for the SafeLLM pipeline."""
from .base import SecurityLayer, ScanContext, ScanResult
from .keywords import KeywordLayer
from .pii_fast import PIILayer  # OSS: lightweight regex-only
from .cache import CacheLayer
from .dlp import DLPScanner, DLPResult

__all__ = [
    # Base classes
    "SecurityLayer",
    "ScanContext",
    "ScanResult",
    # Layers
    "KeywordLayer",      # L1: Fast keyword detection
    "PIILayer",          # L3: PII detection (lightweight, regex-only)
    "CacheLayer",        # L0: Redis cache
    # DLP (Output scanning)
    "DLPScanner",        # DLP: Output PII detection
    "DLPResult",         # DLP scan result
]
