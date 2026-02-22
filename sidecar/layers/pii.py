"""
L3 Security Layer: PII (Personally Identifiable Information) Detection.

Uses Microsoft Presidio Analyzer with regex-only recognizers (no spaCy)
for fast PII detection.

Detected entities:
- EMAIL_ADDRESS
- PHONE_NUMBER  
- CREDIT_CARD
- IBAN_CODE
- IP_ADDRESS
- CRYPTO (wallet addresses)

Performance: ~6-8ms on CPU
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from .base import SecurityLayer, ScanContext, ScanResult
from ..core.pii_masking import build_entity_text_fields
from ..core.settings import get_settings

# Presidio - optional dependency
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    HAS_PRESIDIO = True
except ImportError:
    HAS_PRESIDIO = False
    AnalyzerEngine = None
    RecognizerRegistry = None


class PIILayer(SecurityLayer):
    """
    L3 Security: PII detection using Presidio Analyzer.
    
    Uses regex-only recognizers (no NLP models) for speed.
    Configurable entity types and detection threshold.
    
    Configuration:
        - entities: List of entity types to detect
        - threshold: Minimum confidence score (0.0-1.0)
        - language: Language code for detection
    
    Performance:
        - ~6-8ms per request
        - Regex-based (no NLP model overhead)
    
    Detected PII types (configurable):
        - EMAIL_ADDRESS: user@example.com
        - PHONE_NUMBER: +48 500 600 700
        - CREDIT_CARD: 4111 1111 1111 1111
        - IBAN_CODE: PL61109010140000071219812874
        - IP_ADDRESS: 192.168.1.1
        - CRYPTO: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
    """
    
    # Class-level executor for CPU-bound PII analysis
    _executor: Optional[ThreadPoolExecutor] = None
    
    # Default entities to detect
    DEFAULT_ENTITIES = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "IBAN_CODE",
        "IP_ADDRESS",
        "CRYPTO",
    ]
    
    def __init__(
        self,
        entities: Optional[list[str]] = None,
        threshold: float = 0.4,
        language: str = "en",
    ):
        """
        Initialize PII detection layer.
        
        Args:
            entities: List of PII entity types to detect (None = defaults)
            threshold: Minimum confidence score for detection
            language: Language code for analysis
        """
        self._entities = entities if entities is not None else self.DEFAULT_ENTITIES
        self._threshold = threshold
        self._language = language
        
        # Lazy initialization
        self._analyzer: Optional["AnalyzerEngine"] = None
        self._initialized = False
        self._init_error: Optional[str] = None
        
        # Initialize executor if not exists
        if PIILayer._executor is None:
            # Dynamic worker count for CPU-bound regex operations
            import os
            max_workers = min(16, (os.cpu_count() or 1) + 2)
            PIILayer._executor = ThreadPoolExecutor(
                max_workers=max_workers,
                thread_name_prefix="pii_analyzer"
            )
    
    @classmethod
    def cleanup_executor(cls):
        """Cleanup class-level ThreadPoolExecutor."""
        if cls._executor is not None:
            cls._executor.shutdown(wait=True)
            cls._executor = None

    @property
    def name(self) -> str:
        return "L3_PII"
    
    def _lazy_init(self) -> bool:
        """
        Lazy initialization of Presidio analyzer.
        
        Uses regex-only recognizers for speed (no spaCy).
        Returns True if successful.
        """
        if self._initialized:
            return self._init_error is None
        
        self._initialized = True
        
        if not HAS_PRESIDIO:
            self._init_error = "presidio-analyzer not installed"
            return False
        
        try:
            # Create registry with only regex recognizers (no NLP)
            registry = RecognizerRegistry()
            registry.load_predefined_recognizers()
            
            # Create a "dummy" NLP engine to prevent Presidio from loading spaCy/transformers
            # This saves ~1-1.5GB of RAM per worker
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            nop_config = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": self._language, "model_name": "en_core_web_sm"}] 
            }
            # Note: We use sm (small) instead of large if available, or ideally a stub.
            # Best way to skip NLP is to provide a provider that returns None for NLP results.
            
            self._analyzer = AnalyzerEngine(
                registry=registry,
                nlp_engine=None, # Explicitly none to avoid heavy model loading
                supported_languages=[self._language],
                default_score_threshold=self._threshold,
            )
            
            return True
            
        except Exception as e:
            self._init_error = f"Presidio initialization failed: {e}"
            return False
    
    def _analyze_sync(self, text: str) -> tuple[bool, list[dict]]:
        """
        Run PII analysis synchronously (called in thread pool).
        
        Returns:
            Tuple of (has_pii, detected_entities)
        """
        results = self._analyzer.analyze(
            text=text,
            entities=self._entities,
            language=self._language,
        )
        
        # Filter by threshold (already applied by analyzer, but double-check)
        settings = get_settings()
        include_debug_raw = settings.PII_DEBUG_INCLUDE_RAW and settings.LOG_LEVEL.upper() == "DEBUG"
        filtered = [
            {
                "entity_type": r.entity_type,
                "score": r.score,
                "start": r.start,
                "end": r.end,
                **build_entity_text_fields(r.entity_type, text[r.start:r.end], include_debug_raw),
            }
            for r in results
            if r.score >= self._threshold
        ]
        
        has_pii = len(filtered) > 0
        return has_pii, filtered
    
    async def scan(self, ctx: ScanContext) -> ScanResult:
        """
        Scan text for PII.
        
        Uses ThreadPoolExecutor to avoid blocking the event loop.
        """
        # Lazy initialization
        if not self._lazy_init():
            return ScanResult.blocked(
                reason=f"pii_unavailable: {self._init_error}",
                layer=self.name,
                score=0.0
            )
        
        try:
            # Run analysis in thread pool
            loop = asyncio.get_running_loop()
            has_pii, entities = await loop.run_in_executor(
                PIILayer._executor,
                self._analyze_sync,
                ctx.text
            )
            
            if not has_pii:
                return ScanResult.ok(layer=self.name)
            
            # Build reason with detected entity types
            entity_types = list(set(e["entity_type"] for e in entities))
            entity_count = len(entities)
            max_score = max(e["score"] for e in entities)
            
            reason = f"PII_detected: {', '.join(entity_types)} ({entity_count} entities)"
            
            # Store entities in context metadata for downstream processing
            ctx.metadata["pii_entities"] = entities
            
            return ScanResult.blocked(
                reason=reason,
                layer=self.name,
                score=max_score
            )
            
        except Exception as e:
            return ScanResult.blocked(
                reason=f"pii_error: {str(e)}",
                layer=self.name,
                score=0.0
            )
    
    async def health_check(self) -> bool:
        """Check if PII analyzer is operational."""
        if not self._initialized:
            return self._lazy_init()
        return self._init_error is None
    
    def get_status(self) -> dict:
        """Get detailed layer status for debugging."""
        return {
            "name": self.name,
            "initialized": self._initialized,
            "ready": self._init_error is None,
            "error": self._init_error,
            "entities": self._entities,
            "threshold": self._threshold,
            "language": self._language,
        }


class PIIAnonymizer:
    """
    Optional helper class for anonymizing detected PII.
    
    Usage:
        anonymizer = PIIAnonymizer()
        safe_text = anonymizer.anonymize(text, entities)
        # "Contact: [EMAIL] at [PHONE]"
    """
    
    def __init__(self, replacement_pattern: str = "[{entity_type}]"):
        """
        Args:
            replacement_pattern: Pattern for replacing PII
                                 {entity_type} is replaced with type name
        """
        self._pattern = replacement_pattern
    
    def anonymize(self, text: str, entities: list[dict]) -> str:
        """
        Replace detected PII with placeholders.
        
        Args:
            text: Original text
            entities: List of detected entities from PIILayer
            
        Returns:
            Text with PII replaced by placeholders
        """
        if not entities:
            return text
        
        # Sort by position (reverse) to avoid index shifting
        sorted_entities = sorted(entities, key=lambda e: e["start"], reverse=True)
        
        result = text
        for entity in sorted_entities:
            replacement = self._pattern.format(entity_type=entity["entity_type"])
            result = result[:entity["start"]] + replacement + result[entity["end"]:]
        
        return result
