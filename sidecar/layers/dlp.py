"""
DLP (Data Loss Prevention) Layer for Output Scanning.

Scans LLM responses for PII/sensitive data before returning to client.
This is the OUTPUT counterpart to the INPUT PII layer.

Key difference from PIILayer:
- PIILayer: Blocks requests that CONTAIN PII (user sharing their data)
- DLPLayer: Blocks responses that LEAK PII (LLM exposing sensitive data)

Modes:
- "block":     Replace entire response with error message
- "anonymize": Replace detected PII with [REDACTED] placeholders
- "log":       Allow response but log detected PII for audit

Performance:
- Same as PIILayer (~6-8ms on CPU)
- Adds TTFT (Time To First Token) latency as response must be buffered

Note: Non-streaming only. Streaming requires fundamentally different approach.

Thread Pool Design Decision:
- Uses class-level ThreadPoolExecutor (standard pattern for CPU-bound tasks)
- max_workers capped at min(8, cpu_count+2) to prevent resource exhaustion
- ProcessPoolExecutor was considered but rejected (IPC overhead for small tasks)
- asyncio.to_thread() could be used in Python 3.9+ but executor gives more control
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional
import logging

from ..core.text import normalize_text
from ..core.pii_masking import build_entity_text_fields

# Presidio - optional dependency
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    HAS_PRESIDIO = True
except ImportError:
    HAS_PRESIDIO = False
    AnalyzerEngine = None
    RecognizerRegistry = None

# Fast PII fallback - always available
try:
    from .pii_fast import FastPIIDetector
    HAS_FAST_PII = True
except ImportError:
    HAS_FAST_PII = False
    FastPIIDetector = None

logger = logging.getLogger(__name__)


# === DLP PROMETHEUS METRICS ===
# Import telemetry helpers for metrics registration
try:
    from ..core.telemetry import (
        _get_or_create_counter,
        _get_or_create_histogram,
        _METRICS_ENABLED,
    )
    
    if _METRICS_ENABLED:
        DLP_SCANS_TOTAL = _get_or_create_counter(
            "safellm_dlp_scans_total",
            "Total number of DLP output scans",
            ["mode", "result"]  # result: "clean", "blocked", "anonymized", "logged"
        )
        
        DLP_SCAN_LATENCY = _get_or_create_histogram(
            "safellm_dlp_scan_duration_seconds",
            "Time spent scanning LLM outputs for PII",
            labels=["mode"],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]
        )
        
        DLP_PII_DETECTED = _get_or_create_counter(
            "safellm_dlp_pii_detected_total",
            "Total PII entities detected in LLM outputs",
            ["entity_type"]
        )
    else:
        DLP_SCANS_TOTAL = None
        DLP_SCAN_LATENCY = None
        DLP_PII_DETECTED = None
except ImportError:
    DLP_SCANS_TOTAL = None
    DLP_SCAN_LATENCY = None
    DLP_PII_DETECTED = None


@dataclass(slots=True)
class DLPResult:
    """Result of DLP scan on LLM output."""
    safe: bool
    pii_detected: bool
    entities: list[dict]
    modified_text: Optional[str] = None  # For anonymize mode
    blocked_reason: Optional[str] = None
    latency_ms: float = 0.0


class DLPScanner:
    """
    Data Loss Prevention scanner for LLM outputs.
    
    Usage:
        scanner = DLPScanner(mode="block")
        result = await scanner.scan_output(llm_response)
        
        if not result.safe:
            return "[BLOCKED DUE TO PII LEAK]"
        else:
            return llm_response
    
    Configuration:
        - mode: "block" | "anonymize" | "log"
        - entities: List of PII entity types to detect
        - threshold: Minimum confidence score
    """
    
    # Class-level executor for CPU-bound PII analysis
    _executor: Optional[ThreadPoolExecutor] = None
    
    # Default entities to scan in output
    DEFAULT_OUTPUT_ENTITIES = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "IBAN_CODE",
        "IP_ADDRESS",
        "US_SSN",
        "CRYPTO",
    ]
    
    # Blocked response template (message loaded from settings in __init__)
    BLOCK_REASON_TEMPLATE = "DLP: PII detected in output - {entity_types}"
    
    def __init__(
        self,
        mode: str = "block",
        entities: Optional[list[str]] = None,
        threshold: float = 0.5,
        language: str = "en",
        block_message: Optional[str] = None,
        fail_open: Optional[bool] = None,
    ):
        """
        Initialize DLP scanner.
        
        Args:
            mode: "block" | "anonymize" | "log"
            entities: PII entity types to detect
            threshold: Minimum confidence score (higher = fewer false positives)
            language: Language code for analysis
            block_message: Custom message for blocked responses (default from settings)
            fail_open: If True, allow response on scanner errors (default from settings)
        """
        self._mode = mode.lower()
        self._entities = entities if entities is not None else self.DEFAULT_OUTPUT_ENTITIES
        self._threshold = threshold
        self._language = language
        
        # Block message and fail_open from settings or default
        try:
            from ..core.settings import get_settings
            settings = get_settings()
            self._block_message = block_message or settings.DLP_BLOCK_MESSAGE
            self._fail_open = fail_open if fail_open is not None else settings.DLP_FAIL_OPEN
        except Exception:
            self._block_message = block_message or "[BLOCKED DUE TO PII LEAK]"
            self._fail_open = fail_open if fail_open is not None else False
        
        # Lazy initialization
        self._analyzer: Optional["AnalyzerEngine"] = None
        self._fast_detector: Optional[FastPIIDetector] = None
        self._initialized = False
        self._init_error: Optional[str] = None
        
        # Initialize executor if not exists
        # Design: Class-level executor with capped workers prevents resource exhaustion
        # See module docstring for detailed rationale
        if DLPScanner._executor is None:
            import os
            max_workers = min(8, (os.cpu_count() or 1) + 2)
            DLPScanner._executor = ThreadPoolExecutor(
                max_workers=max_workers,
                thread_name_prefix="dlp_scanner"
            )

    @classmethod
    def cleanup_executor(cls):
        """
        Cleanup class-level ThreadPoolExecutor.
        Should be called at application shutdown or between test sessions.
        """
        if cls._executor is not None:
            cls._executor.shutdown(wait=True)
            cls._executor = None
    
    def _lazy_init(self) -> bool:
        """
        Lazy initialization of Presidio analyzer.
        
        Returns True if successful.
        """
        if self._initialized:
            return self._init_error is None
        
        self._initialized = True
        
        if not HAS_PRESIDIO:
            # Try fast PII fallback
            if HAS_FAST_PII:
                try:
                    self._fast_detector = FastPIIDetector()
                    return True
                except Exception as e:
                    self._init_error = f"presidio-analyzer not installed, fast PII fallback failed: {e}"
                    return False
            else:
                self._init_error = "presidio-analyzer not installed and fast PII unavailable"
                return False
        
        try:
            # Create registry with regex recognizers
            registry = RecognizerRegistry()
            registry.load_predefined_recognizers()
            
            # Add custom regex recognizers for more reliable detection in output
            # Presidio's default recognizers are often too strict without context
            from presidio_analyzer import PatternRecognizer, Pattern
            
            # Enhanced Phone Number Recognizer (more robust for varied formats)
            phone_pattern = Pattern(
                name="phone_number_custom",
                regex=r"(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{3,4}",
                score=0.7
            )
            phone_recognizer = PatternRecognizer(
                supported_entity="PHONE_NUMBER",
                patterns=[phone_pattern]
            )
            registry.add_recognizer(phone_recognizer)
            
            # Enhanced SSN Recognizer (including digits-only and spaces)
            # Use higher score and context to distinguish from phone numbers
            ssn_pattern = Pattern(
                name="ssn_custom",
                regex=r"(?i)(?:ssn|social.?security)\s*:?\s*\d{3}-\d{2}-\d{4}|\b\d{3}-\d{2}-\d{4}\b(?!\s*(?:ext|extension|x)\d*)",
                score=0.8  # Higher than phone number score
            )
            ssn_recognizer = PatternRecognizer(
                supported_entity="US_SSN",
                patterns=[ssn_pattern]
            )
            registry.add_recognizer(ssn_recognizer)

            # Create analyzer without heavy NLP engine
            self._analyzer = AnalyzerEngine(
                registry=registry,
                nlp_engine=None,
                supported_languages=[self._language],
                default_score_threshold=self._threshold,
            )
            
            return True
            
        except Exception as e:
            self._init_error = f"Presidio initialization failed: {e}"
            return False
    
    def _analyze_sync(self, text: str) -> list[dict]:
        """
        Run PII analysis synchronously (called in thread pool).

        Returns list of detected entities.
        """
        if self._analyzer:
            # Use Presidio (preferred)
            results = self._analyzer.analyze(
                text=text,
                entities=self._entities,
                language=self._language,
            )

            # Convert to dict format
            from ..core.settings import get_settings
            settings = get_settings()
            include_debug_raw = settings.PII_DEBUG_INCLUDE_RAW and settings.LOG_LEVEL.upper() == "DEBUG"
            raw_entities = [
                {
                    "entity_type": r.entity_type,
                    "score": r.score,
                    "start": r.start,
                    "end": r.end,
                    **build_entity_text_fields(r.entity_type, text[r.start:r.end], include_debug_raw),
                }
                for r in results
            ]
        elif self._fast_detector:
            # Use fast PII fallback
            raw_entities = self._fast_detector.detect(text, entities=self._entities)
            # Convert confidence to score for consistency and filter by threshold
            converted_entities = []
            for entity in raw_entities:
                conf = entity.get("confidence", 0.9)
                if conf >= self._threshold:
                    converted_entities.append({**entity, "score": conf})
            raw_entities = converted_entities
        else:
            raw_entities = []

        if not raw_entities:
            return []

        # Remove overlaps: keep higher score, then longer match
        raw_entities.sort(key=lambda x: (x["start"], -x["score"], -(x["end"] - x["start"])))

        entities = []
        for entity in raw_entities:
            # Check if this entity overlaps with any already kept
            is_overlap = False
            for kept in entities:
                # Overlap check: max(start1, start2) < min(end1, end2)
                if max(entity["start"], kept["start"]) < min(entity["end"], kept["end"]):
                    is_overlap = True
                    break

            if not is_overlap:
                entities.append(entity)

        return entities
    
    def _anonymize_text(self, text: str, entities: list[dict]) -> str:
        """
        Replace detected PII with [REDACTED] placeholders.
        
        Args:
            text: Original text
            entities: List of detected entities
            
        Returns:
            Text with PII replaced by placeholders
        """
        if not entities:
            return text
        
        # Sort by position (reverse) to avoid index shifting
        sorted_entities = sorted(entities, key=lambda e: e["start"], reverse=True)
        
        result = text
        for entity in sorted_entities:
            replacement = f"[REDACTED:{entity['entity_type']}]"
            result = result[:entity["start"]] + replacement + result[entity["end"]:]
        
        return result
    
    async def scan_output(self, text: str) -> DLPResult:
        """
        Scan LLM output for PII.
        
        Args:
            text: LLM response text
            
        Returns:
            DLPResult with scan results and optional modified text
        """
        import time
        start = time.perf_counter()
        
        # Lazy initialization
        if not self._lazy_init():
            # DLP unavailable - behavior depends on fail_open setting
            logger.warning(f"DLP unavailable: {self._init_error}")
            latency_ms = (time.perf_counter() - start) * 1000
            
            if self._fail_open:
                # Fail-open: allow response (risky)
                self._record_metric("clean", time.perf_counter() - start, [])
                return DLPResult(
                    safe=True,
                    pii_detected=False,
                    entities=[],
                    latency_ms=latency_ms
                )
            else:
                # Fail-closed: block response (safe)
                self._record_metric("blocked", time.perf_counter() - start, [])
                return DLPResult(
                    safe=False,
                    pii_detected=False,
                    entities=[],
                    blocked_reason="DLP scanner unavailable (fail-closed mode)",
                    modified_text=self._block_message,
                    latency_ms=latency_ms
                )
        
        try:
            # Check if executor is shutdown and recreate if needed
            if DLPScanner._executor is None:
                import os
                max_workers = min(8, (os.cpu_count() or 1) + 2)
                DLPScanner._executor = ThreadPoolExecutor(
                    max_workers=max_workers,
                    thread_name_prefix="dlp_scanner"
                )

            # Normalize text to prevent Unicode bypass attacks
            normalized_text = normalize_text(text)

            # Run analysis in thread pool
            loop = asyncio.get_running_loop()

            entities = await loop.run_in_executor(
                DLPScanner._executor,
                self._analyze_sync,
                normalized_text
            )

            latency_sec = time.perf_counter() - start
            latency_ms = latency_sec * 1000

            if not entities:
                # No PII detected - safe to return
                self._record_metric("clean", latency_sec, [])
                return DLPResult(
                    safe=True,
                    pii_detected=False,
                    entities=[],
                    latency_ms=latency_ms
                )

            # PII detected - handle based on mode
            entity_types = list(set(e["entity_type"] for e in entities))
            reason = self.BLOCK_REASON_TEMPLATE.format(
                entity_types=", ".join(entity_types)
            )

            if self._mode == "block":
                # Block entire response
                self._record_metric("blocked", latency_sec, entities)
                return DLPResult(
                    safe=False,
                    pii_detected=True,
                    entities=entities,
                    modified_text=self._block_message,
                    blocked_reason=reason,
                    latency_ms=latency_ms
                )

            elif self._mode == "anonymize":
                # Replace PII with [REDACTED]
                anonymized = self._anonymize_text(normalized_text, entities)
                self._record_metric("anonymized", latency_sec, entities)
                return DLPResult(
                    safe=True,  # Safe after anonymization
                    pii_detected=True,
                    entities=entities,
                    modified_text=anonymized,
                    latency_ms=latency_ms
                )

            else:  # mode == "log"
                # Allow but log for audit
                logger.warning(
                    f"DLP: PII detected in output (log mode): {reason}"
                )
                self._record_metric("logged", latency_sec, entities)
                return DLPResult(
                    safe=True,
                    pii_detected=True,
                    entities=entities,
                    blocked_reason=reason,
                    latency_ms=latency_ms
                )
        except Exception as e:
            logger.error(f"DLP scan error: {e}")
            latency_ms = (time.perf_counter() - start) * 1000
            
            if self._fail_open:
                # Fail-open: allow response (risky)
                return DLPResult(
                    safe=True,
                    pii_detected=False,
                    entities=[],
                    latency_ms=latency_ms
                )
            else:
                # Fail-closed: block response (safe)
                return DLPResult(
                    safe=False,
                    pii_detected=False,
                    entities=[],
                    blocked_reason=f"DLP scan error (fail-closed mode): {str(e)[:100]}",
                    modified_text=self._block_message,
                    latency_ms=latency_ms
                )
    
    def _record_metric(self, result: str, latency_sec: float, entities: list[dict]) -> None:
        """Record Prometheus metrics for DLP scan."""
        try:
            if DLP_SCANS_TOTAL is not None:
                DLP_SCANS_TOTAL.labels(mode=self._mode, result=result).inc()

            if DLP_SCAN_LATENCY is not None:
                DLP_SCAN_LATENCY.labels(mode=self._mode).observe(latency_sec)

            if DLP_PII_DETECTED is not None and entities:
                for entity in entities:
                    DLP_PII_DETECTED.labels(entity_type=entity["entity_type"]).inc()
        except Exception as e:
            logger.debug(f"Failed to record DLP metric: {e}")
    
    async def health_check(self) -> bool:
        """Check if DLP scanner is operational."""
        if not self._initialized:
            return self._lazy_init()
        return self._init_error is None
    
    def get_status(self) -> dict:
        """Get detailed scanner status."""
        return {
            "initialized": self._initialized,
            "ready": self._init_error is None,
            "error": self._init_error,
            "mode": self._mode,
            "entities": self._entities,
            "threshold": self._threshold,
            "fail_open": self._fail_open,
        }
