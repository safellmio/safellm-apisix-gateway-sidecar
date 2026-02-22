"""
PII Detection Layer - fast regex-only detection for OSS.

Aggressive detection mode with:
- Flexible separators (spaces, dashes, dots between digits)
- Text normalization before matching
- Luhn checksum validation for credit cards
"""

import logging
import re
from typing import List, Dict, Optional

from .base import SecurityLayer, ScanContext, ScanResult
from ..core.text import normalize_text
from ..core.settings import get_settings
from ..core.pii_masking import build_entity_text_fields


def _luhn_checksum(card_number: str) -> bool:
    """
    Validate credit card number using Luhn algorithm.

    Returns True if the number passes Luhn validation.
    This significantly reduces false positives.
    """
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    # Luhn algorithm
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(divmod(d * 2, 10))
    return checksum % 10 == 0


class FastPIIDetector:
    """
    Ultra-fast PII detector using regex patterns.

    Focuses on common PII types with low latency.
    Uses aggressive detection with flexible separators.
    """

    # Separator pattern: optional spaces, dashes, dots between digit groups
    _SEP = r'[\s\-\.]*'

    PATTERNS = {
        "EMAIL_ADDRESS": re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            re.IGNORECASE
        ),
        "PHONE_NUMBER": re.compile(
            # Standard phone pattern with negative lookahead to exclude PESEL (11 continuous digits)
            r'\b(?!\d{11}\b)(?:\+?[1-9]\d{0,2}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b'
        ),
        # Credit card: flexible separators, validates with Luhn
        "CREDIT_CARD": re.compile(
            # Visa, MasterCard, Amex, Discover with flexible separators
            r'\b(?:'
            r'4[\d\s\-\.]{12,18}|'  # Visa: starts with 4
            r'5[1-5][\d\s\-\.]{13,17}|'  # MasterCard: 51-55
            r'3[47][\d\s\-\.]{12,16}|'  # Amex: 34 or 37
            r'6(?:011|5[\d\s\-\.]{2})[\d\s\-\.]{11,15}'  # Discover
            r')\b'
        ),
        "IP_ADDRESS": re.compile(
            r'(?<![\d.])\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b(?![\d.])'
        ),
        # IBAN: country code (known codes) + check digits + BBAN
        # Restricted to real IBAN country prefixes to reduce false positives
        "IBAN_CODE": re.compile(
            r'\b(?:AL|AD|AT|AZ|BH|BY|BE|BA|BR|BG|CR|HR|CY|CZ|DK|DO|TL|EE|FO|FI|FR|'
            r'GE|DE|GI|GR|GL|GT|HU|IS|IQ|IE|IL|IT|JO|KZ|XK|KW|LV|LB|LI|LT|LU|'
            r'MK|MT|MR|MU|MC|MD|ME|NL|NO|PK|PS|PL|PT|QA|RO|LC|SM|ST|SA|RS|SC|SK|'
            r'SI|ES|SD|SE|CH|TN|TR|UA|AE|GB|VA|VG)'
            r'\d{2}[\s]?[A-Z0-9]{4}[\s]?[A-Z0-9\s]{6,31}\b',
            re.IGNORECASE
        ),
        "CRYPTO": re.compile(
            r'\b(?:0x[a-fA-F0-9]{40}|bc1[a-zA-Z0-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'
        ),
        # US SSN: with or without dashes, with optional spaces
        "US_SSN": re.compile(
            r'\b(?!000|666|9\d{2})'
            r'\d{3}[\s\-]?(?!00)\d{2}[\s\-]?(?!0000)\d{4}\b'
        ),
        # PESEL: 11 digits, optionally with spaces
        "POLISH_PESEL": re.compile(
            r'\b\d{2}[\s]?\d{2}[\s]?\d{2}[\s]?\d{5}\b'
        ),
        # NIP: flexible separators
        "POLISH_NIP": re.compile(
            r'\b\d{3}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b'
        ),
    }

    # Additional aggressive patterns for obfuscated numbers
    AGGRESSIVE_PATTERNS = {
        # Credit card with spaces between each digit (obfuscation attempt)
        "CREDIT_CARD_OBFUSCATED": re.compile(
            r'\b[4-6](?:[\s\-\.]*\d){14,18}\b'
        ),
        # SSN with various separators — require SSN-like structure (area-group-serial)
        # Area: 001-899 (excl 666), Group: 01-99, Serial: 0001-9999
        "US_SSN_OBFUSCATED": re.compile(
            r'\b(?!0{3})(?!6{3})[0-8]\d{2}[\s\-\.]+(?!0{2})\d{2}[\s\-\.]+(?!0{4})\d{4}\b'
        ),
    }

    _custom_loaded = False
    _custom_patterns: dict[str, re.Pattern] = {}
    _custom_entities: set[str] = set()
    _all_patterns: dict[str, re.Pattern] | None = None
    _custom_max_text_length: int | None = None

    @classmethod
    def _load_custom_patterns(cls) -> None:
        if cls._custom_loaded:
            return
        cls._custom_loaded = True

        settings = get_settings()
        if not settings.CUSTOM_FAST_PII_PATTERNS:
            return

        cls._custom_max_text_length = settings.CUSTOM_FAST_PII_MAX_TEXT_LENGTH
        for name, pattern in settings.CUSTOM_FAST_PII_PATTERNS.items():
            try:
                compiled = re.compile(pattern)
                cls._custom_patterns[name] = compiled
                cls._custom_entities.add(name)
            except re.error as e:
                raise ValueError(f"Invalid custom regex for {name}: {e}") from e
        if cls._custom_patterns:
            cls._all_patterns = {**cls.PATTERNS, **cls._custom_patterns}

    @classmethod
    def _get_patterns(cls) -> tuple[dict[str, re.Pattern], set[str], int | None]:
        if not cls._custom_loaded:
            cls._load_custom_patterns()
        return cls._all_patterns or cls.PATTERNS, cls._custom_entities, cls._custom_max_text_length

    @classmethod
    def detect(cls, text: str, entities: Optional[List[str]] = None) -> List[Dict]:
        detected_entities: List[Dict] = []
        settings = get_settings()
        include_debug_raw = settings.PII_DEBUG_INCLUDE_RAW and settings.LOG_LEVEL.upper() == "DEBUG"
        patterns, custom_entities, custom_max_len = cls._get_patterns()
        if entities:
            target_entities = [e.strip().upper() for e in entities if isinstance(e, str)]
        else:
            target_entities = list(patterns.keys())

        # Track matched positions to avoid duplicates
        matched_positions: set[tuple[int, int]] = set()

        for entity_type in target_entities:
            if entity_type in custom_entities and custom_max_len is not None:
                if len(text) > custom_max_len:
                    continue

            pattern = patterns.get(entity_type)
            if not pattern:
                continue

            for match in pattern.finditer(text):
                pos = (match.start(), match.end())
                if pos in matched_positions:
                    continue

                matched_text = match.group()
                confidence = 0.90

                # Special handling for credit cards - validate with Luhn
                if entity_type == "CREDIT_CARD":
                    digits_only = ''.join(c for c in matched_text if c.isdigit())
                    if len(digits_only) >= 13 and _luhn_checksum(digits_only):
                        confidence = 0.98  # High confidence with Luhn validation
                    else:
                        confidence = 0.75  # Lower confidence without Luhn

                matched_positions.add(pos)
                detected_entities.append({
                    "entity_type": entity_type,
                    "start": match.start(),
                    "end": match.end(),
                    **build_entity_text_fields(entity_type, matched_text, include_debug_raw),
                    "confidence": confidence,
                })

        # Run aggressive patterns for obfuscated data
        cls._detect_obfuscated(text, detected_entities, matched_positions, include_debug_raw)

        return detected_entities

    @classmethod
    def _detect_obfuscated(
        cls,
        text: str,
        detected_entities: List[Dict],
        matched_positions: set[tuple[int, int]],
        include_debug_raw: bool,
    ) -> None:
        """
        Detect obfuscated PII patterns (e.g., spaced-out credit cards).

        These patterns are more aggressive and may have more false positives,
        but catch intentional obfuscation attempts.
        """
        for pattern_name, pattern in cls.AGGRESSIVE_PATTERNS.items():
            for match in pattern.finditer(text):
                pos = (match.start(), match.end())

                # Skip if overlaps with already matched region
                overlaps = any(
                    not (pos[1] <= existing[0] or pos[0] >= existing[1])
                    for existing in matched_positions
                )
                if overlaps:
                    continue

                matched_text = match.group()
                digits_only = ''.join(c for c in matched_text if c.isdigit())

                # Determine entity type from pattern name
                if "CREDIT_CARD" in pattern_name:
                    entity_type = "CREDIT_CARD"
                    # Must have valid Luhn for obfuscated cards
                    if len(digits_only) >= 13 and _luhn_checksum(digits_only):
                        confidence = 0.95
                    else:
                        continue  # Skip invalid card numbers
                elif "SSN" in pattern_name:
                    entity_type = "US_SSN"
                    # SSN must be exactly 9 digits
                    if len(digits_only) != 9:
                        continue
                    # Additional SSN validation
                    area = int(digits_only[:3])
                    group = int(digits_only[3:5])
                    serial = int(digits_only[5:])
                    if area in (0, 666) or area >= 900 or group == 0 or serial == 0:
                        continue
                    confidence = 0.85
                else:
                    continue

                matched_positions.add(pos)
                detected_entities.append({
                    "entity_type": entity_type,
                    "start": match.start(),
                    "end": match.end(),
                    **build_entity_text_fields(entity_type, matched_text, include_debug_raw),
                    "confidence": confidence,
                    "obfuscation_detected": True,
                })


class PIILayer(SecurityLayer):
    """
    PII Detection Layer - regex-only OSS implementation.
    """

    FAST_ENTITIES = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "IP_ADDRESS",
        "US_SSN",
        "POLISH_PESEL",
        "POLISH_NIP",
        "IBAN_CODE",
        "CRYPTO",
    ]

    def __init__(
        self,
        entities: Optional[List[str]] = None,
        threshold: float = 0.7,
        use_fast: Optional[bool] = None,
    ):
        settings = get_settings()
        self._threshold = threshold
        self._entities = entities or self.FAST_ENTITIES
        self._detector = FastPIIDetector()
        self._mode = "FAST_REGEX"
        self._consecutive_errors = 0
        self._max_errors = 5
        self._fail_open = settings.FAIL_OPEN
        # Respect use_fast parameter
        self._use_fast = use_fast if use_fast is not None else settings.USE_FAST_PII
        
        if not self._use_fast:
            # In OSS build, we don't have GLiNER, so if use_fast=False,
            # this layer will essentially do nothing (return OK).
            # The provider should ideally handle this by not creating the layer.
            self._mode = "DISABLED"
            logging.getLogger(__name__).info(
                "PII layer initialized in DISABLED mode (USE_FAST_PII=false in OSS)"
            )
        else:
            self._mode = "FAST_REGEX"

    @property
    def name(self) -> str:
        return f"L3_PII_{self._mode}"

    async def scan(self, ctx: ScanContext) -> ScanResult:
        if self._mode == "DISABLED":
            return ScanResult.ok(layer=self.name)

        if self._consecutive_errors >= self._max_errors:
            if self._fail_open:
                return ScanResult.ok(layer=f"{self.name}_CIRCUIT_OPEN")
            return ScanResult.blocked(
                reason="PII detector unavailable (circuit open)",
                layer=self.name,
            )

        try:
            normalized_text = normalize_text(ctx.text)
            detected_entities = self._detector.detect(normalized_text, self._entities)
            self._consecutive_errors = 0

            high_confidence_entities = [
                entity for entity in detected_entities
                if entity["confidence"] >= self._threshold
            ]

            if high_confidence_entities:
                entity_types = list(set(e["entity_type"] for e in high_confidence_entities))
                return ScanResult.blocked(
                    reason=f"Detected PII: {', '.join(entity_types)}",
                    layer=self.name,
                    score=max(e["confidence"] for e in high_confidence_entities),
                )

            return ScanResult.ok(layer=self.name)

        except Exception as e:
            self._consecutive_errors += 1
            logging.getLogger(__name__).warning(
                "pii_scan_error",
                extra={"count": self._consecutive_errors, "error": str(e)[:100]},
            )
            if self._fail_open:
                return ScanResult.ok(layer=f"{self.name}_ERROR")
            return ScanResult.blocked(
                reason=f"PII detection error: {str(e)[:100]}",
                layer=self.name,
            )

    async def health_check(self) -> bool:
        return True

    def get_stats(self) -> Dict:
        return {
            "layer": self.name,
            "mode": self._mode,
            "entities": self._entities,
            "threshold": self._threshold,
            "performance": "~1-2ms",
        }

    def get_status(self) -> Dict:
        return {
            "name": self.name,
            "initialized": True,
            "ready": True,
            "error": None,
            "mode": self._mode,
            "entities": self._entities,
            "threshold": self._threshold,
        }


FastPIILayer = PIILayer


def cleanup_models() -> None:
    """No-op in OSS (no ML models loaded)."""
    return
