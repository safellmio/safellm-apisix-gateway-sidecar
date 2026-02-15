"""L1 Security Layer: Fast keyword detection using FlashText."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from .base import SecurityLayer, ScanContext, ScanResult
from ..core.text import normalize_text, normalize_keyword, leetspeak_normalize

try:
    from flashtext import KeywordProcessor
    HAS_FLASHTEXT = True
except ImportError:
    HAS_FLASHTEXT = False

# Threshold for offloading to thread pool (bytes)
# FlashText is O(n) where n = text length, can block event loop for large texts
LARGE_TEXT_THRESHOLD = 50_000  # 50KB


class KeywordLayer(SecurityLayer):
    """
    L1 Security: Ultra-fast keyword detection.
    
    Uses FlashText (Aho-Corasick algorithm) for O(n) keyword matching.
    Falls back to simple string matching if FlashText not installed.
    
    Performance: <0.01ms for small texts, offloaded for large texts
    
    Thread Safety:
    - For texts > 50KB, uses ThreadPoolExecutor to avoid blocking event loop
    - This prevents heartbeat failures and request timeouts on large documents
    """
    
    # Class-level executor for large text processing
    _executor: Optional[ThreadPoolExecutor] = None
    
    def __init__(self, blocked_phrases: list[str]):
        # Normalize keywords at init time (cached via lru_cache)
        self._blocked = [normalize_keyword(p) for p in blocked_phrases]
        # Pre-calculate leet skeletons for ultra-fast matching
        self._leet_skeletons = [leetspeak_normalize(p) for p in blocked_phrases]
        self._processor = None
        
        if HAS_FLASHTEXT:
            self._processor = KeywordProcessor()
            for phrase in self._blocked:
                self._processor.add_keyword(phrase)
        
        # Initialize executor if needed
        if KeywordLayer._executor is None:
            import os
            max_workers = min(4, (os.cpu_count() or 1) + 1)
            KeywordLayer._executor = ThreadPoolExecutor(
                max_workers=max_workers,
                thread_name_prefix="keyword_scan"
            )
    
    @classmethod
    def cleanup_executor(cls):
        """Cleanup class-level ThreadPoolExecutor."""
        if cls._executor is not None:
            cls._executor.shutdown(wait=True)
            cls._executor = None

    @property
    def name(self) -> str:
        return "L1_KEYWORDS"
    
    def _scan_sync(self, text_lower: str) -> Optional[str]:
        """
        Synchronous keyword scan (for thread pool execution).
        
        Returns:
            Matched keyword or None if no match
        """
        # 1. Standard matching (Fastest - FlashText)
        if self._processor:
            matches = self._processor.extract_keywords(text_lower)
            if matches:
                return matches[0]
        else:
            # Fallback when flashtext is missing
            for phrase in self._blocked:
                if phrase in text_lower:
                    return phrase
        
        # 2. Hardened matching: Leetspeak + Skeleton (catch "j @ 1 l b r 3 @ k")
        # Optimization: Only run if text has symbols/numbers or is very long
        # Security: Only match skeletons > 3 chars to avoid false positives on short words
        text_leet = leetspeak_normalize(text_lower)
        for i, skeleton in enumerate(self._leet_skeletons):
            if skeleton and len(skeleton) > 3 and skeleton in text_leet:
                return self._blocked[i]
                    
        return None
    
    async def scan(self, ctx: ScanContext) -> ScanResult:
        # Normalize text to prevent Unicode bypass attacks
        text_lower = normalize_text(ctx.text).lower()
        
        # For large texts, offload to thread pool to avoid blocking event loop
        # FlashText is O(n), can take 20-50ms for 500KB documents
        if len(text_lower) > LARGE_TEXT_THRESHOLD:
            loop = asyncio.get_running_loop()
            match = await loop.run_in_executor(
                KeywordLayer._executor,
                self._scan_sync,
                text_lower
            )
        else:
            # Small text - run inline (sub-millisecond)
            match = self._scan_sync(text_lower)
        
        if match:
            return ScanResult.blocked(
                reason=f"blocked: {match}",
                layer=self.name,
                score=1.0
            )
        
        return ScanResult.ok(layer=self.name)
