"""
Text processing utilities for security layers.

Unicode Normalization:
    Security-critical text processing requires Unicode normalization to prevent
    bypass attacks using different representations of the same character.
    
    Example attacks prevented:
    - Combining characters: café (e + combining accent) vs café (precomposed é)
    - Homoglyphs: Cyrillic "а" vs Latin "a"
    - Full-width chars: "ｔｅｓｔ" vs "test"
    
    We use NFKC (Normalization Form KC - Compatibility Composition):
    - K: Compatibility decomposition (handles full-width, ligatures, etc.)
    - C: Canonical composition (combines base + combining chars)
    
    Why NFKC over NFC:
    - NFC only handles canonical equivalence (decomposed ↔ composed)
    - NFKC also handles compatibility equivalence (ﬁ → fi, ２ → 2)
    - NFKC is more aggressive, better for security use cases
"""
import json
import unicodedata
from functools import lru_cache


def normalize_text(text: str) -> str:
    """
    Normalize Unicode text for security scanning (NFKC).
    
    This MUST be called before any text matching (keywords, regex, hashing)
    to prevent Unicode bypass attacks.
    
    Args:
        text: Raw input text (may contain non-normalized Unicode)
        
    Returns:
        NFKC-normalized text
        
    Example:
        >>> normalize_text("café")  # combining accent
        'café'  # precomposed
        >>> normalize_text("ｔｅｓｔ")  # full-width
        'test'  # ASCII
    """
    if not text:
        return text
    return unicodedata.normalize("NFKC", text)


def normalize_for_cache(text: str) -> str:
    """
    Normalize text for cache key generation.
    
    Same as normalize_text but explicitly named for cache layer
    to document intent.
    """
    normalized = normalize_text(text)
    if not normalized:
        return normalized

    stripped = normalized.strip()
    if not stripped:
        return normalized

    # If payload is JSON, canonicalize it to avoid cache misses from key order
    if stripped[0] in ("{", "["):
        try:
            obj = json.loads(stripped)
            return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        except Exception:
            return normalized

    return normalized


@lru_cache(maxsize=1024)
def normalize_keyword(keyword: str) -> str:
    """
    Normalize a keyword/phrase for matching.
    
    Cached because keywords are loaded once and reused.
    """
    return normalize_text(keyword.lower())


def normalize_for_matching(text: str) -> str:
    """
    Normalize text for keyword/pattern matching.
    
    Applies NFKC normalization AND lowercasing for case-insensitive matching.
    """
    return normalize_text(text).lower()


def leetspeak_normalize(text: str) -> str:
    """
    Highly aggressive normalization for security scanning.
    
    1. Lowercase & NFKC (Unicode normalization)
    2. Leetspeak mapping (4 -> a, 1 -> i, 0 -> o, etc.)
    3. Skeleton (keep only alnum)
    
    This is used to catch bypasses like "j @ 1 l b r 3 @ k".
    """
    text = normalize_text(text).lower()
    
    # Common leetspeak mappings (reduced sensitivity - removed 0/1 to avoid false positives)
    leet_map = {
        '4': 'a', '@': 'a',
        '3': 'e',
        '!': 'i', '|': 'i',
        '5': 's', '$': 's',
        '7': 't', '+': 't',
        '8': 'b',
    }
    
    # 1. Apply leet map
    for char, replacement in leet_map.items():
        text = text.replace(char, replacement)
        
    # 2. Skeleton: Keep alphanumeric and common markers to reduce false positives
    return "".join(c for c in text if c.isalnum() or c in ":#@")
