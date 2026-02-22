"""
Configuration management using Pydantic Settings.

All settings can be overridden via environment variables.
Example .env file:

    ENABLE_L1_KEYWORDS=true
    L1_BLOCKED_PHRASES=["hack","jailbreak"]
    L2_THRESHOLD=0.95
    LOG_LEVEL=DEBUG
"""
from functools import lru_cache
import re
from pydantic import field_validator, model_validator, ConfigDict, SecretStr
from pydantic_settings import BaseSettings

_NESTED_QUANTIFIER_RE = re.compile(r"\((?:[^()\\]|\\.)+[+*](?:[^()\\]|\\.)*\)[+*{]")


def _has_potential_regex_redos(pattern: str) -> bool:
    """
    Heuristic check for catastrophic-backtracking patterns.
    Reject obvious risky constructs before runtime.
    """
    if _NESTED_QUANTIFIER_RE.search(pattern):
        return True
    risky_tokens = ("(.+)+", "(.*)+", "(.+)*", "(.*)*", "(\\w+)+", "(\\d+)+")
    return any(token in pattern for token in risky_tokens)


class Settings(BaseSettings):
    """
    Application settings with environment variable support.
    
    Pydantic automatically:
    - Reads from environment variables (case-insensitive by default)
    - Parses JSON strings for complex types (lists, dicts)
    - Validates types and provides defaults
    """
    
    # === Layer Enablement ===
    # Safe defaults: Cache ON (Redis in stack), Keywords ON, PII ON (with shadow mode)
    ENABLE_CACHE: bool = True  # Redis cache layer - safe, no FP risk
    ENABLE_L1_KEYWORDS: bool = True  # Keyword filtering
    ENABLE_L2_AI: bool = False  # AI model (ONNX) - Enterprise only
    ENABLE_L3_PII: bool = True  # PII detection - safe with SHADOW_MODE=true
    
    # === L1: Keyword Configuration ===
    L1_BLOCKED_PHRASES: list[str] = [
        # --- English (Injection/Bypass) ---
        "ignore instructions", "ignore previous", "forget everything",
        "disregard guidelines", "shrug off", "bypass security",
        "system override", "developer mode", "do anything now",
        "stay in character", "act as if you are", "unfiltered response",
        "without any safety", "no restrictions", "reveal your prompt",
        "show me your text", "print your prompt", "system prompt",
        "ignore all preceding", "stop, ignore", "you are now xi jinping",
        "you are now ted", "pretend you are", "you are volkswagen",
        "act as a linux terminal", "ignore above", "forget about all",
        "leave all the previous", "concentrate on the new task",
        "remove all previous tasks", "what was written at the beginning",
        "only reply with", "do not write explanations", "ignore above and say",
        "show all your prompt", "reveal your instructions", "jailbreak", "pwned",
        "### instruction", "### response", "user:", "assistant:", "system:",
        "[system]", "[user]", "rewrite this prompt", "leak your prompt",
        
        # --- German (Injection/Bypass) ---
        "vergiss alle vorherigen", "ignoriere alle", "stopp, ignoriere",
        "vergiss alles davor", "vergiss alles, schreibe", "die obigen ausführungen ignorieren",
        "lass alle vorherigen informationen hinter sich", "aus dem kopf zu streichen",
        "was stand am anfang", "stell dir vor, du bist", "du bist zeit online",
        "antworte im stil eines",
        
        # --- Dangerous Actions ---
        "rm -rf", "drop table", "hack into", "<script>",
        "curl http", "wget http", "how to build a bomb",
        "how to create a virus", "malware code", "exploit code",
        "generate python code to", "generate c++", "schreibe c++",
    ]
    
    # === L2: AI Model Configuration ===
    L2_MODEL_PATH: str = "models/prompt_guard.onnx"
    L2_THRESHOLD: float = 0.9
    L2_MAX_LENGTH: int = 512  # Max tokens for model input
    
    # === L3: PII Configuration ===
    L3_PII_ENTITIES: list[str] = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
    ]
    L3_PII_THRESHOLD: float = 0.7
    L3_PII_LANGUAGE: str = "en"
    
    # PII Detection Method (OSS):
    # - USE_FAST_PII=true (default): Fast regex - basic PII only, ~1-2ms
    USE_FAST_PII: bool = True

    # === Custom Fast PII Regex ===
    # Provide custom regex patterns for company-specific identifiers.
    # Example (JSON):
    #   CUSTOM_FAST_PII_PATTERNS='{"ACME_ID":"ACME-[0-9]{4}"}'
    #
    # Safety limits to reduce ReDoS risk:
    # - Limit count and pattern length
    # - Limit text length for custom pattern matching
    CUSTOM_FAST_PII_PATTERNS: dict[str, str] = {}
    CUSTOM_FAST_PII_MAX_PATTERNS: int = 50
    CUSTOM_FAST_PII_MAX_PATTERN_LENGTH: int = 256
    CUSTOM_FAST_PII_MAX_TEXT_LENGTH: int = 20_000
    
    # === Model Preloading ===
    # Multi-worker memory optimization (Gunicorn/Granian with workers > 1)
    #
    # PRELOAD_MODELS=true: Models load at startup (before fork)
    #   - Requires: gunicorn --preload or granian --workers 1
    #   - RAM: Shared via Copy-on-Write (~500MB for 4 workers)
    #
    # PRELOAD_MODELS=false (default): Lazy loading on first request
    #   - RAM: Each worker loads its own copy (~500MB * N workers)
    #   - Good for dev/test or single worker
    #
    # For production with multi-worker: PRELOAD_MODELS=true + gunicorn --preload
    PRELOAD_MODELS: bool = False
    
    # === Redis Cache ===
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_TTL: int = 3600  # 1 hour cache
    REDIS_TIMEOUT: float = 0.5  # Connection timeout
    REDIS_PASSWORD: SecretStr | None = None  # Optional Redis auth
    
    # === Audit Logs ===
    # Reserved for enterprise; no-op in OSS.
    ENABLE_AUDIT_LOGS: bool = False
    AUDIT_QUEUE_NAME: str = "safellm:audit_logs"
    
    # === DLP (Data Loss Prevention) - Output Scanning ===
    # Scans LLM responses for PII/sensitive data before returning to client
    #
    # ENABLE_DLP=true: Buffer response, scan for PII, block/anonymize if detected
    # ENABLE_DLP=false: No output scanning (faster, but risky)
    #
    # DLP_STREAMING_MODE (Enterprise feature):
    #   - "block":  Buffer → Scan → Send (higher TTFT, safer)
    #               Response is returned only after scanning.
    #   - "audit":  Stream → Log in background (fast TTFT, post-factum detection)
    #               Response is sent immediately; scan happens in background (http-logger batch).
    #               Ideal for SaaS/Startups where UX > immediate blocking.
    #
    # DLP_MODE options (for block mode):
    #   - "block":     Replace entire response with "[BLOCKED DUE TO PII LEAK]"
    #   - "anonymize": Replace PII with [REDACTED] placeholders
    #   - "log":       Allow response but log detected PII for audit
    #
    # Note: DLP_STREAMING_MODE=block increases TTFT (Time To First Token)
    ENABLE_DLP: bool = False
    DLP_STREAMING_MODE: str = "block"  # "block" | "audit"
    DLP_MODE: str = "block"  # "block" | "anonymize" | "log" (for streaming_mode=block)
    
    # DLP PII entities to scan in output (subset of L3_PII_ENTITIES)
    DLP_PII_ENTITIES: list[str] = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "IBAN_CODE",
        "IP_ADDRESS",
        "US_SSN",
        "CRYPTO",
    ]
    DLP_PII_THRESHOLD: float = 0.5  # Higher threshold for output (reduce false positives)
    
    # DLP output size limit (LLM responses can be longer than prompts)
    # 500K chars ≈ ~2MB worst case UTF-8, handles most LLM responses
    DLP_MAX_OUTPUT_LENGTH: int = 500_000
    
    # DLP block message (shown when PII detected in mode=block)
    DLP_BLOCK_MESSAGE: str = "[BLOCKED DUE TO PII LEAK]"
    
    # DLP Fail behavior on scanner errors
    # DLP_FAIL_OPEN=true:  Allow response if scanner fails (risky, for SaaS)
    # DLP_FAIL_OPEN=false: Block response if scanner fails (safe, for banks/healthcare)
    #
    # Default: false (fail-closed) - safer for production use cases
    DLP_FAIL_OPEN: bool = False
    
    # === Shadow Mode (Day-0 Safe Deployment) ===
    # When enabled, pipeline logs "would_block" but allows all requests.
    # Perfect for CISO/Security teams to evaluate rules without blocking production.
    #
    # SHADOW_MODE=true:
    #   - All layers execute normally
    #   - Blocked results logged as "shadow_would_block" 
    #   - Request is ALLOWED (decision.allowed=True)
    #   - Audit logs show what WOULD have been blocked
    #
    # SHADOW_MODE=false:
    #   - Normal blocking behavior
    #
    # Use case: Start with shadow mode, analyze logs, tune thresholds, then disable.
    # Default: true for safe onboarding - new users see what WOULD be blocked
    SHADOW_MODE: bool = True
    
    # === Security ===
    MAX_BODY_SIZE: int = 1_048_576  # 1 MiB max request body (matches APISIX)
    REQUEST_TIMEOUT: int = 30
    FAIL_OPEN: bool = False  # If True, allow on layer errors; False = block
    
    # === Logging ===
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # "json" or "text"
    PII_DEBUG_INCLUDE_RAW: bool = False
    MANAGEMENT_API_KEY: SecretStr | None = None
    
    # === Observability ===
    # Feature flag dla Prometheus metrics
    # Disabling saves CPU/RAM (no middleware for every request)
    ENABLE_METRICS: bool = True
    
    # === Response Headers ===
    ALLOW_HEADER: str = "X-Auth-Result"
    
    @field_validator("L1_BLOCKED_PHRASES", mode="before")
    @classmethod
    def parse_blocked_phrases(cls, v):
        """Parse comma-separated string or JSON list."""
        if isinstance(v, str):
            # Try JSON first
            if v.startswith("["):
                import json
                return json.loads(v)
            # Fallback to comma-separated
            return [item.strip().lower() for item in v.split(",") if item.strip()]
        return v
    
    @field_validator("L3_PII_ENTITIES", "DLP_PII_ENTITIES", mode="before")
    @classmethod
    def parse_pii_entities(cls, v):
        """Parse comma-separated string or JSON list."""
        if isinstance(v, str):
            if v.startswith("["):
                import json
                return json.loads(v)
            return [item.strip().upper() for item in v.split(",") if item.strip()]
        return v
    
    @field_validator("DLP_MODE", mode="before")
    @classmethod
    def validate_dlp_mode(cls, v):
        """Validate DLP mode is one of allowed values."""
        allowed = {"block", "anonymize", "log"}
        if isinstance(v, str):
            v = v.lower().strip()
            if v not in allowed:
                raise ValueError(f"DLP_MODE must be one of: {allowed}")
        return v
    
    @field_validator("DLP_STREAMING_MODE", mode="before")
    @classmethod
    def validate_dlp_streaming_mode(cls, v):
        """Validate DLP streaming mode (block vs audit)."""
        allowed = {"block", "audit"}
        if isinstance(v, str):
            v = v.lower().strip()
            if v not in allowed:
                raise ValueError(f"DLP_STREAMING_MODE must be one of: {allowed}")
        return v
    
    @model_validator(mode="after")
    def validate_redis_config(self):
        """No-op placeholder for Redis validation in OSS."""
        return self

    @model_validator(mode="after")
    def validate_dlp_config(self):
        """Ensure DLP modes are consistent.
        
        DLP_STREAMING_MODE controls HOW responses are handled:
          - "block": Buffer response, scan, then return (higher TTFT)
          - "audit": Stream immediately, scan async in background
          
        DLP_MODE controls WHAT to do when PII is detected:
          - "block": Replace entire response with error
          - "anonymize": Replace PII with [REDACTED]
          - "log": Allow but log for audit (valid with both streaming modes)
          
        The only invalid combo: audit streaming + block/anonymize mode
        (can't block a response that's already streamed)
        """
        if self.DLP_STREAMING_MODE == "audit" and self.DLP_MODE != "log":
            raise ValueError(
                f"DLP_MODE must be 'log' when DLP_STREAMING_MODE='audit'. "
                f"Cannot block/anonymize an already-streamed response."
            )
        # Note: DLP_STREAMING_MODE="block" is valid with any DLP_MODE
        # (block, anonymize, or log) - we buffer in all cases
        return self

    @model_validator(mode="after")
    def validate_custom_fast_pii(self):
        """Validate custom fast PII patterns length/count and normalize keys."""
        if self.CUSTOM_FAST_PII_PATTERNS:
            if len(self.CUSTOM_FAST_PII_PATTERNS) > self.CUSTOM_FAST_PII_MAX_PATTERNS:
                raise ValueError(
                    f"CUSTOM_FAST_PII_PATTERNS too large: "
                    f"{len(self.CUSTOM_FAST_PII_PATTERNS)} > {self.CUSTOM_FAST_PII_MAX_PATTERNS}"
                )
            normalized: dict[str, str] = {}
            for name, pattern in self.CUSTOM_FAST_PII_PATTERNS.items():
                if not isinstance(name, str) or not name.strip():
                    raise ValueError("CUSTOM_FAST_PII_PATTERNS keys must be non-empty strings")
                if not isinstance(pattern, str) or not pattern.strip():
                    raise ValueError("CUSTOM_FAST_PII_PATTERNS values must be non-empty strings")
                if len(pattern) > self.CUSTOM_FAST_PII_MAX_PATTERN_LENGTH:
                    raise ValueError(
                        f"Custom regex '{name}' too long: "
                        f"{len(pattern)} > {self.CUSTOM_FAST_PII_MAX_PATTERN_LENGTH}"
                    )
                if _has_potential_regex_redos(pattern):
                    raise ValueError(
                        f"Custom regex '{name}' rejected due to potential ReDoS risk"
                    )
                normalized[name.strip().upper()] = pattern
            self.CUSTOM_FAST_PII_PATTERNS = normalized
        return self
    
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Uses lru_cache to ensure settings are only loaded once.
    Call get_settings.cache_clear() to reload.
    """
    return Settings()


# Properties for convenience (replaces LegacySettings)
Settings.blocked_phrases = property(lambda self: self.L1_BLOCKED_PHRASES)
Settings.allow_header = property(lambda self: self.ALLOW_HEADER)
