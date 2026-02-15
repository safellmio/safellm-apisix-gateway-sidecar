import os
import pytest
from unittest.mock import patch
from sidecar.core.settings import Settings, get_settings
from sidecar.core.providers import get_pii_layer

class TestEnvConfigOSS:
    """Test environment variable configurations and limits in OSS edition."""

    def test_pii_use_fast_false_disables_layer(self):
        """Test that USE_FAST_PII=false disables PII layer in OSS (no GLiNER)."""
        with patch.dict(os.environ, {"USE_FAST_PII": "false", "ENABLE_L3_PII": "true"}):
            settings = Settings()
            assert settings.USE_FAST_PII is False
            layer = get_pii_layer(settings)
            # In OSS, if USE_FAST_PII=false, layer should be None because GLiNER is missing
            assert layer is None

    def test_pii_use_fast_true_enables_regex(self):
        """Test that USE_FAST_PII=true enables Regex layer in OSS."""
        with patch.dict(os.environ, {"USE_FAST_PII": "true", "ENABLE_L3_PII": "true"}):
            settings = Settings()
            assert settings.USE_FAST_PII is True
            layer = get_pii_layer(settings)
            assert layer is not None
            assert layer._mode == "FAST_REGEX"

    def test_configurable_limits(self):
        """Test that limits are configurable in OSS."""
        custom_limits = {
            "CUSTOM_FAST_PII_MAX_TEXT_LENGTH": "15000",
            "DLP_MAX_OUTPUT_LENGTH": "200000"
        }
        with patch.dict(os.environ, custom_limits):
            get_settings.cache_clear()
            settings = Settings()
            assert settings.CUSTOM_FAST_PII_MAX_TEXT_LENGTH == 15000
            assert settings.DLP_MAX_OUTPUT_LENGTH == 200000

    def test_custom_regex_allowed_in_oss(self):
        """Test that custom regex patterns are allowed in OSS mode."""
        from sidecar.layers.pii_fast import FastPIIDetector
        
        custom_config = {
            "CUSTOM_FAST_PII_PATTERNS": '{"ACME_ID": "ACME-[0-9]{4}"}',
            "SAFELLM_EDITION": "oss"
        }
        with patch.dict(os.environ, custom_config):
            get_settings.cache_clear()
            # FastPIIDetector caches patterns at class level
            FastPIIDetector._custom_loaded = False
            patterns, custom_entities, _ = FastPIIDetector._get_patterns()
            
            assert "ACME_ID" in custom_entities
            assert "ACME_ID" in patterns
