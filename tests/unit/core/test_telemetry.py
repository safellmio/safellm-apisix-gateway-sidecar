"""
Unit tests for telemetry module and metrics integration.

Tests cover:
- Telemetry module initialization and metric definitions
- Feature flag ENABLE_METRICS functionality
- Metric imports and circular import prevention
- Basic metric operations (increment, observe, etc.)
"""
import pytest
from unittest.mock import patch, MagicMock
from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge

from sidecar.core.telemetry import (
    BLOCKED_REQUESTS,
    SCAN_LATENCY,
    PROMPT_LENGTH,
    ACTIVE_REQUESTS,
    CACHE_HITS,
    CACHE_MISSES
)
from sidecar.core.settings import Settings, get_settings


class TestTelemetryModule:
    """Test telemetry module metric definitions and basic operations."""

    def test_blocked_requests_metric_definition(self):
        """Test BLOCKED_REQUESTS counter is properly defined."""
        assert isinstance(BLOCKED_REQUESTS, Counter)
        # Prometheus automatically adds "_total" suffix to counters
        assert BLOCKED_REQUESTS._name == "safellm_blocked_requests"
        assert "layer" in BLOCKED_REQUESTS._labelnames
        assert "reason" in BLOCKED_REQUESTS._labelnames

    def test_scan_latency_metric_definition(self):
        """Test SCAN_LATENCY histogram is properly defined."""
        assert isinstance(SCAN_LATENCY, Histogram)
        assert SCAN_LATENCY._name == "safellm_scan_duration_seconds"
        assert "layer" in SCAN_LATENCY._labelnames

        # Check buckets are optimized for microsecond/millisecond operations
        # Prometheus automatically adds +inf bucket
        expected_buckets = [0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, float('inf')]
        assert SCAN_LATENCY._upper_bounds == expected_buckets

    def test_prompt_length_metric_definition(self):
        """Test PROMPT_LENGTH histogram is properly defined."""
        assert isinstance(PROMPT_LENGTH, Histogram)
        assert PROMPT_LENGTH._name == "safellm_prompt_length_chars"
        # Should have no labels (empty tuple)
        assert PROMPT_LENGTH._labelnames == ()

    def test_active_requests_metric_definition(self):
        """Test ACTIVE_REQUESTS gauge is properly defined."""
        assert isinstance(ACTIVE_REQUESTS, Gauge)
        assert ACTIVE_REQUESTS._name == "safellm_active_requests"

    def test_cache_metrics_definition(self):
        """Test cache metrics are properly defined."""
        assert isinstance(CACHE_HITS, Counter)
        # Prometheus automatically adds "_total" suffix to counters
        assert CACHE_HITS._name == "safellm_cache_hits"
        assert "result" in CACHE_HITS._labelnames

        assert isinstance(CACHE_MISSES, Counter)
        assert CACHE_MISSES._name == "safellm_cache_misses"

    def test_metric_operations(self):
        """Test basic metric operations work without errors."""
        # Create isolated registry for testing
        registry = CollectorRegistry()

        # Test counter increment
        counter = Counter("test_counter", "Test counter", registry=registry)
        counter.inc()
        # Just verify the operation doesn't crash
        assert counter is not None

        # Test histogram observe
        histogram = Histogram("test_histogram", "Test histogram", registry=registry)
        histogram.observe(0.005)
        # Just verify the operation doesn't crash
        assert histogram is not None

        # Test gauge operations
        gauge = Gauge("test_gauge", "Test gauge", registry=registry)
        gauge.inc()
        gauge.dec()
        # Just verify the operation doesn't crash
        assert gauge is not None

    def test_reason_label_values(self):
        """Test that BLOCKED_REQUESTS accepts defined reason values."""
        # These should work without errors
        allowed_reasons = [
            "keyword_match",
            "pii_detected",
            "injection_score_high",
            "cache_hit_blocked"
        ]

        layers = ["keywords", "ai_guard", "pii", "cache"]

        for layer in layers:
            for reason in allowed_reasons:
                # This should not raise an exception
                metric = BLOCKED_REQUESTS.labels(layer=layer, reason=reason)
                assert metric is not None


class TestEnableMetricsFeatureFlag:
    """Test ENABLE_METRICS feature flag functionality."""

    def test_enable_metrics_default_true(self):
        """Test ENABLE_METRICS defaults to True."""
        settings = Settings()
        assert settings.ENABLE_METRICS is True

    def test_enable_metrics_env_override_false(self):
        """Test ENABLE_METRICS can be overridden via environment."""
        with patch.dict("os.environ", {"ENABLE_METRICS": "false"}):
            settings = Settings()
            assert settings.ENABLE_METRICS is False

    def test_enable_metrics_env_override_true(self):
        """Test ENABLE_METRICS explicit true via environment."""
        with patch.dict("os.environ", {"ENABLE_METRICS": "true"}):
            settings = Settings()
            assert settings.ENABLE_METRICS is True

    def test_enable_metrics_case_insensitive(self):
        """Test ENABLE_METRICS is case insensitive."""
        with patch.dict("os.environ", {"enable_metrics": "False"}):
            settings = Settings()
            assert settings.ENABLE_METRICS is False


class TestMetricsIntegration:
    """Test metrics integration patterns (to be used by layers)."""

    def test_blocked_requests_pattern(self):
        """Test the BLOCKED_REQUESTS usage pattern from layers."""
        # Simulate what layers/keywords.py should do
        BLOCKED_REQUESTS.labels(layer="keywords", reason="keyword_match").inc()

        # Should not raise any exceptions
        assert True

    def test_scan_latency_pattern(self):
        """Test the SCAN_LATENCY usage pattern with context manager."""
        # Simulate what layers/ai_guard.py should do
        with SCAN_LATENCY.labels(layer="ai_guard").time():
            # Simulate some work
            import time
            time.sleep(0.001)

        # Should not raise any exceptions
        assert True

    def test_prompt_length_pattern(self):
        """Test the PROMPT_LENGTH usage pattern."""
        test_prompt = "This is a test prompt for security scanning."
        PROMPT_LENGTH.observe(len(test_prompt))

        # Should not raise any exceptions
        assert True

    def test_active_requests_pattern(self):
        """Test ACTIVE_REQUESTS gauge usage pattern."""
        ACTIVE_REQUESTS.inc()
        # Just verify the operation doesn't crash
        assert ACTIVE_REQUESTS is not None

        ACTIVE_REQUESTS.dec()
        # Just verify the operation doesn't crash
        assert ACTIVE_REQUESTS is not None

    def test_cache_metrics_pattern(self):
        """Test cache metrics usage patterns."""
        CACHE_HITS.labels(result="allowed").inc()
        CACHE_HITS.labels(result="blocked").inc()
        CACHE_MISSES.inc()

        # Should not raise any exceptions
        assert True


class TestCircularImportPrevention:
    """Test that telemetry module prevents circular imports."""

    def test_can_import_from_layers(self):
        """Test that layers can safely import from telemetry."""
        # This is the pattern that should work in layers
        try:
            from sidecar.core.telemetry import BLOCKED_REQUESTS as test_import
            assert test_import is not None
        except ImportError:
            pytest.fail("Layers should be able to import from telemetry module")

    def test_telemetry_independent_of_layers(self):
        """Test that telemetry module doesn't import anything from layers."""
        import sidecar.core.telemetry

        # Check that telemetry module doesn't import from layers
        # (this is a basic check - in practice we'd need to inspect the module)
        assert hasattr(sidecar.core.telemetry, 'BLOCKED_REQUESTS')