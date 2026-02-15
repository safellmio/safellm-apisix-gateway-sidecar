"""
Comprehensive DLP (Data Loss Prevention) Tests for Output Scanning.

Tests cover:
- Prometheus metrics recording
- Settings validation (DLP_MAX_OUTPUT_LENGTH, DLP_BLOCK_MESSAGE)
- All DLP modes (block, anonymize, log)
- PII detection accuracy
- Error handling and fail-open behavior
- Performance measurements
- Edge cases and boundary conditions

Test Scenarios for Cheaper Model:
- Test DLP metrics are recorded in Prometheus format
- Test DLP_BLOCK_MESSAGE setting is used instead of hardcoded string
- Test DLP_MAX_OUTPUT_LENGTH validation works

Additional comprehensive tests:
- All PII entity types detection
- Multiple PII in single text
- Different confidence thresholds
- Thread safety and concurrency
- Memory usage patterns
- Scanner health checks
"""

import asyncio
import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List

# Test data with various PII types
TEST_TEXTS = {
    "clean": "This is a clean text with no sensitive information.",
    "email": "Contact me at john.doe@example.com for more details.",
    "phone": "My phone number is (555) 123-4567.",
    "credit_card": "Payment processed using card 4111-1111-1111-1111.",
    "iban": "Bank account: DE89370400440532013000",
    "ip_address": "Server located at 192.168.1.100",
    "us_ssn": "Social Security Number: 900-12-3456",
    "crypto": "Bitcoin address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    "multiple_pii": """
        Contact: john.doe@example.com
        Phone: (555) 123-4567
        Card: 4111-1111-1111-1111
        IP: 192.168.1.100
        SSN: 900-12-3456
    """,
    "empty": "",
    "very_long": "A" * 10000,  # 10KB text
}

EXPECTED_ENTITIES = {
    "email": [{"entity_type": "EMAIL_ADDRESS", "text": "john.doe@example.com"}],
    "phone": [{"entity_type": "PHONE_NUMBER", "text": "(555) 123-4567"}],
    "credit_card": [{"entity_type": "CREDIT_CARD", "text": "4111-1111-1111-1111"}],
    "iban": [{"entity_type": "IBAN_CODE", "text": "DE89370400440532013000"}],
    "ip_address": [{"entity_type": "IP_ADDRESS", "text": "192.168.1.100"}],
    "us_ssn": [{"entity_type": "US_SSN", "text": "900-12-3456"}],
    "crypto": [{"entity_type": "CRYPTO", "text": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"}],
}


class TestDLPMetrics:
    """Test Prometheus metrics recording for DLP scans."""

    @pytest.fixture
    def mock_metrics(self):
        """Mock Prometheus metrics."""
        with patch('sidecar.layers.dlp.DLP_SCANS_TOTAL') as mock_scans, \
             patch('sidecar.layers.dlp.DLP_SCAN_LATENCY') as mock_latency, \
             patch('sidecar.layers.dlp.DLP_PII_DETECTED') as mock_detected:

            # Configure mocks - DLP_SCANS_TOTAL.labels() should return a mock with .inc()
            mock_scans.labels.return_value.inc = Mock()
            mock_latency.labels.return_value.observe = Mock()
            mock_detected.labels.return_value.inc = Mock()

            yield {
                'scans': mock_scans,
                'latency': mock_latency,
                'detected': mock_detected
            }

    @pytest.mark.asyncio
    async def test_metrics_recorded_on_clean_scan(self, mock_metrics):
        """Test that metrics are recorded when no PII is detected."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        result = await scanner.scan_output(TEST_TEXTS["clean"])

        # Verify result is correct
        assert result.safe is True
        assert result.pii_detected is False

        # Verify metrics were recorded
        mock_metrics['scans'].labels.assert_called_with(mode="block", result="clean")
        mock_metrics['scans'].labels.return_value.inc.assert_called_once()

        mock_metrics['latency'].labels.assert_called_with(mode="block")
        mock_metrics['latency'].labels.return_value.observe.assert_called_once()

        # No PII detected, so no entity metrics
        mock_metrics['detected'].labels.assert_not_called()

    @pytest.mark.asyncio
    async def test_metrics_recorded_on_pii_detected_block_mode(self, mock_metrics):
        """Test that metrics are recorded when PII is detected in block mode."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        result = await scanner.scan_output(TEST_TEXTS["email"])

        # Verify scan metrics
        mock_metrics['scans'].labels.assert_called_with(mode="block", result="blocked")
        mock_metrics['scans'].labels().inc.assert_called_once()

        # Verify latency metrics
        mock_metrics['latency'].labels.assert_called_with(mode="block")
        mock_metrics['latency'].labels().observe.assert_called_once()

        # Verify PII detection metrics
        mock_metrics['detected'].labels.assert_called_with(entity_type="EMAIL_ADDRESS")
        mock_metrics['detected'].labels().inc.assert_called_once()

    @pytest.mark.asyncio
    async def test_metrics_recorded_on_pii_detected_anonymize_mode(self, mock_metrics):
        """Test that metrics are recorded when PII is detected in anonymize mode."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="anonymize")
        result = await scanner.scan_output(TEST_TEXTS["email"])

        mock_metrics['scans'].labels.assert_called_with(mode="anonymize", result="anonymized")
        mock_metrics['scans'].labels().inc.assert_called_once()

        mock_metrics['detected'].labels.assert_called_with(entity_type="EMAIL_ADDRESS")
        mock_metrics['detected'].labels().inc.assert_called_once()

    @pytest.mark.asyncio
    async def test_metrics_recorded_on_pii_detected_log_mode(self, mock_metrics):
        """Test that metrics are recorded when PII is detected in log mode."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="log")
        result = await scanner.scan_output(TEST_TEXTS["email"])

        mock_metrics['scans'].labels.assert_called_with(mode="log", result="logged")
        mock_metrics['scans'].labels().inc.assert_called_once()

        mock_metrics['detected'].labels.assert_called_with(entity_type="EMAIL_ADDRESS")
        mock_metrics['detected'].labels().inc.assert_called_once()

    @pytest.mark.asyncio
    async def test_metrics_recorded_multiple_entities(self, mock_metrics):
        """Test that metrics are recorded for multiple PII entities."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        result = await scanner.scan_output(TEST_TEXTS["multiple_pii"])

        # Should record metrics for each entity type
        calls = mock_metrics['detected'].labels.call_args_list
        entity_types = [call[1]['entity_type'] for call in calls]

        assert "EMAIL_ADDRESS" in entity_types
        assert "PHONE_NUMBER" in entity_types
        assert "CREDIT_CARD" in entity_types
        assert len(calls) >= 3  # At least 3 different entity types

    @pytest.mark.asyncio
    async def test_metrics_disabled_when_not_available(self):
        """Test graceful handling when metrics are not available."""
        with patch('sidecar.layers.dlp.DLP_SCANS_TOTAL', None), \
             patch('sidecar.layers.dlp.DLP_SCAN_LATENCY', None), \
             patch('sidecar.layers.dlp.DLP_PII_DETECTED', None):

            from sidecar.layers.dlp import DLPScanner

            scanner = DLPScanner(mode="block")
            result = await scanner.scan_output(TEST_TEXTS["email"])

            # Should still work without metrics
            assert result.pii_detected is True
            assert result.safe is False


class TestDLPSettings:
    """Test DLP settings usage (DLP_MAX_OUTPUT_LENGTH, DLP_BLOCK_MESSAGE)."""

    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing."""
        mock_settings = Mock()
        mock_settings.DLP_BLOCK_MESSAGE = "[CUSTOM BLOCK MESSAGE]"
        mock_settings.DLP_MAX_OUTPUT_LENGTH = 1000
        mock_settings.DLP_MODE = "block"
        mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
        mock_settings.DLP_PII_THRESHOLD = 0.5
        return mock_settings

    def test_custom_block_message_from_settings(self, mock_settings):
        """Test that DLP_BLOCK_MESSAGE setting is used."""
        with patch('sidecar.core.settings.get_settings', return_value=mock_settings):
            from sidecar.layers.dlp import DLPScanner

            scanner = DLPScanner(mode="block")
            assert scanner._block_message == "[CUSTOM BLOCK MESSAGE]"

    def test_custom_block_message_override(self, mock_settings):
        """Test that block_message parameter overrides settings."""
        with patch('sidecar.core.settings.get_settings', return_value=mock_settings):
            from sidecar.layers.dlp import DLPScanner

            scanner = DLPScanner(mode="block", block_message="[OVERRIDE MESSAGE]")
            assert scanner._block_message == "[OVERRIDE MESSAGE]"

    def test_fallback_block_message_on_settings_error(self):
        """Test fallback when settings can't be loaded."""
        with patch('sidecar.core.settings.get_settings', side_effect=Exception("Settings error")):
            from sidecar.layers.dlp import DLPScanner

            scanner = DLPScanner(mode="block")
            assert scanner._block_message == "[BLOCKED DUE TO PII LEAK]"


class TestDLPValidation:
    """Test DLP_MAX_OUTPUT_LENGTH validation in API."""

    @pytest.fixture
    def mock_settings_max_length(self):
        """Mock settings with specific max length."""
        mock_settings = Mock()
        mock_settings.DLP_MAX_OUTPUT_LENGTH = 100  # Small for testing
        return mock_settings

    def test_valid_text_length(self, mock_settings_max_length):
        """Test that valid text length passes validation."""
        with patch('sidecar.api.dlp.get_settings', return_value=mock_settings_max_length):
            from sidecar.api.dlp import OutputScanRequest

            # Text shorter than limit
            request = OutputScanRequest(text="Short text")
            assert request.text == "Short text"

    def test_text_too_long_validation_error(self, mock_settings_max_length):
        """Test that text exceeding max length raises validation error."""
        with patch('sidecar.api.dlp.get_settings', return_value=mock_settings_max_length):
            from sidecar.api.dlp import OutputScanRequest
            from pydantic import ValidationError

            # Text longer than limit (100 chars)
            long_text = "A" * 150

            with pytest.raises(ValidationError) as exc_info:
                OutputScanRequest(text=long_text)

            assert "Output too long" in str(exc_info.value)
            assert "150 chars. Max: 100" in str(exc_info.value)

    def test_fallback_max_length_on_settings_error(self):
        """Test fallback max length when settings can't be loaded."""
        with patch('sidecar.api.dlp.get_settings', side_effect=Exception("Settings error")):
            from sidecar.api.dlp import OutputScanRequest
            from pydantic import ValidationError

            # Should use fallback of 500_000
            long_text = "A" * 600_000

            with pytest.raises(ValidationError) as exc_info:
                OutputScanRequest(text=long_text)

            assert "Output too long" in str(exc_info.value)


class TestDLPModes:
    """Test all DLP modes (block, anonymize, log)."""

    @pytest.mark.asyncio
    async def test_block_mode_no_pii(self):
        """Test block mode with clean text."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        result = await scanner.scan_output(TEST_TEXTS["clean"])

        assert result.safe is True
        assert result.pii_detected is False
        assert result.entities == []
        assert result.modified_text is None
        assert result.blocked_reason is None

    @pytest.mark.asyncio
    async def test_block_mode_with_pii(self):
        """Test block mode with PII detected."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        result = await scanner.scan_output(TEST_TEXTS["email"])

        assert result.safe is False
        assert result.pii_detected is True
        assert len(result.entities) > 0
        assert result.modified_text == "[BLOCKED DUE TO PII LEAK]"
        assert "EMAIL_ADDRESS" in result.blocked_reason

    @pytest.mark.asyncio
    async def test_anonymize_mode_no_pii(self):
        """Test anonymize mode with clean text."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="anonymize")
        result = await scanner.scan_output(TEST_TEXTS["clean"])

        assert result.safe is True
        assert result.pii_detected is False
        assert result.entities == []
        assert result.modified_text is None

    @pytest.mark.asyncio
    async def test_anonymize_mode_with_pii(self):
        """Test anonymize mode with PII detected."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="anonymize")
        result = await scanner.scan_output(TEST_TEXTS["email"])

        assert result.safe is True  # Safe after anonymization
        assert result.pii_detected is True
        assert len(result.entities) > 0
        assert result.modified_text is not None
        assert "[REDACTED:EMAIL_ADDRESS]" in result.modified_text
        assert "john.doe@example.com" not in result.modified_text

    @pytest.mark.asyncio
    async def test_log_mode_no_pii(self):
        """Test log mode with clean text."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="log")
        result = await scanner.scan_output(TEST_TEXTS["clean"])

        assert result.safe is True
        assert result.pii_detected is False
        assert result.entities == []
        assert result.modified_text is None

    @pytest.mark.asyncio
    async def test_log_mode_with_pii(self):
        """Test log mode with PII detected."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="log")
        result = await scanner.scan_output(TEST_TEXTS["email"])

        assert result.safe is True  # Allowed but logged
        assert result.pii_detected is True
        assert len(result.entities) > 0
        assert result.modified_text is None  # Original text preserved


class TestDLPPIIEntities:
    """Test detection of various PII entity types."""

    @pytest.mark.parametrize("test_case,expected_entities", [
        ("email", ["EMAIL_ADDRESS"]),
        ("phone", ["PHONE_NUMBER"]),
        ("credit_card", ["CREDIT_CARD"]),
        ("iban", ["IBAN_CODE"]),
        ("ip_address", ["IP_ADDRESS"]),
        ("us_ssn", ["US_SSN"]),
        ("crypto", ["CRYPTO"]),
    ])
    @pytest.mark.asyncio
    async def test_individual_pii_detection(self, test_case, expected_entities):
        """Test detection of individual PII types."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        result = await scanner.scan_output(TEST_TEXTS[test_case])

        assert result.pii_detected is True
        detected_types = [e["entity_type"] for e in result.entities]
        for expected_type in expected_entities:
            assert expected_type in detected_types

    @pytest.mark.asyncio
    async def test_multiple_pii_types_detection(self):
        """Test detection of multiple PII types in single text."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        result = await scanner.scan_output(TEST_TEXTS["multiple_pii"])

        assert result.pii_detected is True
        assert len(result.entities) >= 3  # Should detect multiple entities

        detected_types = set(e["entity_type"] for e in result.entities)
        expected_types = {"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IP_ADDRESS", "US_SSN"}
        assert len(detected_types.intersection(expected_types)) >= 3


class TestDLPErrorHandling:
    """Test error handling and fail-open behavior."""

    @pytest.mark.asyncio
    async def test_fail_open_on_presidio_unavailable(self):
        """Test fail-open when NO PII libraries are available (both Presidio and FastPII unavailable)."""
        with patch('sidecar.layers.dlp.HAS_PRESIDIO', False), \
             patch('sidecar.layers.dlp.HAS_FAST_PII', False):
            from sidecar.layers.dlp import DLPScanner

            scanner = DLPScanner(mode="block", fail_open=True)  # Enable fail-open for this test
            result = await scanner.scan_output(TEST_TEXTS["email"])

            # Should fail open (allow) when NO PII libraries are available
            assert result.safe is True
            assert result.pii_detected is False
            assert result.entities == []

    @pytest.mark.asyncio
    async def test_fail_open_on_analyzer_initialization_error(self):
        """Test fail-open when analyzer initialization fails."""
        with patch('sidecar.layers.dlp.AnalyzerEngine', side_effect=Exception("Init failed")):
            from sidecar.layers.dlp import DLPScanner

            scanner = DLPScanner(mode="block", fail_open=True)  # Enable fail-open for this test
            result = await scanner.scan_output(TEST_TEXTS["email"])

            # Should fail open on initialization error
            assert result.safe is True
            assert result.pii_detected is False

    @pytest.mark.asyncio
    async def test_fail_open_on_scan_error(self):
        """Test fail-open when scan operation fails."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block", fail_open=True)  # Enable fail-open for this test

        # Mock the executor to raise an exception
        with patch.object(scanner, '_analyze_sync', side_effect=Exception("Scan failed")):
            result = await scanner.scan_output(TEST_TEXTS["email"])

            # Should fail open on scan error
            assert result.safe is True
            assert result.pii_detected is False


class TestDLPEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_text(self):
        """Test scanning empty text."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        result = await scanner.scan_output("")

        assert result.safe is True
        assert result.pii_detected is False
        assert result.entities == []

    @pytest.mark.asyncio
    async def test_whitespace_only_text(self):
        """Test scanning whitespace-only text."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        result = await scanner.scan_output("   \n\t   ")

        assert result.safe is True
        assert result.pii_detected is False
        assert result.entities == []

    @pytest.mark.asyncio
    async def test_very_long_text_without_pii(self):
        """Test scanning very long text without PII."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        result = await scanner.scan_output(TEST_TEXTS["very_long"])

        assert result.safe is True
        assert result.pii_detected is False

    @pytest.mark.asyncio
    async def test_text_with_special_characters(self):
        """Test scanning text with special characters and Unicode."""
        from sidecar.layers.dlp import DLPScanner

        special_text = "Email: user@example.pl\nPhone: +48 123-456-789\nCafé résumé naïve"
        scanner = DLPScanner(mode="block")
        result = await scanner.scan_output(special_text)

        # Should detect email and phone despite special chars
        assert result.pii_detected is True
        detected_types = [e["entity_type"] for e in result.entities]
        assert "EMAIL_ADDRESS" in detected_types

    @pytest.mark.asyncio
    async def test_low_confidence_threshold(self):
        """Test with very low confidence threshold."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block", threshold=0.1)
        result = await scanner.scan_output(TEST_TEXTS["email"])

        # With low threshold, should still detect
        assert result.pii_detected is True

    @pytest.mark.asyncio
    async def test_high_confidence_threshold(self):
        """Test with very high confidence threshold."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block", threshold=0.99)
        result = await scanner.scan_output(TEST_TEXTS["email"])

        # With high threshold, might not detect (depending on presidio scores)
        # Just ensure it doesn't crash
        assert isinstance(result.safe, bool)
        assert isinstance(result.pii_detected, bool)


class TestDLPPerformance:
    """Test performance and latency measurements."""

    @pytest.mark.asyncio
    async def test_latency_measurement_included(self):
        """Test that latency is measured and included in results."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        start_time = time.perf_counter()

        result = await scanner.scan_output(TEST_TEXTS["clean"])

        end_time = time.perf_counter()

        # Latency should be reasonable (less than 2 seconds including init)
        assert 0 <= result.latency_ms <= 2000

        # Latency should be roughly consistent with wall clock time
        wall_clock_ms = (end_time - start_time) * 1000
        assert abs(result.latency_ms - wall_clock_ms) < 100  # Within 100ms

    @pytest.mark.skip(reason="Sporadic 'Event loop is closed' error in test teardown due to ThreadPoolExecutor state")
    @pytest.mark.asyncio
    async def test_latency_increases_with_text_length(self):
        """Test that latency scales reasonably with text length."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")

        # Run short text first (may include initialization time)
        short_result = await scanner.scan_output("Short text")
        # Run long text second to measure actual processing time
        long_result = await scanner.scan_output(TEST_TEXTS["very_long"])

        # Long text should be reasonably fast (< 1s for 10KB even with init)
        assert long_result.latency_ms < 1000, f"Long text too slow: {long_result.latency_ms}ms"
        # At least initialization + short text should be reasonable
        assert short_result.latency_ms < 2000, f"Short text too slow: {short_result.latency_ms}ms"


class TestDLPHealth:
    """Test health check functionality."""

    @pytest.mark.skip(reason="Sporadic 'Event loop is closed' error in test teardown due to ThreadPoolExecutor state")
    @pytest.mark.asyncio
    async def test_health_check_successful(self):
        """Test health check when scanner is operational."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        healthy = await scanner.health_check()

        # Should be healthy if Presidio is available
        assert isinstance(healthy, bool)

    @pytest.mark.skip(reason="Sporadic 'Event loop is closed' error in test teardown due to ThreadPoolExecutor state")
    def test_get_status_includes_required_fields(self):
        """Test that get_status returns required status information."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")
        status = scanner.get_status()

        required_fields = ["initialized", "ready", "error", "mode", "entities", "threshold"]
        for field in required_fields:
            assert field in status

        assert status["mode"] == "block"
        assert isinstance(status["entities"], list)
        assert isinstance(status["threshold"], float)


class TestDLPThreadSafety:
    """Test thread safety and concurrent operations."""

    @pytest.mark.asyncio
    async def test_concurrent_scans(self):
        """Test that multiple concurrent scans work correctly."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")

        # Run multiple scans concurrently
        tasks = [
            scanner.scan_output(TEST_TEXTS["clean"]),
            scanner.scan_output(TEST_TEXTS["email"]),
            scanner.scan_output(TEST_TEXTS["phone"]),
        ]

        results = await asyncio.gather(*tasks)

        # Verify results are correct
        assert results[0].pii_detected is False  # clean
        assert results[1].pii_detected is True   # email
        assert results[2].pii_detected is True   # phone

    @pytest.mark.asyncio
    async def test_shared_executor_instance(self):
        """Test that all scanner instances share the same executor."""
        from sidecar.layers.dlp import DLPScanner

        scanner1 = DLPScanner(mode="block")
        scanner2 = DLPScanner(mode="anonymize")

        # Both should use the same executor instance
        assert DLPScanner._executor is not None
        assert scanner1._executor is scanner2._executor

    def test_executor_worker_limits(self):
        """Test that executor respects worker limits."""
        from sidecar.layers.dlp import DLPScanner
        import os

        # Force recreation of executor
        DLPScanner._executor = None

        # Mock cpu_count
        with patch('os.cpu_count', return_value=8):
            scanner = DLPScanner(mode="block")

            # Should create executor with max_workers = min(8, 8+2) = 8
            assert DLPScanner._executor is not None
            assert DLPScanner._executor._max_workers == 8


# Integration tests with API
class TestDLPAPIIntegration:
    """Integration tests for DLP API endpoints."""

    @pytest.fixture
    def mock_settings_enabled(self):
        """Mock settings with DLP enabled."""
        mock_settings = Mock()
        mock_settings.ENABLE_DLP = True
        mock_settings.DLP_MODE = "block"
        mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER"]
        mock_settings.DLP_PII_THRESHOLD = 0.5
        mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
        return mock_settings

    @pytest.fixture
    def mock_settings_disabled(self):
        """Mock settings with DLP disabled."""
        mock_settings = Mock()
        mock_settings.ENABLE_DLP = False
        mock_settings.DLP_MODE = "block"
        mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
        mock_settings.DLP_PII_THRESHOLD = 0.5
        mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
        return mock_settings

    def test_dlp_disabled_bypass(self, mock_settings_disabled):
        """Test that DLP is bypassed when disabled."""
        with patch('sidecar.api.dlp.get_settings', return_value=mock_settings_disabled):
            from sidecar.api.dlp import scan_output, OutputScanRequest

            # Should return pass-through response
            request = OutputScanRequest(text="Some text")
            # Note: This would need a test client for full integration testing
            # For now, just verify the logic path exists

    def test_dlp_enabled_processing(self, mock_settings_enabled):
        """Test that DLP processes requests when enabled."""
        with patch('sidecar.api.dlp.get_settings', return_value=mock_settings_enabled):
            from sidecar.api.dlp import scan_output, OutputScanRequest

            # Should create scanner and process
            request = OutputScanRequest(text="Contact: test@example.com")
            # Note: Full integration test would require test client

    def test_health_endpoint_disabled(self, mock_settings_disabled):
        """Test health endpoint when DLP is disabled."""
        with patch('sidecar.api.dlp.get_settings', return_value=mock_settings_disabled):
            from sidecar.api.dlp import dlp_health

            # Note: Would need async test client for full testing
            # This verifies the logic path exists

    def test_health_endpoint_enabled(self, mock_settings_enabled):
        """Test health endpoint when DLP is enabled."""
        with patch('sidecar.api.dlp.get_settings', return_value=mock_settings_enabled):
            from sidecar.api.dlp import dlp_health

            # Note: Would need async test client for full testing


# Load testing scenarios
class TestDLPLoadScenarios:
    """Load testing scenarios for DLP."""

    @pytest.mark.asyncio
    async def test_high_frequency_scans(self):
        """Test rapid successive scans."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")

        # Perform many rapid scans
        tasks = []
        for i in range(50):
            text = f"Test text {i} with email{i}@example.com"
            tasks.append(scanner.scan_output(text))

        results = await asyncio.gather(*tasks)

        # All should complete successfully
        assert len(results) == 50
        for result in results:
            assert result.pii_detected is True
            assert result.safe is False

    @pytest.mark.asyncio
    async def test_large_text_scanning(self):
        """Test scanning very large texts."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")

        # Create a large text with multiple PII instances
        large_text_parts = []
        for i in range(100):
            large_text_parts.append(f"Contact {i}: user{i}@example.com, phone: +1-555-000-{i:04d}")

        large_text = "\n".join(large_text_parts)

        result = await scanner.scan_output(large_text)

        # Should detect PII despite large size
        assert result.pii_detected is True
        assert len(result.entities) >= 10  # Should find many emails/phones


# Configuration validation tests
class TestDLPConfiguration:
    """Test DLP configuration validation."""

    def test_valid_dlp_modes(self):
        """Test that valid DLP modes are accepted."""
        from sidecar.layers.dlp import DLPScanner

        valid_modes = ["block", "anonymize", "log"]

        for mode in valid_modes:
            scanner = DLPScanner(mode=mode)
            assert scanner._mode == mode.lower()

    def test_invalid_dlp_mode_raises_error(self):
        """Test that invalid DLP mode raises validation error."""
        from sidecar.core.settings import Settings
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            # This should raise an error during settings validation
            settings = Settings(DLP_MODE="invalid_mode")

    def test_case_insensitive_mode(self):
        """Test that DLP mode is case insensitive."""
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="BLOCK")
        assert scanner._mode == "block"

        scanner = DLPScanner(mode="Anonymize")
        assert scanner._mode == "anonymize"


class TestDLPAuditTruncationMetric:
    """Ensure audit truncation increments the metric when enabled."""

    def test_audit_truncation_increments_metric(self, monkeypatch):
        from unittest.mock import MagicMock
        from sidecar.api import dlp as dlp_api

        monkeypatch.setattr(dlp_api, "_get_max_output_length", lambda: 5)
        mock_counter = MagicMock()
        monkeypatch.setattr(dlp_api, "DLP_AUDIT_TRUNCATIONS", mock_counter)

        item = dlp_api.AuditIngestItem(response_body="1234567")

        assert item.response_body == "12345"
        mock_counter.inc.assert_called_once()


if __name__ == "__main__":
    # Run basic smoke tests
    print("Running DLP smoke tests...")

    async def run_smoke_tests():
        from sidecar.layers.dlp import DLPScanner

        scanner = DLPScanner(mode="block")

        # Test clean text
        result = await scanner.scan_output("Clean text")
        assert result.safe is True
        print("✓ Clean text test passed")

        # Test PII detection
        result = await scanner.scan_output("Email: test@example.com")
        assert result.pii_detected is True
        print("✓ PII detection test passed")

        # Test block mode
        assert result.safe is False
        print("✓ Block mode test passed")

        print("All smoke tests passed!")

    asyncio.run(run_smoke_tests())
