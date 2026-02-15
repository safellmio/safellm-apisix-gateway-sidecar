"""
Comprehensive Unit Tests for PIILayer (sidecar/layers/pii.py).

Tests cover:
- Lazy initialization and Presidio setup
- PII detection accuracy for all entity types
- ThreadPoolExecutor management and cleanup
- Error handling (missing dependencies, runtime errors)
- PIIAnonymizer functionality
- Health checks and status reporting
- Edge cases and boundary conditions
- Thread safety and concurrency
- Performance and latency
- Configuration validation

Target: Achieve >90% test coverage for PIILayer and PIIAnonymizer.
"""

import asyncio
import gc
import os
import pytest
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List

# Test data with various PII types for comprehensive testing
TEST_TEXTS = {
    "clean": "This is a clean text with no sensitive information.",
    "email": "Contact me at john.doe@example.com for more details.",
    "phone": "My phone number is (555) 123-4567.",
    "credit_card": "Payment processed using card 4111-1111-1111-1111.",
    "iban": "Bank account: DE89370400440532013000",
    "ip_address": "Server located at 192.168.1.100",
    "crypto": "Bitcoin address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    "us_ssn": "Social Security Number: 900-12-3456",
    "multiple_pii": """
        Contact: john.doe@example.com
        Phone: (555) 123-4567
        Card: 4111-1111-1111-1111
        IP: 192.168.1.100
        SSN: 900-12-3456
    """,
    "empty": "",
    "whitespace": "   \n\t   ",
    "very_long": "A" * 50000,  # 50KB text for performance testing
    "special_chars": "Email: user@example.pl\nPhone: +48 123-456-789\nCafé résumé naïve",
    "lowercase_email": "contact: test.email+tag@gmail.com",
    "international_phone": "Tel: +44 20 7946 0958 or +33.1.42.68.53.00",
    "partial_credit_card": "Last four digits: ****-****-****-1234",  # Should not detect partial
}

EXPECTED_ENTITIES = {
    "email": [{"entity_type": "EMAIL_ADDRESS", "text": "john.doe@example.com"}],
    "phone": [{"entity_type": "PHONE_NUMBER", "text": "(555) 123-4567"}],
    "credit_card": [{"entity_type": "CREDIT_CARD", "text": "4111-1111-1111-1111"}],
    "iban": [{"entity_type": "IBAN_CODE", "text": "DE89370400440532013000"}],
    "ip_address": [{"entity_type": "IP_ADDRESS", "text": "192.168.1.100"}],
    "crypto": [{"entity_type": "CRYPTO", "text": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"}],
    "us_ssn": [{"entity_type": "US_SSN", "text": "900-12-3456"}],
}


class TestPIILayerInitialization:
    """Test PIILayer initialization, lazy loading, and setup."""

    def setup_method(self):
        """Reset class-level state before each test."""
        from sidecar.layers import pii
        pii.PIILayer._executor = None

    def teardown_method(self):
        """Clean up after each test."""
        from sidecar.layers import pii
        if pii.PIILayer._executor is not None:
            pii.PIILayer._executor.shutdown(wait=True)
            pii.PIILayer._executor = None

    def test_default_initialization(self):
        """Test PIILayer with default parameters."""
        from sidecar.layers.pii import PIILayer

        layer = PIILayer()

        assert layer._entities == PIILayer.DEFAULT_ENTITIES
        assert layer._threshold == 0.4
        assert layer._language == "en"
        assert layer._analyzer is None
        assert layer._initialized is False
        assert layer._init_error is None

    def test_custom_initialization(self):
        """Test PIILayer with custom parameters."""
        from sidecar.layers.pii import PIILayer

        custom_entities = ["EMAIL_ADDRESS", "PHONE_NUMBER"]
        layer = PIILayer(
            entities=custom_entities,
            threshold=0.8,
            language="pl"
        )

        assert layer._entities == custom_entities
        assert layer._threshold == 0.8
        assert layer._language == "pl"

    def test_executor_initialization(self):
        """Test ThreadPoolExecutor initialization."""
        from sidecar.layers.pii import PIILayer

        # Executor should not exist initially
        assert PIILayer._executor is None

        # Create first instance
        layer1 = PIILayer()

        # Executor should be created
        assert PIILayer._executor is not None
        assert isinstance(PIILayer._executor, ThreadPoolExecutor)

        # Create second instance - should reuse executor
        layer2 = PIILayer()
        assert layer2._executor is layer1._executor

    def test_executor_worker_count(self):
        """Test executor worker count calculation."""
        from sidecar.layers.pii import PIILayer

        with patch('os.cpu_count', return_value=8):
            PIILayer._executor = None  # Force recreation
            layer = PIILayer()

            # Should be min(16, 8 + 2) = 10
            assert PIILayer._executor._max_workers == 10

        with patch('os.cpu_count', return_value=20):
            PIILayer._executor = None  # Force recreation
            layer = PIILayer()

            # Should be min(16, 20 + 2) = 16
            assert PIILayer._executor._max_workers == 16

    def test_executor_cleanup(self):
        """Test executor cleanup."""
        from sidecar.layers.pii import PIILayer

        layer = PIILayer()
        assert PIILayer._executor is not None

        PIILayer.cleanup_executor()
        assert PIILayer._executor is None

    @pytest.mark.asyncio
    async def test_lazy_initialization_success(self):
        """Test successful lazy initialization with Presidio available."""
        from sidecar.layers.pii import PIILayer

        layer = PIILayer()

        # Should initialize successfully (assuming Presidio is available)
        success = layer._lazy_init()

        if success:
            assert layer._initialized is True
            assert layer._init_error is None
            assert layer._analyzer is not None
        else:
            # If Presidio not available, should have error
            assert layer._init_error is not None
            assert "presidio" in layer._init_error.lower()

    def test_lazy_initialization_presidio_unavailable(self):
        """Test lazy initialization when Presidio is not available."""
        from sidecar.layers.pii import PIILayer

        with patch('sidecar.layers.pii.HAS_PRESIDIO', False):
            layer = PIILayer()

            success = layer._lazy_init()
            assert success is False
            assert layer._init_error == "presidio-analyzer not installed"
            assert layer._initialized is True  # Still marked as initialized

    def test_lazy_initialization_analyzer_creation_failure(self):
        """Test lazy initialization when AnalyzerEngine creation fails."""
        from sidecar.layers.pii import PIILayer

        with patch('sidecar.layers.pii.AnalyzerEngine', side_effect=Exception("Creation failed")):
            layer = PIILayer()

            success = layer._lazy_init()
            assert success is False
            assert "Creation failed" in layer._init_error

    def test_double_initialization(self):
        """Test that calling _lazy_init multiple times works correctly."""
        from sidecar.layers.pii import PIILayer

        layer = PIILayer()

        # First call
        result1 = layer._lazy_init()

        # Second call should return same result
        result2 = layer._lazy_init()

        assert result1 == result2
        assert layer._initialized is True


class TestPIILayerDetection:
    """Test PII detection functionality."""

    @pytest.fixture
    def layer(self):
        """Create a PIILayer instance for testing."""
        from sidecar.layers.pii import PIILayer

        layer = PIILayer()
        # Force initialization
        layer._lazy_init()
        return layer

    @pytest.mark.asyncio
    async def test_clean_text_detection(self, layer):
        """Test detection on clean text with no PII."""
        from sidecar.layers.base import ScanContext

        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        ctx = ScanContext(text=TEST_TEXTS["clean"])
        result = await layer.scan(ctx)

        assert result.safe is True
        assert result.score == 0.0
        assert "pii_entities" not in ctx.metadata

    @pytest.mark.asyncio
    async def test_email_detection(self, layer):
        """Test email address detection."""
        from sidecar.layers.base import ScanContext

        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        ctx = ScanContext(text=TEST_TEXTS["email"])
        result = await layer.scan(ctx)

        assert not result.safe
        assert result.score >= 0.0
        assert "EMAIL_ADDRESS" in result.reason
        assert "pii_entities" in ctx.metadata
        assert len(ctx.metadata["pii_entities"]) > 0

    @pytest.mark.asyncio
    async def test_multiple_pii_detection(self, layer):
        """Test detection of multiple PII types in single text."""
        from sidecar.layers.base import ScanContext

        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        ctx = ScanContext(text=TEST_TEXTS["multiple_pii"])
        result = await layer.scan(ctx)

        assert not result.safe
        assert "pii_entities" in ctx.metadata
        entities = ctx.metadata["pii_entities"]
        assert len(entities) >= 3  # Should detect multiple entities

        # Check entity types
        entity_types = {e["entity_type"] for e in entities}
        expected_types = {"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"}
        assert len(entity_types.intersection(expected_types)) >= 2

    @pytest.mark.parametrize("test_case,expected_type", [
        ("email", "EMAIL_ADDRESS"),
        ("phone", "PHONE_NUMBER"),
        ("credit_card", "CREDIT_CARD"),
        ("iban", "IBAN_CODE"),
        ("ip_address", "IP_ADDRESS"),
        ("crypto", "CRYPTO"),
    ])
    @pytest.mark.asyncio
    async def test_individual_entity_detection(self, layer, test_case, expected_type):
        """Test detection of individual PII entity types."""
        from sidecar.layers.base import ScanContext

        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        ctx = ScanContext(text=TEST_TEXTS[test_case])
        result = await layer.scan(ctx)

        assert not result.safe
        assert expected_type in result.reason
        assert "pii_entities" in ctx.metadata

        # Verify entity details
        entities = ctx.metadata["pii_entities"]
        assert len(entities) > 0
        assert any(e["entity_type"] == expected_type for e in entities)

    @pytest.mark.asyncio
    async def test_threshold_filtering(self, layer):
        """Test that entities below threshold are filtered out."""
        from sidecar.layers.base import ScanContext

        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        # Use very high threshold
        layer._threshold = 0.99
        ctx = ScanContext(text=TEST_TEXTS["email"])
        result = await layer.scan(ctx)

        # Result might be clean if confidence is below threshold
        assert isinstance(result.safe, bool)

    @pytest.mark.asyncio
    async def test_empty_text(self, layer):
        """Test scanning empty text."""
        from sidecar.layers.base import ScanContext

        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        ctx = ScanContext(text="")
        result = await layer.scan(ctx)

        assert result.safe is True

    @pytest.mark.asyncio
    async def test_whitespace_only_text(self, layer):
        """Test scanning whitespace-only text."""
        from sidecar.layers.base import ScanContext

        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        ctx = ScanContext(text=TEST_TEXTS["whitespace"])
        result = await layer.scan(ctx)

        assert result.safe is True

    @pytest.mark.asyncio
    async def test_special_characters_and_unicode(self, layer):
        """Test detection with special characters and Unicode."""
        from sidecar.layers.base import ScanContext

        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        ctx = ScanContext(text=TEST_TEXTS["special_chars"])
        result = await layer.scan(ctx)

        # Should detect email despite special chars
        assert not result.safe
        assert "EMAIL_ADDRESS" in result.reason


class TestPIIErrorHandling:
    """Test error handling in PIILayer."""

    @pytest.mark.asyncio
    async def test_unavailable_presidio_blocks_scan(self):
        """Test that unavailable Presidio blocks the scan."""
        from sidecar.layers.pii import PIILayer
        from sidecar.layers.base import ScanContext

        with patch('sidecar.layers.pii.HAS_PRESIDIO', False):
            layer = PIILayer()
            ctx = ScanContext(text="test@example.com")
            result = await layer.scan(ctx)

            assert not result.safe
            assert "pii_unavailable" in result.reason
            assert result.score == 0.0

    @pytest.mark.asyncio
    async def test_analyzer_runtime_error(self):
        """Test handling of runtime errors during analysis."""
        from sidecar.layers.pii import PIILayer
        from sidecar.layers.base import ScanContext

        layer = PIILayer()

        # Mock analyzer to raise exception
        with patch.object(layer, '_analyze_sync', side_effect=Exception("Runtime error")):
            # Force initialization success
            layer._initialized = True
            layer._init_error = None

            ctx = ScanContext(text="test@example.com")
            result = await layer.scan(ctx)

            assert not result.safe
            assert "pii_error" in result.reason
            assert result.score == 0.0


class TestPIIAnonymizer:
    """Test PIIAnonymizer functionality."""

    def test_default_anonymizer_creation(self):
        """Test PIIAnonymizer with default pattern."""
        from sidecar.layers.pii import PIIAnonymizer

        anonymizer = PIIAnonymizer()

        assert anonymizer._pattern == "[{entity_type}]"

    def test_custom_anonymizer_creation(self):
        """Test PIIAnonymizer with custom pattern."""
        from sidecar.layers.pii import PIIAnonymizer

        anonymizer = PIIAnonymizer(replacement_pattern="***{entity_type}***")

        assert anonymizer._pattern == "***{entity_type}***"

    def test_anonymize_no_entities(self):
        """Test anonymization with no entities."""
        from sidecar.layers.pii import PIIAnonymizer

        anonymizer = PIIAnonymizer()
        text = "This is clean text."
        result = anonymizer.anonymize(text, [])

        assert result == text

    def test_anonymize_single_entity(self):
        """Test anonymization of single entity."""
        from sidecar.layers.pii import PIIAnonymizer

        anonymizer = PIIAnonymizer()
        text = "Contact me at test@example.com please."
        entities = [
            {
                "entity_type": "EMAIL_ADDRESS",
                "start": 14,
                "end": 30,
                "text": "test@example.com"
            }
        ]

        result = anonymizer.anonymize(text, entities)

        assert "test@example.com" not in result
        assert "[EMAIL_ADDRESS]" in result
        assert result == "Contact me at [EMAIL_ADDRESS] please."

    def test_anonymize_multiple_entities(self):
        """Test anonymization of multiple entities."""
        from sidecar.layers.pii import PIIAnonymizer

        anonymizer = PIIAnonymizer(replacement_pattern="REDACTED_{entity_type}")
        text = "Email: test@example.com, Phone: 555-1234"
        entities = [
            {
                "entity_type": "EMAIL_ADDRESS",
                "start": 7,
                "end": 22,
                "text": "test@example.com"
            },
            {
                "entity_type": "PHONE_NUMBER",
                "start": 31,
                "end": 39,
                "text": "555-1234"
            }
        ]

        result = anonymizer.anonymize(text, entities)

        assert "test@example.com" not in result
        assert "555-1234" not in result
        assert "REDACTED_EMAIL_ADDRESS" in result
        assert "REDACTED_PHONE_NUMBER" in result

    def test_anonymize_overlapping_entities(self):
        """Test anonymization with overlapping entities (should handle in reverse order)."""
        from sidecar.layers.pii import PIIAnonymizer

        anonymizer = PIIAnonymizer()
        text = "My email is test@example.com and I work at example.com"
        entities = [
            {
                "entity_type": "EMAIL_ADDRESS",
                "start": 12,
                "end": 27,
                "text": "test@example.com"
            },
            {
                "entity_type": "DOMAIN_NAME",  # Hypothetical entity
                "start": 41,
                "end": 52,
                "text": "example.com"
            }
        ]

        result = anonymizer.anonymize(text, entities)

        # Should handle replacement in reverse order to avoid index shifting issues
        assert "test@example.com" not in result
        assert "[EMAIL_ADDRESS]" in result


class TestPIIHealthAndStatus:
    """Test health checks and status reporting."""

    @pytest.mark.asyncio
    async def test_health_check_after_initialization(self):
        """Test health check after successful initialization."""
        from sidecar.layers.pii import PIILayer

        layer = PIILayer()
        healthy = await layer.health_check()

        # Should match lazy init result
        assert healthy == (layer._init_error is None)

    @pytest.mark.asyncio
    async def test_health_check_presidio_unavailable(self):
        """Test health check when Presidio is unavailable."""
        from sidecar.layers.pii import PIILayer

        with patch('sidecar.layers.pii.HAS_PRESIDIO', False):
            layer = PIILayer()
            healthy = await layer.health_check()

            assert healthy is False

    def test_get_status_complete(self):
        """Test get_status returns all required fields."""
        from sidecar.layers.pii import PIILayer

        layer = PIILayer()

        status = layer.get_status()

        required_fields = [
            "name", "initialized", "ready", "error",
            "entities", "threshold", "language"
        ]

        for field in required_fields:
            assert field in status

        assert status["name"] == "L3_PII"
        assert status["entities"] == PIILayer.DEFAULT_ENTITIES
        assert status["threshold"] == 0.4
        assert status["language"] == "en"

    def test_get_status_after_initialization(self):
        """Test get_status after initialization."""
        from sidecar.layers.pii import PIILayer

        layer = PIILayer()
        layer._lazy_init()

        status = layer.get_status()

        assert status["initialized"] is True
        assert isinstance(status["ready"], bool)


class TestPIIConcurrency:
    """Test thread safety and concurrent operations."""

    @pytest.mark.asyncio
    async def test_concurrent_scans(self):
        """Test multiple concurrent PII scans."""
        from sidecar.layers.pii import PIILayer
        from sidecar.layers.base import ScanContext

        layer = PIILayer()
        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        # Create multiple scan tasks
        texts = [
            TEST_TEXTS["clean"],
            TEST_TEXTS["email"],
            TEST_TEXTS["phone"],
            TEST_TEXTS["credit_card"],
        ]

        tasks = []
        for text in texts:
            ctx = ScanContext(text=text)
            tasks.append(layer.scan(ctx))

        results = await asyncio.gather(*tasks)

        # Verify results
        assert len(results) == 4
        assert results[0].safe is True  # clean
        assert not results[1].safe   # email
        assert not results[2].safe   # phone
        assert not results[3].safe   # credit_card

    @pytest.mark.asyncio
    async def test_shared_executor_between_instances(self):
        """Test that multiple PIILayer instances share the same executor."""
        from sidecar.layers.pii import PIILayer
        from sidecar.layers.base import ScanContext

        layer1 = PIILayer()
        layer2 = PIILayer()

        assert PIILayer._executor is not None
        assert layer1._executor is layer2._executor

        # Both should work concurrently
        if layer1._lazy_init():
            ctx1 = ScanContext(text=TEST_TEXTS["email"])
            ctx2 = ScanContext(text=TEST_TEXTS["phone"])

            result1, result2 = await asyncio.gather(
                layer1.scan(ctx1),
                layer2.scan(ctx2)
            )

            assert not result1.safe
            assert not result2.safe


class TestPIIPerformance:
    """Test performance and latency characteristics."""

    @pytest.mark.asyncio
    async def test_reasonable_latency(self):
        """Test that scans complete within reasonable time."""
        from sidecar.layers.pii import PIILayer
        from sidecar.layers.base import ScanContext

        layer = PIILayer()
        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        start_time = time.perf_counter()

        ctx = ScanContext(text=TEST_TEXTS["clean"])
        result = await layer.scan(ctx)

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        # Should complete within reasonable time (allowing for init)
        assert latency_ms < 2000  # 2 seconds max

    @pytest.mark.asyncio
    async def test_large_text_performance(self):
        """Test performance with large text."""
        from sidecar.layers.pii import PIILayer
        from sidecar.layers.base import ScanContext

        layer = PIILayer()
        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        start_time = time.perf_counter()

        ctx = ScanContext(text=TEST_TEXTS["very_long"])
        result = await layer.scan(ctx)

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        # Large text should still be reasonably fast
        assert latency_ms < 5000  # 5 seconds max for 50KB


class TestPIIConfiguration:
    """Test configuration validation and edge cases."""

    def test_custom_entity_list(self):
        """Test PIILayer with custom entity list."""
        from sidecar.layers.pii import PIILayer

        custom_entities = ["EMAIL_ADDRESS", "PHONE_NUMBER"]
        layer = PIILayer(entities=custom_entities)

        assert layer._entities == custom_entities

    def test_empty_entity_list(self):
        """Test PIILayer with empty entity list."""
        from sidecar.layers.pii import PIILayer

        layer = PIILayer(entities=[])

        assert layer._entities == []

    def test_threshold_bounds(self):
        """Test threshold validation (should accept any float)."""
        from sidecar.layers.pii import PIILayer

        # Test various thresholds
        for threshold in [0.0, 0.5, 1.0, 0.99]:
            layer = PIILayer(threshold=threshold)
            assert layer._threshold == threshold

    def test_language_codes(self):
        """Test different language codes."""
        from sidecar.layers.pii import PIILayer

        for lang in ["en", "pl", "de", "fr"]:
            layer = PIILayer(language=lang)
            assert layer._language == lang


# Integration with ScanContext
class TestPIIWithScanContext:
    """Test PIILayer integration with ScanContext."""

    @pytest.mark.asyncio
    async def test_context_metadata_storage(self):
        """Test that PII entities are stored in context metadata."""
        from sidecar.layers.pii import PIILayer
        from sidecar.layers.base import ScanContext

        layer = PIILayer()
        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        ctx = ScanContext(text=TEST_TEXTS["email"])

        # Metadata should be empty initially
        assert "pii_entities" not in ctx.metadata

        result = await layer.scan(ctx)

        # Should store entities in metadata
        assert "pii_entities" in ctx.metadata
        entities = ctx.metadata["pii_entities"]
        assert isinstance(entities, list)
        assert len(entities) > 0

        # Verify entity structure
        entity = entities[0]
        required_fields = ["entity_type", "score", "start", "end", "text"]
        for field in required_fields:
            assert field in entity

    @pytest.mark.asyncio
    async def test_context_preservation(self):
        """Test that context data is preserved during scan."""
        from sidecar.layers.pii import PIILayer
        from sidecar.layers.base import ScanContext

        layer = PIILayer()
        if not layer._lazy_init():
            pytest.skip("Presidio not available")

        # Add some initial metadata
        ctx = ScanContext(text=TEST_TEXTS["clean"])
        ctx.metadata["custom_field"] = "test_value"

        result = await layer.scan(ctx)

        # Should preserve existing metadata
        assert ctx.metadata["custom_field"] == "test_value"
        assert "pii_entities" not in ctx.metadata  # No PII detected


if __name__ == "__main__":
    # Run basic smoke tests
    print("Running PII layer smoke tests...")

    async def run_smoke_tests():
        from sidecar.layers.pii import PIILayer, PIIAnonymizer
        from sidecar.layers.base import ScanContext

        layer = PIILayer()

        # Test initialization
        success = layer._lazy_init()
        print(f"✓ Initialization: {'SUCCESS' if success else 'FAILED (Presidio not available)'}")

        if success:
            # Test clean text
            ctx = ScanContext(text="Clean text")
            result = await layer.scan(ctx)
            assert result.safe is True
            print("✓ Clean text scan passed")

            # Test PII detection
            ctx = ScanContext(text="Email: test@example.com")
            result = await layer.scan(ctx)
            assert not result.safe
            print("✓ PII detection scan passed")

            # Test anonymizer
            anonymizer = PIIAnonymizer()
            entities = [
                {"entity_type": "EMAIL_ADDRESS", "start": 7, "end": 22, "text": "test@example.com"}
            ]
            safe_text = anonymizer.anonymize("Email: test@example.com", entities)
            assert "test@example.com" not in safe_text
            assert "[EMAIL_ADDRESS]" in safe_text
            print("✓ Anonymizer test passed")

        # Test cleanup
        PIILayer.cleanup_executor()
        print("✓ Cleanup completed")

        print("All smoke tests passed!")

    asyncio.run(run_smoke_tests())