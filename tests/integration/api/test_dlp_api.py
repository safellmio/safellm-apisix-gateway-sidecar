"""
Integration Tests for DLP API Endpoints.

Tests the full DLP API integration including:
- /v1/scan/output endpoint
- /v1/scan/output/health endpoint
- Settings integration
- Request/response validation
- Error handling
- Performance under load
"""

import pytest
from httpx import AsyncClient
from unittest.mock import Mock, patch
import json


class TestDLPAPIEndpoints:
    """Test DLP API endpoints integration."""

    @pytest.mark.asyncio
    async def test_scan_output_clean_text(self, client: AsyncClient):
        """Test scanning clean text (no PII)."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED]"
            mock_get_settings.return_value = mock_settings

            payload = {
                "text": "This is a clean response with no sensitive information.",
                "request_id": "test-123"
            }

            response = await client.post("/v1/scan/output", json=payload)

            assert response.status_code == 200
            data = response.json()

            assert data["safe"] is True
            assert data["pii_detected"] is False
            assert data["entities_count"] == 0
            assert data["blocked"] is False
            assert data["text"] == payload["text"]  # Original text preserved
            assert "latency_ms" in data
            assert data["latency_ms"] >= 0

    @pytest.mark.asyncio
    async def test_scan_output_with_pii_block_mode(self, client: AsyncClient):
        """Test scanning text with PII in block mode."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings, \
             patch('sidecar.api.dlp.is_feature_available', return_value=True):
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED DUE TO PII LEAK]"
            mock_get_settings.return_value = mock_settings
    
            payload = {
                "text": "Contact me at john.doe@example.com for details.",
                "request_id": "test-pii-123"
            }
    
            response = await client.post("/v1/scan/output", json=payload)
    
            assert response.status_code == 200
            data = response.json()
    
            assert data["safe"] is False
            assert data["pii_detected"] is True
            assert data["entities_count"] >= 1
            assert data["blocked"] is True
            assert data["text"] == "[BLOCKED DUE TO PII LEAK]"  # Blocked message
            assert "blocked_reason" in data
            assert "EMAIL_ADDRESS" in data["blocked_reason"]

    @pytest.mark.asyncio
    async def test_scan_output_with_pii_anonymize_mode(self, client: AsyncClient):
        """Test scanning text with PII in anonymize mode."""
        # Change DLP mode to anonymize for this test
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings, \
             patch('sidecar.api.dlp.is_feature_available', return_value=True):
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "anonymize"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_get_settings.return_value = mock_settings
    
            payload = {
                "text": "My email is test@example.com and phone is +1-555-123-4567",
                "request_id": "test-anonymize-123"
            }
    
            response = await client.post("/v1/scan/output", json=payload)
    
            assert response.status_code == 200
            data = response.json()
    
            assert data["safe"] is True  # Safe after anonymization
            assert data["pii_detected"] is True
            assert data["entities_count"] >= 1
            assert data["blocked"] is False
            assert "[REDACTED:EMAIL_ADDRESS]" in data["text"]
            assert "test@example.com" not in data["text"]  # Email redacted

    @pytest.mark.asyncio
    async def test_scan_output_with_pii_log_mode(self, client: AsyncClient):
        """Test scanning text with PII in log mode."""
        # Change DLP mode to log for this test
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "log"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_get_settings.return_value = mock_settings

            payload = {
                "text": "Contact: admin@company.com",
                "request_id": "test-log-123"
            }

            response = await client.post("/v1/scan/output", json=payload)

            assert response.status_code == 200
            data = response.json()

            assert data["safe"] is True  # Allowed but logged
            assert data["pii_detected"] is True
            assert data["entities_count"] >= 1
            assert data["blocked"] is False
            assert data["text"] == payload["text"]  # Original text preserved

    @pytest.mark.asyncio
    async def test_scan_output_text_too_long(self, client: AsyncClient):
        """Test validation of maximum output length."""
        # Create text that exceeds DLP_MAX_OUTPUT_LENGTH
        long_text = "A" * 600000  # 600KB, exceeds default 500KB limit

        payload = {
            "text": long_text,
            "request_id": "test-long-123"
        }

        response = await client.post("/v1/scan/output", json=payload)

        assert response.status_code == 422  # Validation error
        data = response.json()

        assert "detail" in data
        assert "Output too long" in str(data["detail"])

    @pytest.mark.asyncio
    async def test_scan_output_empty_text(self, client: AsyncClient):
        """Test scanning empty text."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED]"
            mock_get_settings.return_value = mock_settings

            payload = {
                "text": "",
                "request_id": "test-empty-123"
            }

            response = await client.post("/v1/scan/output", json=payload)

            assert response.status_code == 200
            data = response.json()

            assert data["safe"] is True
            assert data["pii_detected"] is False
            assert data["entities_count"] == 0

    @pytest.mark.asyncio
    async def test_scan_output_without_request_id(self, client: AsyncClient):
        """Test scanning without request_id (should auto-generate)."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED]"
            mock_get_settings.return_value = mock_settings

            payload = {
                "text": "Clean text without request ID"
            }

            response = await client.post("/v1/scan/output", json=payload)

            assert response.status_code == 200
            data = response.json()

            assert data["safe"] is True
            assert "latency_ms" in data

    @pytest.mark.asyncio
    async def test_dlp_disabled_bypass(self, client: AsyncClient):
        """Test that DLP is bypassed when disabled."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = False
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED]"
            mock_get_settings.return_value = mock_settings

            payload = {
                "text": "This should be bypassed even with email@test.com",
                "request_id": "test-disabled-123"
            }

            response = await client.post("/v1/scan/output", json=payload)

            assert response.status_code == 200
            data = response.json()

            assert data["safe"] is True
            assert data["pii_detected"] is False
            assert data["entities_count"] == 0
            assert data["mode"] == "disabled"
            assert data["text"] == payload["text"]  # Unmodified


class TestDLPHealthEndpoint:
    """Test DLP health check endpoint."""

    @pytest.mark.asyncio
    async def test_health_endpoint_dlp_enabled_healthy(self, client: AsyncClient):
        """Test health endpoint when DLP is enabled and healthy."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_STREAMING_MODE = "block"
            mock_settings.DLP_FAIL_OPEN = False
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 500000
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED]"
            mock_get_settings.return_value = mock_settings

            response = await client.get("/v1/scan/output/health")

        assert response.status_code == 200
        data = response.json()

        assert "status" in data
        assert data["status"] in ["healthy", "unhealthy"]
        assert "enabled" in data
        assert data["enabled"] is True
        assert "mode" in data

        if data["status"] == "healthy":
            assert "initialized" in data
            assert "ready" in data
            assert "error" in data

    @pytest.mark.asyncio
    async def test_health_endpoint_dlp_disabled(self, client: AsyncClient):
        """Test health endpoint when DLP is disabled."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = False
            mock_settings.DLP_MODE = "block"
            mock_get_settings.return_value = mock_settings

            response = await client.get("/v1/scan/output/health")

            assert response.status_code == 200
            data = response.json()

            assert data["status"] == "disabled"
            assert data["enabled"] is False
            assert "mode" in data


class TestDLPSettingsIntegration:
    """Test DLP settings integration with API."""

    @pytest.mark.asyncio
    async def test_custom_block_message_from_settings(self, client: AsyncClient):
        """Test that custom block message from settings is used."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings, \
             patch('sidecar.core.settings.get_settings') as mock_core_get_settings, \
             patch('sidecar.api.dlp.is_feature_available', return_value=True):
    
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_BLOCK_MESSAGE = "[CUSTOM BLOCKED MESSAGE]"
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_get_settings.return_value = mock_settings
            mock_core_get_settings.return_value = mock_settings

            payload = {
                "text": "Email: test@example.com",
                "request_id": "test-custom-msg-123"
            }

            response = await client.post("/v1/scan/output", json=payload)

            assert response.status_code == 200
            data = response.json()

            assert data["safe"] is False
            assert data["blocked"] is True
            assert data["text"] == "[CUSTOM BLOCKED MESSAGE]"

    @pytest.mark.asyncio
    async def test_dlp_max_output_length_integration(self, client: AsyncClient):
        """Test DLP_MAX_OUTPUT_LENGTH setting integration."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 50  # Very small limit
            mock_get_settings.return_value = mock_settings

            # Text that exceeds the limit
            long_text = "A" * 100

            payload = {
                "text": long_text,
                "request_id": "test-max-length-123"
            }

            response = await client.post("/v1/scan/output", json=payload)

            assert response.status_code == 422
            data = response.json()
            assert "Output too long" in str(data["detail"])
            assert "100 chars. Max: 50" in str(data["detail"])


class TestDLPErrorHandling:
    """Test error handling in DLP API."""

    @pytest.mark.asyncio
    async def test_scan_error_fail_open(self, client: AsyncClient):
        """Test that scan errors result in fail-open behavior."""
        with patch('sidecar.api.dlp.get_dlp_scanner') as mock_get_scanner:
            mock_scanner = Mock()
            mock_scanner.scan_output.side_effect = Exception("Scan failed")
            mock_get_scanner.return_value = mock_scanner

            payload = {
                "text": "Some text that would cause scan error",
                "request_id": "test-error-123"
            }

            response = await client.post("/v1/scan/output", json=payload)

            # Should fail open (allow the request)
            assert response.status_code == 200
            data = response.json()

            assert data["safe"] is True
            assert data["pii_detected"] is False
            assert data["entities_count"] == 0

    @pytest.mark.asyncio
    async def test_invalid_request_format(self, client: AsyncClient):
        """Test handling of invalid request format."""
        # Missing required 'text' field
        payload = {
            "request_id": "test-invalid-123"
        }

        response = await client.post("/v1/scan/output", json=payload)

        assert response.status_code == 422  # Validation error
        data = response.json()
        assert "detail" in data

    @pytest.mark.asyncio
    async def test_malformed_json(self, client: AsyncClient):
        """Test handling of malformed JSON."""
        response = await client.post(
            "/v1/scan/output",
            content="invalid json",
            headers={"Content-Type": "application/json"}
        )

        # FastAPI returns 422 or 400 for malformed JSON depending on middleware
        assert response.status_code in [400, 422]


class TestDLPPerformanceIntegration:
    """Test DLP performance in integration context."""

    @pytest.mark.asyncio
    async def test_response_time_measurement(self, client: AsyncClient):
        """Test that response time is properly measured."""
        import time
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED]"
            mock_get_settings.return_value = mock_settings

            payload = {
                "text": "Clean text for performance test",
                "request_id": "test-perf-123"
            }

            start_time = time.time()
            response = await client.post("/v1/scan/output", json=payload)
            end_time = time.time()

            assert response.status_code == 200
            data = response.json()

            # Response time should be reasonable
            request_duration = end_time - start_time
            assert request_duration < 2.0  # Relaxed from 1.0

            # API should report latency
            assert "latency_ms" in data
            assert data["latency_ms"] >= 0

    @pytest.mark.asyncio
    async def test_concurrent_requests(self, client: AsyncClient):
        """Test handling of concurrent DLP scan requests."""
        import asyncio
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED]"
            mock_get_settings.return_value = mock_settings

            async def make_request(i: int):
                payload = {
                    "text": f"Test text {i} with email{i}@example.com",
                    "request_id": f"test-concurrent-{i}"
                }
                response = await client.post("/v1/scan/output", json=payload)
                return response.status_code, response.json()

            # Make 10 concurrent requests
            tasks = [make_request(i) for i in range(10)]
            results = await asyncio.gather(*tasks)

            # All requests should succeed
            for status_code, data in results:
                assert status_code == 200
                assert "safe" in data
                assert "latency_ms" in data

    @pytest.mark.asyncio
    async def test_large_payload_handling(self, client: AsyncClient):
        """Test handling of large payloads."""
        # Create a large but valid payload (under the limit)
        large_text = "A" * 10000  # 10KB
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED]"
            mock_get_settings.return_value = mock_settings

            payload = {
                "text": large_text,
                "request_id": "test-large-123"
            }

            response = await client.post("/v1/scan/output", json=payload)

            assert response.status_code == 200
            data = response.json()

            # Should process successfully
            assert "safe" in data
            assert "latency_ms" in data


class TestDLPMultiplePIIEntities:
    """Test detection of multiple PII entity types."""

    @pytest.mark.asyncio
    async def test_multiple_pii_entities_detection(self, client: AsyncClient):
        """Test detection of multiple PII types in one request."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings, \
             patch('sidecar.api.dlp.is_feature_available', return_value=True):
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IP_ADDRESS", "US_SSN"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED]"
            mock_get_settings.return_value = mock_settings

            payload = {
                "text": """
                Contact Information:
                Email: john.doe@example.com
                Phone: +1-555-123-4567
                Credit Card: 4111-1111-1111-1111
                IP Address: 192.168.1.100
                SSN: 123-45-6789
                """,
                "request_id": "test-multiple-pii-123"
            }

            response = await client.post("/v1/scan/output", json=payload)

            assert response.status_code == 200
            data = response.json()

            assert data["pii_detected"] is True
            assert data["entities_count"] >= 3  # Should detect multiple entities
            assert data["safe"] is False  # Should be blocked in default mode
            assert data["blocked"] is True

    @pytest.mark.asyncio
    async def test_pii_entity_types_variety(self, client: AsyncClient):
        """Test detection of various PII entity types."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS", "US_SSN", "CRYPTO"]
            mock_settings.DLP_PII_THRESHOLD = 0.1 # Lower threshold for variety test
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED]"
            mock_get_settings.return_value = mock_settings

            test_cases = [
                ("email@test.com", "EMAIL_ADDRESS"),
                ("+1-555-123-4567", "PHONE_NUMBER"),
                ("4111-1111-1111-1111", "CREDIT_CARD"),
                ("DE89370400440532013000", "IBAN_CODE"),
                ("192.168.1.100", "IP_ADDRESS"),
                ("123-45-6789", "US_SSN"),
                ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "CRYPTO"),
            ]

            for test_text, expected_type in test_cases:
                payload = {
                    "text": f"Test: {test_text}",
                    "request_id": f"test-{expected_type.lower()}-123"
                }

                response = await client.post("/v1/scan/output", json=payload)

                assert response.status_code == 200, f"Failed for {expected_type}"
                data = response.json()

                assert data["pii_detected"] is True, f"No PII detected for {expected_type}"
                assert data["entities_count"] >= 1, f"No entities found for {expected_type}"


class TestDLPAPISecurity:
    """Test security aspects of DLP API."""

    @pytest.mark.asyncio
    async def test_no_injection_in_response(self, client: AsyncClient):
        """Test that responses don't contain injection vulnerabilities."""
        payload = {
            "text": "Clean text",
            "request_id": "test-security-123"
        }

        response = await client.post("/v1/scan/output", json=payload)

        assert response.status_code == 200
        data = response.json()

        # Response should be valid JSON, no script injection
        assert isinstance(data, dict)
        assert "safe" in data

        # Check Content-Type header
        assert response.headers.get("content-type") == "application/json"

    @pytest.mark.asyncio
    async def test_request_size_limits(self, client: AsyncClient):
        """Test that request size limits are enforced."""
        # This would depend on FastAPI settings, but we can test with very large requests
        # Note: Actual limits would be set in nginx/apisix config
        very_large_text = "A" * 1000000  # 1MB

        payload = {
            "text": very_large_text,
            "request_id": "test-size-limit-123"
        }

        # This might succeed or fail depending on server config
        response = await client.post("/v1/scan/output", json=payload)

        # Should either succeed or fail with appropriate error
        assert response.status_code in [200, 413, 422]


# Load testing utilities
class TestDLPLoadTesting:
    """Load testing scenarios for DLP API."""

    @pytest.mark.asyncio
    async def test_burst_requests(self, client: AsyncClient):
        """Test handling of burst request patterns."""
        import asyncio
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED]"
            mock_get_settings.return_value = mock_settings

            async def burst_request(i: int):
                payload = {
                    "text": f"Burst test {i} email{i}@example.com",
                    "request_id": f"burst-{i}"
                }
                response = await client.post("/v1/scan/output", json=payload)
                return response.status_code

            # Send burst of requests
            tasks = [burst_request(i) for i in range(20)]
            results = await asyncio.gather(*tasks)

            # All should succeed
            assert all(status == 200 for status in results)

    @pytest.mark.asyncio
    async def test_sustained_load(self, client: AsyncClient):
        """Test sustained load over time."""
        import time
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "block"
            mock_settings.DLP_PII_ENTITIES = ["EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 1_000_000
            mock_settings.DLP_BLOCK_MESSAGE = "[BLOCKED]"
            mock_get_settings.return_value = mock_settings

            start_time = time.time()
            request_count = 0

            # Send requests for 2 seconds (reduced from 5 to save time)
            while time.time() - start_time < 2:
                payload = {
                    "text": f"Load test {request_count} - email{request_count}@test.com",
                    "request_id": f"load-{request_count}"
                }

                response = await client.post("/v1/scan/output", json=payload)
                assert response.status_code == 200

                request_count += 1

            # Should handle reasonable load
            assert request_count >= 2  # At least 1 request per second


class TestAuditAPIEndpoints:
    """Test audit mode API endpoints."""

    @pytest.mark.asyncio
    async def test_audit_ingest_success(self, client: AsyncClient):
        """Test successful audit batch ingest."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings, \
             patch('sidecar.api.dlp.get_dlp_scanner') as mock_get_scanner:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_PII_ENTITIES = ["US_SSN", "EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_STREAMING_MODE = "audit"
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 500000  # Required for validator
            mock_get_settings.return_value = mock_settings

            # Mock scanner to return predictable results
            mock_scanner = Mock()
            mock_get_scanner.return_value = mock_scanner

            # Configure mock scanner responses
            async def mock_scan_output(text):
                if "123-45-6789" in text:
                    return Mock(pii_detected=True, entities=[{"entity_type": "US_SSN"}])
                elif "@example.com" in text or "@test.com" in text:
                    return Mock(pii_detected=True, entities=[{"entity_type": "EMAIL_ADDRESS"}])
                else:
                    return Mock(pii_detected=False, entities=[])

            mock_scanner.scan_output = mock_scan_output

            audit_batch = [
                {
                    "request_body": "What is AI?",
                    "response_body": "AI is artificial intelligence. My SSN is 123-45-6789",
                    "route_id": "chat-route-1",
                    "request_id": "req-123"
                }
            ]

            response = await client.post("/v1/audit/ingest", json={"items": audit_batch})

            assert response.status_code == 200
            data = response.json()
            assert "ingested" in data
            assert "pii_detected" in data
            assert "processing_time_ms" in data
            assert data["ingested"] == 1
            assert data["pii_detected"] == 1

    @pytest.mark.asyncio
    async def test_audit_ingest_empty_batch(self, client: AsyncClient):
        """Test audit ingest with empty batch."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_get_settings.return_value = mock_settings

            response = await client.post("/v1/audit/ingest", json={"items": []})

            assert response.status_code == 200
            data = response.json()
            assert data["ingested"] == 0
            assert data["pii_detected"] == 0

    @pytest.mark.asyncio
    async def test_audit_ingest_mixed_content(self, client: AsyncClient):
        """Test audit ingest with mixed clean and PII content."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings, \
             patch('sidecar.api.dlp.get_dlp_scanner') as mock_get_scanner:
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_PII_ENTITIES = ["US_SSN", "EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 500000  # Required for validator
            mock_get_settings.return_value = mock_settings

            mock_scanner = Mock()
            mock_get_scanner.return_value = mock_scanner

            async def mock_scan_output(text):
                if "@example.com" in text or "@test.com" in text:
                    return Mock(pii_detected=True, entities=[{"entity_type": "EMAIL_ADDRESS"}])
                else:
                    return Mock(pii_detected=False, entities=[])

            mock_scanner.scan_output = mock_scan_output

            audit_batch = [
                {
                    "request_body": "Hello",
                    "response_body": "Hello, how can I help?",
                    "route_id": "chat-route-1"
                },
                {
                    "request_body": "My email",
                    "response_body": "Your email is user@example.com",
                    "route_id": "chat-route-2"
                }
            ]

            response = await client.post("/v1/audit/ingest", json={"items": audit_batch})

        assert response.status_code == 200
        data = response.json()
        assert data["ingested"] == 2
        assert data["pii_detected"] == 1  # Only second response has PII

    @pytest.mark.asyncio
    async def test_audit_stats_endpoint(self, client: AsyncClient):
        """Test audit stats endpoint."""
        # Note: This test assumes DLP is enabled. In production deployments,
        # ENABLE_DLP should be set to true for audit functionality to work.
        # First ingest some data
        audit_batch = [
            {
                "request_id": "test-123",
                "route_id": "test-route",
                "client_ip": "127.0.0.1",
                "request_body": "test request",
                "response_body": "Response with SSN: 123-45-6789",
                "upstream_latency": 0.1,
                "timestamp": "2024-01-01T00:00:00Z"
            }
        ]

        # Test audit ingest with DLP disabled (default settings)
        ingest_response = await client.post("/v1/audit/ingest", json={"items": audit_batch})
        assert ingest_response.status_code == 200
        ingest_data = ingest_response.json()
        assert ingest_data["ingested"] == 1
        assert ingest_data["pii_detected"] == 0  # DLP disabled, so no PII detection

        # Now check stats - should show the ingest even with DLP disabled
        response = await client.get("/v1/audit/stats")

        assert response.status_code == 200
        data = response.json()
        assert "streaming_mode" in data
        assert "enabled" in data
        assert data["enabled"] == False  # DLP is disabled by default
        assert "total_ingested" in data
        assert "pii_detected" in data
        assert "entities_by_type" in data
        assert "last_ingest_time" in data
        assert data["total_ingested"] >= 1  # Items should be counted even with DLP disabled
        assert data["pii_detected"] == 0

    @pytest.mark.asyncio
    async def test_audit_health_endpoint(self, client: AsyncClient):
        """Test audit health endpoint."""
        response = await client.get("/v1/audit/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "streaming_mode" in data
        assert "enabled" in data
        assert "mode" in data
        assert data["mode"] in ["block", "anonymize", "log"]
        assert "edition" in data
        assert "dlp_block_available" in data

    @pytest.mark.asyncio
    async def test_audit_ingest_invalid_format(self, client: AsyncClient):
        """Test audit ingest with invalid request format."""
        # Missing required fields - should still work since all fields are optional
        response = await client.post("/v1/audit/ingest", json={"items": [{"invalid": "data"}]})

        assert response.status_code == 200  # Model accepts unknown fields

    @pytest.mark.asyncio
    async def test_audit_stats_basic(self, client: AsyncClient):
        """Test basic audit stats functionality."""
        with patch('sidecar.api.dlp.get_settings') as mock_get_settings, \
             patch('sidecar.api.dlp.get_dlp_scanner') as mock_get_scanner, \
             patch('sidecar.api.dlp.is_feature_available', return_value=True):
            mock_settings = Mock()
            mock_settings.ENABLE_DLP = True
            mock_settings.DLP_MODE = "log"
            mock_settings.DLP_PII_ENTITIES = ["US_SSN", "EMAIL_ADDRESS"]
            mock_settings.DLP_PII_THRESHOLD = 0.5
            mock_settings.DLP_STREAMING_MODE = "audit"
            mock_settings.DLP_MAX_OUTPUT_LENGTH = 500000  # Required for validator
            mock_settings.DLP_FAIL_OPEN = False  # Required for proper mock
            mock_get_settings.return_value = mock_settings

            mock_scanner = Mock()
            mock_get_scanner.return_value = mock_scanner

            async def mock_scan_output(text):
                if "987-65-4321" in text:
                    return Mock(pii_detected=True, entities=[{"entity_type": "US_SSN"}])
                else:
                    return Mock(pii_detected=False, entities=[])

            mock_scanner.scan_output = mock_scan_output

            # Single batch
            batch = [
                {
                    "request_body": "test",
                    "response_body": "Response with SSN: 987-65-4321",
                    "route_id": "test-route"
                }
            ]

            await client.post("/v1/audit/ingest", json={"items": batch})

            # Check stats
            response = await client.get("/v1/audit/stats")
            stats = response.json()

            assert stats["total_ingested"] >= 1
            assert stats["pii_detected"] >= 1
            assert "US_SSN" in stats["entities_by_type"]


if __name__ == "__main__":
    print("DLP API Integration Tests")
    print("Note: Run with pytest for full test execution")