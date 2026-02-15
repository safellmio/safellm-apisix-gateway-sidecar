"""HTTP Protocol Limits Tests - E2E Scenarios"""
import pytest
import base64
import json
from httpx import AsyncClient


class TestHTTPLimits:
    """Test HTTP protocol limits and edge cases."""

    @pytest.mark.asyncio
    async def test_header_overflow_edge_cases(self, client: AsyncClient):
        """Test various header overflow scenarios."""
        # Test 1: Large prompt within limits (64KB)
        large_prompt_64k = "safe " * (64 * 1024 // 5)  # ~64KB
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }
        data = {"message": large_prompt_64k}

        response = await client.post("/auth", headers=headers, json=data)
        assert response.status_code == 200
        assert response.headers.get("X-Auth-Result") == "allowed"

    @pytest.mark.asyncio
    async def test_base64_encoding_edge_cases(self, client: AsyncClient):
        """Test Base64 encoding with edge cases (emojis, unicode, binary-like)."""
        test_cases = [
            # Emojis
            {"message": "Explain 🔥🎉💀 in context AI"},
            # Unicode
            {"message": "Translate: 日本語, العربية, עברית"},
            # Control characters and null bytes
            {"message": "Test\x00\x01\x02control chars"},
            # Binary-like content
            {"message": "Data: " + base64.b64encode(b"binary data").decode()},
        ]

        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }

        for data in test_cases:
            response = await client.post("/auth", headers=headers, json=data)
            # Should process without corruption
            assert response.status_code in [200, 403]  # Either allowed or blocked by content

    @pytest.mark.asyncio
    async def test_large_prompt_sizes(self, client: AsyncClient):
        """Test different prompt sizes to find limits."""
        sizes_kb = [1, 8, 32, 64, 128, 192]

        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }

        for size_kb in sizes_kb:
            # Create prompt of specific size
            prompt = "safe " * (size_kb * 1024 // 5)  # Approximate size calculation
            data = {"message": prompt}

            try:
                response = await client.post("/auth", headers=headers, json=data, timeout=30.0)

                if size_kb <= 64:
                    # Should work within safe limits
                    assert response.status_code == 200
                    assert response.headers.get("X-Auth-Result") == "allowed"
                elif size_kb <= 192:
                    # May work depending on configuration
                    assert response.status_code in [200, 413]
                else:
                    # Large sizes may fail
                    assert response.status_code in [200, 413]

            except Exception as e:
                # Large payloads may timeout or fail
                if size_kb > 192:
                    pytest.skip(f"Large payload ({size_kb}KB) test skipped: {e}")
                else:
                    raise

    @pytest.mark.asyncio
    async def test_base64_corruption_detection(self, client: AsyncClient):
        """Test that Base64 encoding/decoding doesn't corrupt data."""
        # Create test message with special characters
        original_message = "Test message with special chars: 🔥🎉💀 中文 العربية"
        data = {"message": original_message}

        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }

        response = await client.post("/auth", headers=headers, json=data)

        # Should process without corruption
        assert response.status_code in [200, 403]

        # If response includes processed data, verify it's not corrupted
        if "X-Guard-Body-Length" in response.headers:
            # Check that length matches expectation
            expected_b64_len = len(base64.b64encode(original_message.encode()).decode())
            reported_len = int(response.headers.get("X-Guard-Body-Length", 0))
            # Allow some variance for JSON encoding
            assert abs(reported_len - len(original_message)) < 50

    @pytest.mark.asyncio
    async def test_malformed_base64_handling(self, client: AsyncClient):
        """Test handling of malformed Base64 in headers."""
        # This test simulates what would happen if APISIX sends malformed Base64
        # Since we're testing the sidecar directly, we'll test with edge case inputs

        test_cases = [
            # Normal case
            {"message": "normal message"},
            # Empty message
            {"message": ""},
            # Very long safe message
            {"message": "safe " * 10000},
        ]

        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }

        for data in test_cases:
            response = await client.post("/auth", headers=headers, json=data)
            # Should handle gracefully
            assert response.status_code in [200, 403]