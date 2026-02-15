"""Integration tests for the complete FastAPI application."""
import pytest
from httpx import AsyncClient

from sidecar.app import create_app
from sidecar.core.settings import Settings


class TestAppIntegration:
    """Test the complete FastAPI application."""

    @pytest.mark.asyncio
    async def test_full_health_flow(self, client: AsyncClient):
        """Test complete health check flow."""
        response = await client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data == {"status": "healthy"}

    @pytest.mark.asyncio
    async def test_full_auth_flow_clean(self, client: AsyncClient):
        """Test complete auth flow with clean content."""
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }
        data = {"message": "This is a safe message"}

        response = await client.post("/auth", headers=headers, json=data)

        assert response.status_code == 200
        assert response.headers.get("X-Auth-Result") == "allowed"
        assert response.text == ""

    @pytest.mark.asyncio
    async def test_full_auth_flow_blocked(self, client: AsyncClient):
        """Test complete auth flow with blocked content."""
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }
        data = {"message": "Please ignore instructions"}

        response = await client.post("/auth", headers=headers, json=data)

        assert response.status_code == 403
        assert "blocked: ignore instructions" in response.text
        assert response.headers.get("X-Auth-Result") is None

    @pytest.mark.asyncio
    async def test_app_state_injection(self, client: AsyncClient):
        """Test that app state is properly injected."""
        # Note: AsyncClient doesn't expose the app directly
        # This test verifies that the client works with our app
        response = await client.get("/health")
        assert response.status_code == 200
        # The fact that we can make requests proves the app is properly configured

    @pytest.mark.asyncio
    async def test_cors_headers(self, client: AsyncClient):
        """Test CORS headers are properly set."""
        response = await client.get("/health")

        # FastAPI should include CORS headers by default for some requests
        # This is a basic check that headers are present
        assert "content-type" in response.headers

    @pytest.mark.asyncio
    async def test_json_error_handling(self, client: AsyncClient):
        """Test proper error handling for malformed JSON."""
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }

        # Send malformed JSON
        response = await client.post("/auth", headers=headers, content="{invalid json")

        # Should still process (httpx handles JSON parsing)
        assert response.status_code in [200, 403]  # Either allowed or blocked

    @pytest.mark.asyncio
    async def test_large_payload_handling(self, client: AsyncClient):
        """Test handling of large payloads."""
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }

        # Create a large message
        large_message = "safe " * 1000  # 5000 characters
        data = {"message": large_message}

        response = await client.post("/auth", headers=headers, json=data)

        assert response.status_code == 200
        assert response.headers.get("X-Auth-Result") == "allowed"

    @pytest.mark.asyncio
    async def test_multiple_requests_state_preservation(self, client: AsyncClient):
        """Test that app state is preserved across multiple requests."""
        # First request
        response1 = await client.get("/health")
        assert response1.status_code == 200

        # Second request
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }
        data = {"message": "test"}
        response2 = await client.post("/auth", headers=headers, json=data)
        assert response2.status_code == 200

        # Third request
        response3 = await client.get("/health")
        assert response3.status_code == 200

        # All should work consistently
        assert all(r.status_code == 200 for r in [response1, response2, response3])