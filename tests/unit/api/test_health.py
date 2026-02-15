"""Unit tests for health API endpoint."""
import pytest
from httpx import AsyncClient

from sidecar.api.health import router


class TestHealthAPI:
    """Test the health API endpoints."""

    @pytest.mark.asyncio
    async def test_health_endpoint(self, client: AsyncClient):
        """Test the health endpoint returns correct response."""
        response = await client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data == {"status": "healthy"}

    @pytest.mark.asyncio
    async def test_health_endpoint_content_type(self, client: AsyncClient):
        """Test health endpoint returns JSON content type."""
        response = await client.get("/health")

        assert response.headers["content-type"] == "application/json"

    @pytest.mark.asyncio
    async def test_health_endpoint_methods(self, client: AsyncClient):
        """Test that health endpoint only accepts GET method."""
        # GET should work
        response = await client.get("/health")
        assert response.status_code == 200

        # POST should fail
        response = await client.post("/health")
        assert response.status_code == 405  # Method Not Allowed

        # PUT should fail
        response = await client.put("/health")
        assert response.status_code == 405

        # DELETE should fail
        response = await client.delete("/health")
        assert response.status_code == 405