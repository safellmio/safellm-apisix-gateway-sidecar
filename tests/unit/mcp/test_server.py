"""Unit tests for MCP JSON-RPC server."""
from __future__ import annotations

import pytest

from sidecar.mcp.base import MCPToolPlugin, MCPToolSpec
from sidecar.mcp.registry import MCPToolRegistry
from sidecar.mcp.server import MCPServer


class _EchoPlugin(MCPToolPlugin):
    @property
    def spec(self) -> MCPToolSpec:
        return MCPToolSpec(
            name="echo",
            description="Echo",
            input_schema={"type": "object", "additionalProperties": True},
        )

    async def run(self, arguments):
        return {"value": arguments.get("value", "")}


class _FailingPlugin(MCPToolPlugin):
    @property
    def spec(self) -> MCPToolSpec:
        return MCPToolSpec(
            name="boom",
            description="Failing plugin",
            input_schema={"type": "object", "additionalProperties": True},
        )

    async def run(self, arguments):
        raise RuntimeError("sensitive internals")


@pytest.fixture
def server() -> MCPServer:
    registry = MCPToolRegistry()
    registry.register(_EchoPlugin())
    return MCPServer(registry=registry, server_name="test-mcp", server_version="0.0.1")


@pytest.mark.asyncio
async def test_initialize(server: MCPServer) -> None:
    response = await server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})

    assert response["result"]["serverInfo"]["name"] == "test-mcp"
    assert response["result"]["protocolVersion"] == "2024-11-05"


@pytest.mark.asyncio
async def test_tools_list(server: MCPServer) -> None:
    response = await server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

    assert response["result"]["tools"][0]["name"] == "echo"


@pytest.mark.asyncio
async def test_tools_call(server: MCPServer) -> None:
    response = await server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"value": "ok"}},
        }
    )

    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["value"] == "ok"


@pytest.mark.asyncio
async def test_unknown_method_returns_error(server: MCPServer) -> None:
    response = await server.handle_request({"jsonrpc": "2.0", "id": 4, "method": "unknown", "params": {}})

    assert response["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_invalid_request_returns_error(server: MCPServer) -> None:
    response = await server.handle_request({"id": 5, "method": "tools/list"})

    assert response["error"]["code"] == -32600


@pytest.mark.asyncio
async def test_initialized_notification_returns_none(server: MCPServer) -> None:
    response = await server.handle_request(
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
    )
    assert response is None


@pytest.mark.asyncio
async def test_unknown_notification_returns_none(server: MCPServer) -> None:
    response = await server.handle_request(
        {"jsonrpc": "2.0", "method": "notifications/custom", "params": {"x": 1}}
    )
    assert response is None


@pytest.mark.asyncio
async def test_internal_error_is_generic() -> None:
    registry = MCPToolRegistry()
    registry.register(_FailingPlugin())
    failing_server = MCPServer(registry=registry)

    response = await failing_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {"name": "boom", "arguments": {}},
        }
    )
    assert response["error"]["code"] == -32000
    assert response["error"]["message"] == "Internal server error"
