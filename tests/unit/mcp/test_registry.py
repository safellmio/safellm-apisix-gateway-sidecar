"""Unit tests for MCP registry."""
from __future__ import annotations

import pytest

from sidecar.mcp.base import MCPToolPlugin, MCPToolSpec
from sidecar.mcp.registry import MCPToolRegistry


class _EchoPlugin(MCPToolPlugin):
    @property
    def spec(self) -> MCPToolSpec:
        return MCPToolSpec(
            name="echo",
            description="Echo tool",
            input_schema={"type": "object", "additionalProperties": True},
        )

    async def run(self, arguments: dict[str, object]) -> dict[str, object]:
        return {"echo": arguments}


@pytest.mark.asyncio
async def test_registry_register_and_call() -> None:
    registry = MCPToolRegistry()
    registry.register(_EchoPlugin())

    tools = registry.list_tools()
    assert len(tools) == 1
    assert tools[0]["name"] == "echo"

    result = await registry.call_tool("echo", {"x": 1})
    assert result == {"echo": {"x": 1}}


def test_registry_duplicate_registration_raises() -> None:
    registry = MCPToolRegistry()
    registry.register(_EchoPlugin())

    with pytest.raises(ValueError, match="already registered"):
        registry.register(_EchoPlugin())


@pytest.mark.asyncio
async def test_registry_unknown_tool_raises() -> None:
    registry = MCPToolRegistry()

    with pytest.raises(ValueError, match="Unknown MCP tool"):
        await registry.call_tool("missing", {})
