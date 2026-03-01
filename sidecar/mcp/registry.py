"""Registry for SafeLLM MCP plugins."""
from __future__ import annotations

from typing import Any

from .base import MCPToolPlugin


class MCPToolRegistry:
    """Stores and dispatches MCP tool plugins by unique name."""

    def __init__(self) -> None:
        self._plugins: dict[str, MCPToolPlugin] = {}

    def register(self, plugin: MCPToolPlugin) -> None:
        name = plugin.spec.name
        if name in self._plugins:
            raise ValueError(f"MCP tool already registered: {name}")
        self._plugins[name] = plugin

    def list_tools(self) -> list[dict[str, Any]]:
        return [plugin.spec.as_mcp_dict() for plugin in self._plugins.values()]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        plugin = self._plugins.get(name)
        if plugin is None:
            raise ValueError(f"Unknown MCP tool: {name}")
        payload = arguments or {}
        return await plugin.run(payload)
