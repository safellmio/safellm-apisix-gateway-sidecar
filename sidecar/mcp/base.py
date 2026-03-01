"""MCP base abstractions for SafeLLM sidecar tools."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class MCPToolSpec:
    """Describes one MCP tool exposed by the sidecar."""

    name: str
    description: str
    input_schema: dict[str, Any]

    def as_mcp_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class MCPToolPlugin(ABC):
    """Plugin contract for MCP tools."""

    @property
    @abstractmethod
    def spec(self) -> MCPToolSpec:
        """Tool metadata and JSON schema."""

    @abstractmethod
    async def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute tool logic and return JSON-serializable result."""
