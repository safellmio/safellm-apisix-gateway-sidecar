"""Minimal MCP stdio server for SafeLLM sidecar tools."""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

from .plugins import DLPScanPlugin, GuardDecisionPlugin, PIIScanPlugin
from .registry import MCPToolRegistry
from ..core.logger import configure_logging
from ..core.settings import get_settings
from ..services.auth import AuthService

_LOGGER = logging.getLogger(__name__)


class MCPServer:
    """Line-delimited JSON-RPC server exposing SafeLLM tools."""

    def __init__(self, registry: MCPToolRegistry, server_name: str = "safellm-mcp", server_version: str = "2.2.0"):
        self._registry = registry
        self._server_name = server_name
        self._server_version = server_version

    async def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        has_request_id = "id" in request
        request_id = request.get("id")
        method = request.get("method")

        if request.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return None if not has_request_id else self._error_response(request_id, -32600, "Invalid Request")

        params = request.get("params")
        if params is None:
            params = {}
        elif not isinstance(params, dict):
            return None if not has_request_id else self._error_response(request_id, -32602, "Invalid params")

        try:
            if method == "notifications/initialized" or method.startswith("notifications/"):
                return None

            if method == "initialize":
                return self._ok_response(
                    request_id,
                    {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {
                            "name": self._server_name,
                            "version": self._server_version,
                        },
                        "capabilities": {"tools": {}},
                    },
                )

            if method == "ping":
                return self._ok_response(request_id, {"ok": True})

            if method == "tools/list":
                return self._ok_response(request_id, {"tools": self._registry.list_tools()})

            if method == "tools/call":
                name = params.get("name")
                arguments = params.get("arguments", {})
                if not isinstance(name, str) or name == "":
                    return None if not has_request_id else self._error_response(
                        request_id, -32602, "Invalid params: name is required"
                    )
                if not isinstance(arguments, dict):
                    return None if not has_request_id else self._error_response(
                        request_id, -32602, "Invalid params: arguments must be object"
                    )

                result = await self._registry.call_tool(name, arguments)
                return self._ok_response(
                    request_id,
                    {
                        "content": [
                            {"type": "text", "text": json.dumps(result, separators=(",", ":"), ensure_ascii=True)}
                        ],
                        "structuredContent": result,
                        "isError": False,
                    },
                )

            return None if not has_request_id else self._error_response(request_id, -32601, f"Method not found: {method}")
        except ValueError as exc:
            return None if not has_request_id else self._error_response(request_id, -32602, str(exc))
        except Exception:  # pragma: no cover - defensive fallback
            _LOGGER.exception("mcp_internal_error")
            return None if not has_request_id else self._error_response(request_id, -32000, "Internal server error")

    async def run_stdio(self) -> None:
        """Start stdio loop for MCP hosts."""
        while True:
            line = await asyncio.to_thread(sys.stdin.readline)
            if line == "":
                return
            line = line.strip()
            if not line:
                continue

            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                response = self._error_response(None, -32700, "Parse error")
            else:
                if not isinstance(request, dict):
                    response = self._error_response(None, -32600, "Invalid Request")
                else:
                    response = await self.handle_request(request)

            if response is not None:
                sys.stdout.write(json.dumps(response, separators=(",", ":"), ensure_ascii=True) + "\n")
                sys.stdout.flush()

    @staticmethod
    def _ok_response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }


async def run_default_server() -> None:
    """Bootstrap MCP server with built-in SafeLLM plugins."""
    # MCP protocol uses stdout for JSON-RPC frames, so logs must go to stderr.
    configure_logging(stream=sys.stderr)

    settings = get_settings()
    auth_service = AuthService(settings)

    registry = MCPToolRegistry()
    registry.register(GuardDecisionPlugin(auth_service=auth_service))
    registry.register(PIIScanPlugin(settings=settings))
    registry.register(DLPScanPlugin(settings=settings))

    server = MCPServer(registry=registry)
    try:
        await server.run_stdio()
    finally:
        await auth_service.shutdown()


def main() -> None:
    asyncio.run(run_default_server())


if __name__ == "__main__":
    main()
