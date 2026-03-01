"""Built-in security MCP plugins for SafeLLM."""
from __future__ import annotations

from typing import Any

from ..base import MCPToolPlugin, MCPToolSpec
from ...core.settings import Settings
from ...layers.base import ScanContext
from ...layers.dlp import DLPScanner
from ...services.auth import AuthService


def _require_string(arguments: dict[str, Any], field: str) -> str:
    value = arguments.get(field)
    if not isinstance(value, str) or value == "":
        raise ValueError(f"'{field}' must be a non-empty string")
    return value


def _optional_string(arguments: dict[str, Any], field: str, default: str = "") -> str:
    value = arguments.get(field, default)
    if not isinstance(value, str):
        raise ValueError(f"'{field}' must be a string")
    return value


class GuardDecisionPlugin(MCPToolPlugin):
    """Runs full SafeLLM input pipeline and returns decision details."""

    _SPEC = MCPToolSpec(
        name="safellm.guard_decide",
        description="Execute SafeLLM input guard pipeline for prompt + URI.",
        input_schema={
            "type": "object",
            "properties": {
                "prompt": {"type": "string", "minLength": 1},
                "uri": {"type": "string", "minLength": 1},
                "request_id": {"type": "string"},
            },
            "required": ["prompt", "uri"],
            "additionalProperties": False,
        },
    )

    def __init__(self, auth_service: AuthService):
        self._auth_service = auth_service

    @property
    def spec(self) -> MCPToolSpec:
        return self._SPEC

    async def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        prompt = _require_string(arguments, "prompt")
        uri = _require_string(arguments, "uri")
        request_id = _optional_string(arguments, "request_id")

        result = await self._auth_service.decide_async(body=prompt, uri=uri, request_id=request_id)
        decision = result.decision

        return {
            "allowed": decision.allowed,
            "reason": decision.reason,
            "status_code": decision.status_code,
            "latency_ms": result.total_latency_ms,
            "layers_executed": result.layers_executed,
            "stopping_layer": result.stopping_layer,
        }


class PIIScanPlugin(MCPToolPlugin):
    """Runs SafeLLM PII layer only."""

    _SPEC = MCPToolSpec(
        name="safellm.pii_scan",
        description="Run PII scan layer over raw text.",
        input_schema={
            "type": "object",
            "properties": {
                "text": {"type": "string", "minLength": 1},
                "request_id": {"type": "string"},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
    )

    def __init__(self, settings: Settings):
        self._settings = settings

    @property
    def spec(self) -> MCPToolSpec:
        return self._SPEC

    async def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        text = _require_string(arguments, "text")
        request_id = _optional_string(arguments, "request_id")

        # Lazy import avoids bootstrap circular import between providers and services package init.
        from ...core.providers import get_pii_layer
        layer = get_pii_layer(self._settings)
        if layer is None:
            return {
                "enabled": False,
                "safe": True,
                "reason": "pii_layer_disabled",
                "layer": None,
                "score": 0.0,
            }

        result = await layer.scan(ScanContext(text=text, request_id=request_id))
        return {
            "enabled": True,
            "safe": result.safe,
            "reason": result.reason,
            "layer": result.layer or layer.name,
            "score": result.score,
            "latency_ms": result.latency_ms,
        }


class DLPScanPlugin(MCPToolPlugin):
    """Runs SafeLLM output DLP scanner."""

    _SPEC = MCPToolSpec(
        name="safellm.dlp_scan",
        description="Run DLP output scan over model response text.",
        input_schema={
            "type": "object",
            "properties": {
                "text": {"type": "string", "minLength": 1},
                "mode": {"type": "string", "enum": ["block", "anonymize", "log"]},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
    )

    def __init__(self, settings: Settings):
        self._settings = settings
        self._scanners: dict[str, DLPScanner] = {}

    @property
    def spec(self) -> MCPToolSpec:
        return self._SPEC

    def _get_scanner(self, mode: str) -> DLPScanner:
        scanner = self._scanners.get(mode)
        if scanner is not None:
            return scanner

        scanner = DLPScanner(
            mode=mode,
            entities=self._settings.DLP_PII_ENTITIES,
            threshold=self._settings.DLP_PII_THRESHOLD,
            fail_open=self._settings.DLP_FAIL_OPEN,
            block_message=self._settings.DLP_BLOCK_MESSAGE,
        )
        self._scanners[mode] = scanner
        return scanner

    async def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        text = _require_string(arguments, "text")
        mode = arguments.get("mode", self._settings.DLP_MODE)
        if not isinstance(mode, str):
            raise ValueError("'mode' must be a string")
        mode = mode.lower()
        if mode not in {"block", "anonymize", "log"}:
            raise ValueError("'mode' must be one of: block, anonymize, log")

        result = await self._get_scanner(mode).scan_output(text)

        return {
            "mode": mode,
            "safe": result.safe,
            "pii_detected": result.pii_detected,
            "entities": result.entities,
            "modified_text": result.modified_text,
            "blocked_reason": result.blocked_reason,
            "latency_ms": result.latency_ms,
        }
