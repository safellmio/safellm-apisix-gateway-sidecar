"""Unit tests for built-in MCP security plugins."""
from __future__ import annotations

import pytest

from sidecar.core.settings import Settings
from sidecar.layers.base import ScanResult
from sidecar.mcp.plugins.security import DLPScanPlugin, GuardDecisionPlugin, PIIScanPlugin
from sidecar.models import Decision
from sidecar.pipeline.engine import PipelineResult


class _FakeAuthService:
    async def decide_async(self, body: str, uri: str, request_id: str = "") -> PipelineResult:
        assert body == "hello"
        assert uri == "/chat"
        assert request_id == "req-1"
        return PipelineResult(
            decision=Decision(allowed=True, reason="clean"),
            total_latency_ms=3.2,
            layers_executed=2,
            stopping_layer=None,
        )


class _FakePIILayer:
    name = "L1_PII_FAST_REGEX"

    async def scan(self, ctx):
        assert ctx.text == "john@example.com"
        return ScanResult.blocked(reason="pii_detected", layer=self.name, score=0.94)


class _FakeDLPResult:
    safe = False
    pii_detected = True
    entities = [{"entity_type": "EMAIL_ADDRESS", "text": "john@example.com"}]
    modified_text = "[BLOCKED]"
    blocked_reason = "DLP: PII detected"
    latency_ms = 1.7


class _FakeDLPScanner:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def scan_output(self, text: str):
        assert text == "response"
        return _FakeDLPResult()


@pytest.mark.asyncio
async def test_guard_plugin_returns_pipeline_fields() -> None:
    plugin = GuardDecisionPlugin(auth_service=_FakeAuthService())

    result = await plugin.run({"prompt": "hello", "uri": "/chat", "request_id": "req-1"})

    assert result["allowed"] is True
    assert result["reason"] == "clean"
    assert result["layers_executed"] == 2


@pytest.mark.asyncio
async def test_pii_plugin_handles_disabled_layer(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(ENABLE_CACHE=False)
    plugin = PIIScanPlugin(settings=settings)

    monkeypatch.setattr("sidecar.core.providers.get_pii_layer", lambda _settings: None)

    result = await plugin.run({"text": "any text"})

    assert result["enabled"] is False
    assert result["safe"] is True
    assert result["reason"] == "pii_layer_disabled"


@pytest.mark.asyncio
async def test_pii_plugin_runs_layer(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(ENABLE_CACHE=False)
    plugin = PIIScanPlugin(settings=settings)

    monkeypatch.setattr("sidecar.core.providers.get_pii_layer", lambda _settings: _FakePIILayer())

    result = await plugin.run({"text": "john@example.com"})

    assert result["enabled"] is True
    assert result["safe"] is False
    assert result["layer"] == "L1_PII_FAST_REGEX"


@pytest.mark.asyncio
async def test_dlp_plugin_runs_selected_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(ENABLE_CACHE=False)
    plugin = DLPScanPlugin(settings=settings)

    monkeypatch.setattr("sidecar.mcp.plugins.security.DLPScanner", _FakeDLPScanner)

    result = await plugin.run({"text": "response", "mode": "block"})

    assert result["mode"] == "block"
    assert result["safe"] is False
    assert result["pii_detected"] is True
    assert result["entities"][0]["entity_type"] == "EMAIL_ADDRESS"


@pytest.mark.asyncio
async def test_plugin_input_validation() -> None:
    plugin = GuardDecisionPlugin(auth_service=_FakeAuthService())

    with pytest.raises(ValueError, match="prompt"):
        await plugin.run({"prompt": "", "uri": "/chat"})
