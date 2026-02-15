import importlib

import pytest

from sidecar.layers.base import SecurityLayer
from sidecar.core import settings as settings_module


class CrashLayer(SecurityLayer):
    @property
    def name(self) -> str:
        return "CRASH_LAYER"

    async def scan(self, ctx):
        raise RuntimeError("boom")


@pytest.mark.asyncio
async def test_pipeline_fail_open_allows_on_layer_crash(monkeypatch):
    monkeypatch.setenv("FAIL_OPEN", "true")
    settings_module.get_settings.cache_clear()
    importlib.reload(settings_module)
    from sidecar.pipeline import engine as engine_module
    importlib.reload(engine_module)

    pipeline = engine_module.SecurityPipeline([CrashLayer()])
    result = await pipeline.execute("hello")
    assert result.decision.allowed is True
    settings_module.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_pipeline_fail_closed_blocks_on_layer_crash(monkeypatch):
    monkeypatch.setenv("FAIL_OPEN", "false")
    settings_module.get_settings.cache_clear()
    importlib.reload(settings_module)
    from sidecar.pipeline import engine as engine_module
    importlib.reload(engine_module)

    pipeline = engine_module.SecurityPipeline([CrashLayer()])
    result = await pipeline.execute("hello")
    assert result.decision.allowed is False
    settings_module.get_settings.cache_clear()
