"""Core interfaces for OSS-safe provider pattern."""
from __future__ import annotations

from typing import Any, Awaitable, Callable, Protocol


class Coalescer(Protocol):
    """Request coalescer interface (local)."""

    async def coalesce(self, request_hash: str, scan_coro: Callable[[], Awaitable[Any]]) -> Any:
        ...

    async def shutdown(self) -> None:
        ...


class AuditLogger(Protocol):
    """Audit logger interface (OSS no-op implementation)."""

    async def log(
        self,
        request_id: str,
        prompt: str,
        verdict: str,
        layer: str | None = None,
        reason: str | None = None,
        latency_ms: float = 0.0,
        user_id: str | None = None,
    ) -> None:
        ...
