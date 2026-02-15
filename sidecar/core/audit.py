"""
OSS audit stub.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class AuditLogEntry:
    """Placeholder entry for OSS (unused)."""
    request_id: str
    prompt: str
    verdict: str
    layer: str | None = None
    reason: str | None = None
    latency_ms: float = 0.0
    user_id: str | None = None


class AuditLogger:
    """No-op audit logger for OSS."""

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
        return


_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Return no-op logger in OSS."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


async def log_audit_event(
    request_id: str,
    prompt: str,
    allowed: bool,
    layer: str,
    reason: str,
    latency_ms: float,
) -> None:
    """No-op in OSS."""
    return
