import asyncio

import pytest

from sidecar.layers.cache import RedisCircuitBreaker


@pytest.mark.asyncio
async def test_circuit_breaker_dead_time_fast_fail():
    cb = RedisCircuitBreaker(failure_threshold=1, recovery_timeout=0.2)

    assert await cb.should_attempt() is True

    await cb.record_failure()
    assert await cb.should_attempt() is False

    await asyncio.sleep(0.21)
    assert await cb.should_attempt() is True
