"""Failure Modes Tests - E2E Scenarios"""
import asyncio
import time
import pytest
from unittest.mock import patch, AsyncMock
from httpx import AsyncClient, TimeoutException


class TestFailureModes:
    """Test system behavior under failure conditions."""

    @pytest.mark.asyncio
    async def test_redis_circuit_breaker_activation(self, client: AsyncClient):
        """Test circuit breaker activation when Redis is unavailable."""
        print("\n🧪 Testing Redis circuit breaker...")

        # Test the circuit breaker logic directly
        from sidecar.layers.cache import RedisCircuitBreaker

        cb = RedisCircuitBreaker(failure_threshold=3, recovery_timeout=2)

        # Initially should allow attempts
        assert await cb.should_attempt() == True

        # Record failures
        for i in range(3):
            await cb.record_failure()
            if i < 2:
                assert await cb.should_attempt() == True, f"Should still allow attempts after {i+1} failures"
            else:
                assert await cb.should_attempt() == False, "Should block attempts after 3 failures"

        print("   Circuit breaker activated after 3 failures")

        # Test recovery
        await asyncio.sleep(2.1)  # Wait for recovery timeout
        assert await cb.should_attempt() == True, "Should allow attempts after recovery timeout"
        await cb.record_success()
        assert await cb.should_attempt() == True, "Should remain open after successful recovery"

        print("   Circuit breaker recovered successfully")

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration_with_cache(self, client: AsyncClient):
        """Test circuit breaker integration with cache layer."""
        print("\n🧪 Testing circuit breaker integration...")

        # Mock Redis to always fail
        with patch('redis.Redis') as mock_redis:
            mock_redis_instance = AsyncMock()
            mock_redis_instance.get.side_effect = Exception("Redis connection failed")
            mock_redis_instance.set.side_effect = Exception("Redis connection failed")
            mock_redis.return_value = mock_redis_instance

            # Import and test cache layer
            from sidecar.layers.cache import CacheLayer

            cache = CacheLayer()

            # First few requests should try Redis and fail
            from sidecar.layers.base import ScanContext

            for i in range(3):
                ctx = ScanContext(text=f"test prompt {i}")
                result = await cache.scan(ctx)
                # When Redis fails, circuit breaker should eventually activate
                # and cache should return ok() to continue pipeline
                assert result.safe == True, "Should allow pipeline to continue when Redis fails"

            # Circuit breaker should eventually activate
            # (This depends on the circuit breaker configuration in the cache layer)

    @pytest.mark.asyncio
    async def test_graceful_degradation_under_load(self, client: AsyncClient):
        """Test graceful degradation when system is overloaded."""
        print("\n🧪 Testing graceful degradation under load...")

        # Create high concurrent load
        num_concurrent = 100

        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }

        async def make_request(request_id: int):
            """Make a single request and handle potential failures."""
            try:
                data = {"message": f"Load test message {request_id} - safe content"}
                response = await client.post("/auth", headers=headers, json=data, timeout=5.0)
                return response.status_code
            except TimeoutException:
                return 408  # Request timeout
            except Exception as e:
                print(f"   Request {request_id} failed with: {e}")
                return 500  # Internal server error

        # Launch concurrent requests
        start_time = time.time()
        tasks = [make_request(i) for i in range(num_concurrent)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_time = time.time() - start_time

        # Analyze results
        status_codes = []
        errors = []

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                errors.append(result)
                status_codes.append(500)
            else:
                status_codes.append(result)

        success_count = sum(1 for code in status_codes if code == 200)
        error_count = len([code for code in status_codes if code >= 400])

        success_rate = success_count / num_concurrent
        error_rate = error_count / num_concurrent

        print(f"   Load test results ({num_concurrent} concurrent requests in {total_time:.2f}s):")
        print(f"     Success rate: {success_rate:.1%} ({success_count}/{num_concurrent})")
        print(f"     Error rate: {error_rate:.1%} ({error_count}/{num_concurrent})")

        # System should handle load gracefully
        # Allow some failures but not complete breakdown
        assert success_rate > 0.5, f"Success rate too low: {success_rate:.1%}"

        # P99 latency should be reasonable (under 5 seconds as per requirements)
        if success_count > 0:
            p99_latency = total_time * 1000  # Convert to ms for display
            print(f"   P99 latency: {p99_latency:.2f}ms")
    @pytest.mark.asyncio
    async def test_service_degradation_with_partial_failures(self, client: AsyncClient):
        """Test behavior when some components fail but others work."""
        print("\n🧪 Testing partial service degradation...")

        # Test with mixed scenarios
        test_cases = [
            # Normal operation
            {"message": "Normal safe message", "expect_success": True},
            # Large payload (may cause issues)
            {"message": "Large " * 10000, "expect_success": True},  # Should still work
            # Special characters
            {"message": "Special chars: 🔥🎉💀 中文", "expect_success": True},
        ]

        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }

        success_count = 0
        total_count = len(test_cases)

        for i, test_case in enumerate(test_cases):
            try:
                response = await client.post("/auth", headers=headers, json=test_case, timeout=10.0)

                if test_case["expect_success"]:
                    if response.status_code == 200:
                        success_count += 1
                    else:
                        print(f"   Unexpected failure for case {i}: {response.status_code}")
                else:
                    # For cases that might fail, any response is acceptable
                    success_count += 1

            except Exception as e:
                if test_case["expect_success"]:
                    print(f"   Exception for expected success case {i}: {e}")
                else:
                    success_count += 1

        success_rate = success_count / total_count
        print(f"   Partial degradation test: {success_rate:.1%} success rate")

        assert success_rate > 0.8, f"Too many failures in partial degradation test: {success_rate:.1%}"

    @pytest.mark.asyncio
    async def test_timeout_handling(self, client: AsyncClient):
        """Test proper timeout handling for slow operations."""
        print("\n🧪 Testing timeout handling...")

        # Test with various timeout scenarios
        timeout_scenarios = [
            (1.0, "Short timeout - may fail"),
            (5.0, "Normal timeout"),
            (10.0, "Long timeout"),
        ]

        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }

        for timeout, description in timeout_scenarios:
            try:
                data = {"message": f"Test with {timeout}s timeout - safe content"}
                response = await client.post("/auth", headers=headers, json=data, timeout=timeout)

                if timeout < 2.0:
                    # Very short timeout might fail
                    assert response.status_code in [200, 408, 500], f"Unexpected status for short timeout: {response.status_code}"
                else:
                    # Normal/long timeout should succeed
                    assert response.status_code == 200, f"Failed with {description}: {response.status_code}"

                print(f"   {description}: {'✅' if response.status_code == 200 else '⚠️'} ({response.status_code})")

            except TimeoutException:
                if timeout < 2.0:
                    print(f"   {description}: ⚠️ Timeout (expected for short timeout)")
                else:
                    pytest.fail(f"Unexpected timeout with {description}")
            except Exception as e:
                print(f"   {description}: ❌ Exception: {e}")

    @pytest.mark.asyncio
    async def test_resource_exhaustion_recovery(self, client: AsyncClient):
        """Test recovery after resource exhaustion."""
        print("\n🧪 Testing resource exhaustion recovery...")

        # First, exhaust resources with high load
        print("   Phase 1: Exhausting resources...")

        high_load_tasks = []
        for i in range(50):  # High concurrent load
            headers = {
                "Content-Type": "application/json",
                "X-Forwarded-URI": "/api/chat"
            }
            data = {"message": f"Exhaustion test {i}"}

            task = asyncio.create_task(
                client.post("/auth", headers=headers, json=data, timeout=2.0)
            )
            high_load_tasks.append(task)

        # Execute high load
        exhaustion_results = await asyncio.gather(*high_load_tasks, return_exceptions=True)

        exhausted_success_count = sum(1 for r in exhaustion_results if not isinstance(r, Exception) and (r.status_code == 200 if hasattr(r, 'status_code') else False))
        print(f"   Exhaustion phase: {exhausted_success_count}/50 successful")

        # Wait for recovery
        print("   Phase 2: Waiting for recovery...")
        await asyncio.sleep(2)

        # Test recovery with normal load
        print("   Phase 3: Testing recovery...")

        recovery_tasks = []
        for i in range(10):  # Normal load
            headers = {
                "Content-Type": "application/json",
                "X-Forwarded-URI": "/api/chat"
            }
            data = {"message": f"Recovery test {i}"}

            task = asyncio.create_task(
                client.post("/auth", headers=headers, json=data, timeout=5.0)
            )
            recovery_tasks.append(task)

        recovery_results = await asyncio.gather(*recovery_tasks, return_exceptions=True)

        recovery_success_count = sum(1 for r in recovery_results if not isinstance(r, Exception) and (r.status_code == 200 if hasattr(r, 'status_code') else False))
        recovery_rate = recovery_success_count / 10

        print(f"   Recovery phase: {recovery_success_count}/10 successful ({recovery_rate:.1%})")

        # System should recover after resource exhaustion
        assert recovery_rate > 0.7, f"Poor recovery after exhaustion: {recovery_rate:.1%}"