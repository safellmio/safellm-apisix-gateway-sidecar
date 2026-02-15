"""Concurrency and Scaling Tests - E2E Scenarios"""
import asyncio
import time
import hashlib
import pytest
from typing import List
from httpx import AsyncClient


class TestConcurrencyScaling:
    """Test concurrency and scaling scenarios."""

    def _simulate_scan_operation(self, prompt: str) -> str:
        """Simulate a security scan operation with realistic delay."""
        import time
        time.sleep(0.01)  # Simulate processing time
        return f"scan_result_{hashlib.md5(prompt.encode()).hexdigest()[:8]}"

    async def _mock_async_scan_operation(self, prompt: str) -> str:
        """Async version for coalescer testing."""
        await asyncio.sleep(0.01)  # Simulate async processing time
        return f"scan_result_{hashlib.md5(prompt.encode()).hexdigest()[:8]}"

    @pytest.mark.asyncio
    async def test_request_coalescing_single_worker(self, client: AsyncClient):
        """Test request coalescing with identical concurrent requests."""
        # This test simulates what happens in the sidecar's request coalescer
        # Since we're testing the sidecar directly, we'll test the logic

        from sidecar.services.request_coalescer import RequestCoalescer

        coalescer = RequestCoalescer()
        await coalescer.start()  # Start cleanup task

        # Test coalescing with identical requests
        request_hash = "test_hash_identical"
        prompt = "identical test prompt"

        start_time = time.time()

        # Send 10 identical requests concurrently
        tasks = []
        for i in range(10):
            task = asyncio.create_task(
                coalescer.coalesce(request_hash, lambda: self._mock_async_scan_operation(prompt))
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks)
        total_time = time.time() - start_time

        # All results should be identical (coalesced to single scan)
        assert len(set(results)) == 1, "All results should be identical"
        assert results[0] == f"scan_result_{hashlib.md5(prompt.encode()).hexdigest()[:8]}"

        # Should complete much faster than 10 * 0.01 = 0.1s
        assert total_time < 0.05, f"Coalescing too slow: {total_time:.3f}s"

        print(f"   Coalesced 10 requests in {total_time:.3f}s")
        await coalescer.shutdown()

    @pytest.mark.asyncio
    async def test_request_coalescing_different_requests(self, client: AsyncClient):
        """Test that different requests are not coalesced."""
        from sidecar.services.request_coalescer import RequestCoalescer

        coalescer = RequestCoalescer()
        await coalescer.start()

        # Different prompts should not be coalesced
        prompts = [f"different prompt {i}" for i in range(5)]
        hashes = [f"hash_{i}" for i in range(5)]

        start_time = time.time()

        tasks = []
        for prompt, hash_val in zip(prompts, hashes):
            task = asyncio.create_task(
                coalescer.coalesce(hash_val, lambda p=prompt: self._mock_async_scan_operation(p))
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks)
        total_time = time.time() - start_time

        # All results should be different
        assert len(set(results)) == 5, "Different requests should produce different results"

        # Should take ~0.01s (all 5 scans run concurrently)
        assert total_time < 0.05, f"Too slow: {total_time:.3f}s"

        await coalescer.shutdown()

    @pytest.mark.asyncio
    async def test_multi_worker_coalescing_limitation(self, client: AsyncClient):
        """Document and test the multi-worker coalescing limitation."""
        # This test documents the limitation that coalescing works per-worker only
        # In a real multi-worker setup, each worker would have its own coalescer

        from sidecar.services.request_coalescer import RequestCoalescer

        # Simulate multiple workers (each with their own coalescer)
        workers = [RequestCoalescer() for _ in range(4)]

        for worker in workers:
            await worker.start()

        request_hash = "shared_hash"
        prompt = "shared prompt across workers"

        start_time = time.time()

        # Simulate load balancer distributing requests across workers
        tasks = []
        for i, worker in enumerate(workers):
            # Each worker gets some requests (simulating load balancer distribution)
            for j in range(3):  # 3 requests per worker = 12 total
                task = asyncio.create_task(
                    worker.coalesce(request_hash, lambda w=i: self._mock_async_scan_operation(f"{prompt}_worker_{w}"))
                )
                tasks.append(task)

        results = await asyncio.gather(*tasks)
        total_time = time.time() - start_time

        # In multi-worker scenario: each worker does its own coalescing
        # So we get 4 different results (one per worker) instead of 1
        unique_results = set(results)
        assert len(unique_results) == 4, f"Expected 4 unique results (per worker), got {len(unique_results)}"

        # Time should be ~0.01s (all scans run concurrently)
        assert total_time < 0.05, f"Too slow: {total_time:.3f}s"

        print(f"   Multi-worker scenario: {len(unique_results)} unique scans performed")

        for worker in workers:
            await worker.shutdown()

    @pytest.mark.asyncio
    async def test_concurrent_load_simulation(self, client: AsyncClient):
        """Simulate concurrent load to test system behavior."""
        # Test with various concurrency levels
        concurrency_levels = [1, 5, 10, 20]

        for concurrency in concurrency_levels:
            start_time = time.time()

            # Create concurrent requests
            tasks = []
            for i in range(concurrency):
                headers = {
                    "Content-Type": "application/json",
                    "X-Forwarded-URI": "/api/chat"
                }
                data = {"message": f"Safe test message {i}"}

                # Note: This tests the FastAPI app directly, not through coalescer
                # In real scenario, APISIX would distribute requests
                task = asyncio.create_task(
                    client.post("/auth", headers=headers, json=data)
                )
                tasks.append(task)

            responses = await asyncio.gather(*tasks)
            total_time = time.time() - start_time

            # Check that most requests succeed
            success_count = sum(1 for r in responses if r.status_code == 200)
            success_rate = success_count / concurrency

            print(f"   Concurrency {concurrency}: {success_rate:.1%} success rate in {total_time:.3f}s")

            # Should handle reasonable concurrency
            if concurrency <= 10:
                assert success_rate > 0.9, f"Low success rate at concurrency {concurrency}: {success_rate:.1%}"
            else:
                # Higher concurrency may have some failures
                assert success_rate > 0.7, f"Very low success rate at high concurrency {concurrency}: {success_rate:.1%}"

    @pytest.mark.asyncio
    async def test_request_coalescing_cleanup(self, client: AsyncClient):
        """Test that coalesced requests are properly cleaned up."""
        from sidecar.services.request_coalescer import RequestCoalescer

        coalescer = RequestCoalescer()
        await coalescer.start()

        # Add some coalesced requests
        request_hash = "cleanup_test"
        tasks = []
        for i in range(3):
            task = asyncio.create_task(
                coalescer.coalesce(request_hash, lambda idx=i: self._mock_async_scan_operation(f"cleanup_test_{idx}"))
            )
            tasks.append(task)

        await asyncio.gather(*tasks)

        # Wait for cleanup (default cleanup delay is 0.1s)
        await asyncio.sleep(0.2)

        # Pending requests should be cleaned up
        assert request_hash not in coalescer._pending_requests, "Request should be cleaned up"

        await coalescer.shutdown()