"""
Request Coalescer Service - Deduplicate concurrent identical requests.

This service prevents redundant processing of identical security scans by
coalescing concurrent requests for the same content. When multiple users
submit the same prompt simultaneously, only one scan is performed and all
waiting requests get the result.

Benefits:
- Reduces CPU usage for repetitive queries
- Improves throughput for common prompts
- Prevents redundant AI model inferences

Usage:
    coalescer = RequestCoalescer()
    await coalescer.start()  # Start cleanup task
    result = await coalescer.coalesce(request_hash, scan_coroutine)

⚠️ MULTI-WORKER LIMITATION:
    This implementation uses asyncio.Lock which only works within a single process.
    When running with multiple workers (e.g., Granian --workers 4 or Kubernetes pods):
    
    - Each worker has its OWN independent pending_requests dictionary
    - Deduplication only works for requests hitting the SAME worker
    - 4 workers = up to 4× duplicate scans for identical prompts
    - "Thundering herd" protection is LOCAL, not GLOBAL
    
    This is acceptable for single-worker deployments and development.
"""

import asyncio
import hashlib
from typing import Dict, Callable, Awaitable, Any, Optional, Set
import time


class RequestCoalescer:
    """
    Coalesce concurrent identical requests to prevent redundant processing.

    This is especially useful for LLM security scanning where the same prompts
    are often submitted by multiple users simultaneously.
    """

    def __init__(self, max_pending: int = 1000, cleanup_interval: int = 60):
        """
        Initialize request coalescer.

        Args:
            max_pending: Maximum number of pending requests before cleanup
            cleanup_interval: Seconds between cleanup of expired requests
        """
        self._pending_requests: Dict[str, asyncio.Future] = {}
        self._pending_lock = asyncio.Lock()
        self._max_pending = max_pending
        self._cleanup_interval = cleanup_interval
        self._cleanup_task: Optional[asyncio.Task] = None
        self._delayed_cleanup_tasks: Set[asyncio.Task] = set()
        self._started = False

    async def start(self):
        """Start the cleanup background task. Call this after event loop is running."""
        if not self._started:
            self._cleanup_task = asyncio.create_task(self._cleanup_expired())
            self._started = True

    def _hash_request(self, request_data: Any) -> str:
        """Generate hash for request deduplication."""
        if isinstance(request_data, str):
            return hashlib.sha256(request_data.encode('utf-8')).hexdigest()
        else:
            request_str = str(request_data)
            return hashlib.sha256(request_str.encode('utf-8')).hexdigest()

    async def coalesce(
        self, 
        request_hash: str, 
        request_func: Callable[[], Awaitable[Any]]
    ) -> Any:
        """
        Coalesce concurrent requests for the same hash.

        Args:
            request_hash: Unique identifier for the request (e.g., prompt hash)
            request_func: Async callable to execute if this is the first request

        Returns:
            Result of the request execution
        
        Example:
            async def scan_prompt():
                return await pipeline.scan(prompt)
            
            result = await coalescer.coalesce(hash, scan_prompt)
        """
        # Lazy start cleanup task if not started
        if not self._started:
            await self.start()

        async with self._pending_lock:
            # Check if we already have a pending request for this hash
            if request_hash in self._pending_requests:
                # Capture future under lock, await outside lock
                existing_future = self._pending_requests[request_hash]
                # Release lock before awaiting to avoid deadlock
            else:
                existing_future = None

        # If there's an existing future, wait for it outside the lock
        if existing_future is not None:
            try:
                return await existing_future
            except Exception:
                # If the original failed, let caller handle retry
                raise

        # This is the first request for this hash
        future: asyncio.Future = asyncio.Future()

        async with self._pending_lock:
            # Double-check after acquiring lock (another coroutine may have created it)
            if request_hash in self._pending_requests:
                existing_future = self._pending_requests[request_hash]
            else:
                self._pending_requests[request_hash] = future
                existing_future = None

        if existing_future is not None:
            # Someone else created it while we were waiting
            return await existing_future

        try:
            # Execute the actual request function (call the callable)
            result = await request_func()

            # Signal success to all waiting requests
            if not future.done():
                future.set_result(result)

            # Schedule cleanup after short delay
            delayed_task = asyncio.create_task(self._delayed_cleanup(request_hash, 0.1))
            self._delayed_cleanup_tasks.add(delayed_task)
            delayed_task.add_done_callback(self._delayed_cleanup_tasks.discard)

            return result

        except Exception as e:
            # Signal failure to all waiting requests
            if not future.done():
                future.set_exception(e)

            # Clean up immediately on failure
            async with self._pending_lock:
                self._pending_requests.pop(request_hash, None)

            raise

    async def _delayed_cleanup(self, request_hash: str, delay: float):
        """Clean up completed request after delay."""
        try:
            await asyncio.sleep(delay)
            async with self._pending_lock:
                self._pending_requests.pop(request_hash, None)
        except asyncio.CancelledError:
            raise

    async def _cleanup_expired(self):
        """Periodically clean up expired pending requests."""
        while True:
            try:
                await asyncio.sleep(self._cleanup_interval)

                async with self._pending_lock:
                    # Remove completed futures
                    expired_hashes = [
                        h for h, f in self._pending_requests.items() 
                        if f.done()
                    ]
                    for h in expired_hashes:
                        self._pending_requests.pop(h, None)

                    # Prevent unbounded growth
                    if len(self._pending_requests) > self._max_pending:
                        # Cancel oldest entries
                        hashes_to_remove = list(self._pending_requests.keys())[:100]
                        for h in hashes_to_remove:
                            future = self._pending_requests.pop(h, None)
                            if future and not future.done():
                                future.cancel()

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"RequestCoalescer cleanup error: {e}")
                continue

    def get_stats(self) -> Dict:
        """Get coalescer statistics."""
        pending = len(self._pending_requests)
        return {
            "pending_requests": pending,
            "max_pending": self._max_pending,
            "cleanup_interval": self._cleanup_interval,
            "started": self._started
        }

    async def shutdown(self):
        """Gracefully shutdown the coalescer."""
        delayed_tasks = list(self._delayed_cleanup_tasks)
        for task in delayed_tasks:
            if not task.done():
                task.cancel()
        if delayed_tasks:
            await asyncio.gather(*delayed_tasks, return_exceptions=True)

        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Cancel all pending requests
        async with self._pending_lock:
            for future in self._pending_requests.values():
                if not future.done():
                    future.cancel()
            self._pending_requests.clear()

        self._delayed_cleanup_tasks.clear()
        self._started = False
