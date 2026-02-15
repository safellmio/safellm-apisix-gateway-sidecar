
"""Locust load testing scenarios for SafeLLM Gateway."""

import time
from locust import HttpUser, task, between
import random
import string


class SafeLLMUser(HttpUser):
    """Load testing user for SafeLLM Gateway."""

    wait_time = between(0.1, 1.0)  # Random wait between requests

    def generate_massive_text(self, size_mb: int = 1) -> str:
        """Generate text with many keywords for Slowloris-style testing."""
        keywords = [
            "password", "secret", "token", "api_key", "credit_card",
            "social_security", "ssn", "confidential", "private", "sensitive"
        ]

        # Generate approximately size_mb MB of text
        target_chars = size_mb * 1024 * 1024
        text_parts = []

        while len(" ".join(text_parts)) < target_chars:
            # Create text with many keyword variations
            part = " ".join([f"{kw}_{random.randint(1, 1000)}" for kw in keywords for _ in range(50)])
            text_parts.append(part)

        return " ".join(text_parts)[:target_chars]

    @task(3)  # 30% of requests
    def normal_request(self):
        """Normal safe request."""
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }
        data = {
            "message": f"Normal safe message {random.randint(1, 1000)}"
        }

        with self.client.post("/auth", json=data, headers=headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Status code: {response.status_code}")

    @task(1)  # 10% of requests - massive keyword search
    def slowloris_keyword_attack(self):
        """Slowloris-style keyword attack with massive text."""
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }

        # Generate massive text (truncated for API limits)
        massive_text = self.generate_massive_text(0.5)[:50000]  # 50KB limit
        data = {
            "message": f"Slowloris attack: {massive_text}"
        }

        start_time = time.time()
        with self.client.post("/auth", json=data, headers=headers, timeout=30, catch_response=True) as response:
            latency = time.time() - start_time

            if response.status_code == 200:
                response.success()
            elif latency > 25:  # Allow some slow responses but not timeouts
                response.failure(f"Too slow: {latency:.2f}s")
            else:
                response.failure(f"Status code: {response.status_code}")

    @task(1)  # 10% of requests - health checks
    def health_check(self):
        """Health endpoint monitoring."""
        start_time = time.time()
        with self.client.get("/health", catch_response=True) as response:
            latency = (time.time() - start_time) * 1000  # ms

            if response.status_code == 200 and latency < 100:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}, {latency:.1f}ms")


class ConcurrencyRaceUser(HttpUser):
    """Specialized user for testing request coalescing race conditions."""

    wait_time = between(0.001, 0.005)  # Very fast requests

    @task
    def identical_request_race(self):
        """Send identical requests to test coalescing."""
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-URI": "/api/chat"
        }

        # Always use the same message to test coalescing
        data = {
            "message": "IDENTICAL_RACE_CONDITION_TEST_MESSAGE_FOR_COALESCING"
        }

        with self.client.post("/auth", json=data, headers=headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Race condition request failed: {response.status_code}")
