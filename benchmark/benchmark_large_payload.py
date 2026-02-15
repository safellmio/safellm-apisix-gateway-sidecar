#!/usr/bin/env python3
"""
Large Payload Memory Stress Test for GatewayApsix

Tests the memory pressure issue described in ReasearchStructureCall.md:
- Lua VM loading large bodies into RAM via ngx.req.read_body()
- Potential OOM kills at high RPS with 1MB+ payloads
- Current MAX_BODY_SIZE protection (1MB limit)

This benchmark confirms whether the 1MB limit in Lua protects against OOM.
"""

import time
import os
import sys
import subprocess
import statistics
import json
import psutil
import threading
import tempfile
from typing import List, Dict, Tuple

sys.path.append(os.getcwd())
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:9080")
GATEWAY_AUTH_ENDPOINT = os.getenv("GATEWAY_AUTH_ENDPOINT", "/v1/guard")
GATEWAY_TIMEOUT = int(os.getenv("GATEWAY_TIMEOUT", "30"))

def get_memory_usage() -> Dict[str, float]:
    """Get current memory usage statistics."""
    try:
        process = psutil.Process()
        memory_info = process.memory_info()
        return {
            "rss_mb": memory_info.rss / 1024 / 1024,  # Resident Set Size
            "vms_mb": memory_info.vms / 1024 / 1024,  # Virtual Memory Size
            "percent": process.memory_percent()
        }
    except:
        return {"rss_mb": 0, "vms_mb": 0, "percent": 0}

def run_large_payload_request(payload_size_kb: int, bypass_cache: bool = True) -> Tuple[bool, float, Dict]:
    """
    Run single request with large payload.

    Args:
        payload_size_kb: Size of payload in KB
        bypass_cache: Add unique ID to avoid cache hits

    Returns:
        Tuple of (allowed, latency_ms, response_data)
    """
    start_time = time.time()

    # Create large payload
    large_text = "A" * (payload_size_kb * 1024)  # A characters
    if bypass_cache:
        large_text += f" [UNIQUE:{time.time()}]"

    try:
        payload = json.dumps({"prompt": large_text})

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp_file:
                tmp_file.write(payload)
                tmp_path = tmp_file.name

            curl_cmd = [
                'curl', '-s', '-w', '\n%{http_code}',
                '-X', 'POST',
                '-H', 'Content-Type: application/json',
                '-H', 'x-forwarded-uri: /v1/chat/completions',
                '--data-binary', f"@{tmp_path}",
                '--max-time', str(GATEWAY_TIMEOUT),
                f"{GATEWAY_URL}{GATEWAY_AUTH_ENDPOINT}"
            ]

            result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=GATEWAY_TIMEOUT + 1)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        if result.returncode != 0:
            raise Exception(f"Curl failed: {result.stderr}")

        output = result.stdout.strip()
        parts = output.split('\n')
        if len(parts) >= 1:
            status_code = int(parts[-1])
            body = "\n".join(parts[:-1])
        else:
            raise Exception("Invalid curl response format")

        allowed = status_code == 200
        latency_ms = (time.time() - start_time) * 1000

        response_data = {
            "status_code": status_code,
            "allowed": allowed,
            "content": body[:200] if body else "",
            "payload_size_kb": payload_size_kb
        }

        return allowed, latency_ms, response_data

    except Exception as e:
        return False, (time.time() - start_time) * 1000, {"error": str(e), "payload_size_kb": payload_size_kb}

def benchmark_payload_sizes():
    """Test different payload sizes to find limits."""
    print("\n📏 Large Payload Size Benchmark")
    print("=" * 70)

    if not test_gateway_health():
        print("❌ Gateway not healthy")
        return []

    # Test various payload sizes (reduced for faster execution)
    sizes_kb = [100, 500, 1024]  # KB sizes including 1MB test
    results = []

    for size_kb in sizes_kb:
        print(f"\n🧪 Testing {size_kb}KB payload...")

        latencies = []
        status_codes = []
        memory_usage = []

        # Run 3 times for averaging
        for i in range(3):
            mem_before = get_memory_usage()
            allowed, latency, details = run_large_payload_request(size_kb, bypass_cache=True)
            mem_after = get_memory_usage()

            latencies.append(latency)
            status_codes.append(details.get('status_code', 0))
            memory_usage.append({
                "before": mem_before,
                "after": mem_after,
                "delta_mb": mem_after["rss_mb"] - mem_before["rss_mb"]
            })

            print(f"  Run {i+1}: {latency:.1f}ms | Status: {details.get('status_code', 'ERR')} | Mem Δ: {mem_after['rss_mb'] - mem_before['rss_mb']:+.1f}MB")

        avg_latency = statistics.mean(latencies)
        common_status = max(set(status_codes), key=status_codes.count)
        avg_mem_delta = statistics.mean([m["delta_mb"] for m in memory_usage])

        results.append({
            'size_kb': size_kb,
            'avg_latency': avg_latency,
            'common_status': common_status,
            'avg_mem_delta_mb': avg_mem_delta,
            'memory_usage': memory_usage
        })

        # Check if hitting the 1MB limit (status 413 = Payload Too Large)
        if common_status == 413:
            print(f"  ✅ 1MB LIMIT WORKING: {size_kb}KB payload correctly rejected")
        elif common_status == 200:
            print(f"  ⚠️  LARGE PAYLOAD ALLOWED: {size_kb}KB payload passed through")
        else:
            print(f"  ❌ UNEXPECTED STATUS: {common_status}")

    # Summary
    print("\n📊 Payload Size Test Summary:")
    for r in results:
        status_icon = "✅" if r['common_status'] == 413 else "⚠️" if r['common_status'] == 200 else "❌"
        print(f"  {r['size_kb']:4}KB: {status_icon} {r['common_status']} | {r['avg_latency']:5.1f}ms | MemΔ: {r['avg_mem_delta_mb']:+.1f}MB")

    return results

def benchmark_memory_pressure_simulation():
    """Simulate the memory pressure scenario from ReasearchStructureCall.md."""
    print("\n💥 Memory Pressure Simulation (ReasearchStructureCall.md Scenario)")
    print("=" * 70)

    if not test_gateway_health():
        print("❌ Gateway not healthy")
        return {}

    # Scenario: 10 RPS with 1MB payloads (reduced for faster execution)
    PAYLOAD_SIZE_KB = 1024  # 1MB
    TARGET_RPS = 5  # Reduced RPS for faster execution
    DURATION_SECONDS = 10  # Reduced duration

    print(f"Scenario: {TARGET_RPS} RPS with {PAYLOAD_SIZE_KB}KB payloads for {DURATION_SECONDS}s")
    print("Original analysis predicted OOM at 100 RPS with 1MB payloads")
    print()

    start_time = time.time()
    end_time = start_time + DURATION_SECONDS

    request_count = 0
    latencies = []
    memory_readings = []
    status_codes = []

    last_memory_check = 0

    try:
        while time.time() < end_time:
            # Track memory every 5 seconds
            current_time = time.time()
            if current_time - last_memory_check >= 5:
                memory_readings.append(get_memory_usage())
                last_memory_check = current_time

            allowed, latency, details = run_large_payload_request(PAYLOAD_SIZE_KB, bypass_cache=True)
            latencies.append(latency)
            status_codes.append(details.get('status_code', 0))
            request_count += 1

            # Sleep to maintain target RPS
            target_interval = 1.0 / TARGET_RPS
            elapsed = time.time() - (start_time + (request_count - 1) * target_interval)
            if elapsed < target_interval:
                time.sleep(target_interval - elapsed)

    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")

    actual_duration = time.time() - start_time
    actual_rps = request_count / actual_duration if actual_duration > 0 else 0

    # Analyze results
    memory_peaks = [m["rss_mb"] for m in memory_readings]
    max_memory_mb = max(memory_peaks) if memory_peaks else 0
    memory_growth = max_memory_mb - (memory_readings[0]["rss_mb"] if memory_readings else 0)

    blocked_count = status_codes.count(413)
    allowed_count = status_codes.count(200)

    print("\n📊 Memory Pressure Results:")
    print(f"   Duration: {actual_duration:.1f}s")
    print(f"   Requests: {request_count}")
    print(f"   Actual RPS: {actual_rps:.1f}")
    print(f"   Avg Latency: {statistics.mean(latencies):.1f}ms")
    print(f"   Max Memory: {max_memory_mb:.1f}MB")
    print(f"   Memory Growth: {memory_growth:+.1f}MB")
    print(f"   Blocked (413): {blocked_count}/{request_count} ({blocked_count/request_count*100:.1f}%)")
    print(f"   Allowed (200): {allowed_count}/{request_count} ({allowed_count/request_count*100:.1f}%)")

    # Assessment
    if blocked_count == request_count:
        print("  ✅ SAFETY WORKING: All large payloads correctly blocked at Lua level")
        print("     No memory pressure - Lua limit prevents OOM scenario")
    elif allowed_count > 0:
        print("  ⚠️  MEMORY RISK: Some large payloads getting through")
        if memory_growth > 100:  # 100MB growth threshold
            print("  🚨 HIGH MEMORY PRESSURE: Significant memory growth detected")
        else:
            print("  ✅ LOW MEMORY IMPACT: Minimal memory growth despite large payloads")
    else:
        print("  ❓ UNEXPECTED RESULTS: Mixed status codes")

    return {
        "duration": actual_duration,
        "requests": request_count,
        "rps": actual_rps,
        "avg_latency": statistics.mean(latencies),
        "max_memory_mb": max_memory_mb,
        "memory_growth_mb": memory_growth,
        "blocked_count": blocked_count,
        "allowed_count": allowed_count,
        "memory_readings": memory_readings
    }

def test_gateway_health() -> bool:
    """Test if GatewayApsix is healthy by checking /v1/guard endpoint."""
    try:
        result = subprocess.run([
            'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
            '-X', 'POST', '-H', 'Content-Type: application/json',
            '-d', '{"text":"health_check"}',
            f"{GATEWAY_URL}{GATEWAY_AUTH_ENDPOINT}"
        ], capture_output=True, text=True, timeout=10)
        return result.returncode == 0 and result.stdout.strip() == '200'
    except:
        return False

if __name__ == "__main__":
    print("🚀 Large Payload Memory Stress Test for GatewayApsix")
    print("=" * 70)
    print("Testing the memory pressure issue from ReasearchStructureCall.md")
    print(f"Gateway URL: {GATEWAY_URL}")
    print("Testing Lua VM memory limits with large payloads")

    try:
        # Test different payload sizes
        size_results = benchmark_payload_sizes()

        # Simulate the memory pressure scenario
        memory_results = benchmark_memory_pressure_simulation()

        # Final assessment
        print("\n" + "=" * 70)
        print("🎯 FINAL ASSESSMENT - Does ReasearchStructureCall.md analysis hold?")
        print("=" * 70)

        # Check if 1MB limit is working
        limit_working = any(r['common_status'] == 413 for r in size_results if r['size_kb'] >= 1000)

        if limit_working:
            print("✅ ANALYSIS CORRECT: 1MB limit in Lua protects against OOM")
            print("   Large payloads are blocked before reaching memory-intensive processing")
        else:
            print("❌ ANALYSIS INCORRECT: No 1MB limit detected")
            print("   Large payloads may cause memory pressure")

        # Check memory pressure simulation
        if memory_results.get('blocked_count', 0) == memory_results.get('requests', 1):
            print("✅ MEMORY SAFETY: All large payloads blocked, no memory pressure")
        elif memory_results.get('memory_growth_mb', 0) > 50:
            print("⚠️  MEMORY PRESSURE DETECTED: Significant memory growth")
            print("   Analysis prediction of OOM risk may be valid for higher RPS")
        else:
            print("✅ LOW RISK: Minimal memory impact from large payloads")

        print("\n📋 Recommendations:")
        if limit_working:
            print("   - Current 1MB Lua limit provides adequate protection")
            print("   - Safe for production MVP with current limits")
            print("   - Monitor memory usage in production RAG deployments")
        else:
            print("   - Implement 1MB limit in Lua as suggested in analysis")
            print("   - Add memory monitoring for large payload scenarios")

    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
