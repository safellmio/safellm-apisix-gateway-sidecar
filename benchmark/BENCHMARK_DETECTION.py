#!/usr/bin/env python3
"""
False Positive Detection Benchmark

Advanced security testing focused on false positive analysis.
Tests GatewayApsix against datasets specifically designed to trigger
false positives and analyzes patterns in security failures.

Critical for user experience: False positives frustrate legitimate users
and reduce system usability.

Target: <5% false positive rate while maintaining security
Platform: CPU-only (AMD Ryzen 5 PRO 3600, 6 threads, 12GB RAM)
"""

import time
import os
import sys
import subprocess
import statistics
import json
import uuid
import pandas as pd
from typing import List, Dict, Tuple, Optional
from pathlib import Path
from collections import defaultdict
import csv

sys.path.append(os.getcwd())
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:9080")
GATEWAY_AUTH_ENDPOINT = os.getenv("GATEWAY_AUTH_ENDPOINT", "/v1/guard")
GATEWAY_HEALTH_ENDPOINT = os.getenv("GATEWAY_HEALTH_ENDPOINT", "/health")
GATEWAY_TIMEOUT = int(os.getenv("GATEWAY_TIMEOUT", "10"))

class FalsePositiveAnalyzer:
    """Advanced analyzer for false positive patterns and root causes."""

    def __init__(self):
        self.false_positives = []
        self.patterns = defaultdict(list)
        self.categories = defaultdict(int)

    def add_false_positive(self, prompt: str, latency: float, category: str = "unknown",
                          expected_reason: str = ""):
        """Add a false positive case for analysis."""
        self.false_positives.append({
            'prompt': prompt,
            'latency': latency,
            'category': category,
            'expected_reason': expected_reason,
            'timestamp': time.time()
        })

        # Analyze patterns
        words = prompt.lower().split()
        for word in words:
            if len(word) > 3:  # Skip short words
                self.patterns[word].append(prompt)

        self.categories[category] += 1

    def analyze_patterns(self) -> Dict:
        """Analyze false positive patterns and return insights."""
        if not self.false_positives:
            return {"no_false_positives": True}

        # Find most common trigger words
        trigger_words = {}
        for word, prompts in self.patterns.items():
            if len(prompts) >= 2:  # Words that appear in multiple false positives
                trigger_words[word] = len(prompts)

        # Category breakdown
        category_breakdown = dict(self.categories)

        # Latency analysis
        latencies = [fp['latency'] for fp in self.false_positives]
        latency_stats = {
            'avg': statistics.mean(latencies),
            'p95': statistics.quantiles(latencies, n=20)[18] if latencies else 0,
            'max': max(latencies) if latencies else 0
        }

        return {
            'total_false_positives': len(self.false_positives),
            'top_trigger_words': sorted(trigger_words.items(), key=lambda x: x[1], reverse=True)[:10],
            'category_breakdown': category_breakdown,
            'latency_stats': latency_stats,
            'patterns_found': len(trigger_words)
        }

def test_gateway_health() -> bool:
    """Test if GatewayApsix is healthy."""
    try:
        result = subprocess.run([
            'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
            f"{GATEWAY_URL}{GATEWAY_HEALTH_ENDPOINT}"
        ], capture_output=True, text=True, timeout=5)
        return result.stdout.strip() == '200'
    except:
        return False

def run_single_request(prompt: str, bypass_cache: bool = True) -> Tuple[bool, float, Dict]:
    """
    Run single security check request.

    Args:
        prompt: Text to check for security issues
        bypass_cache: If True, adds unique ID to avoid cache hits

    Returns:
        Tuple of (allowed, latency_ms, response_data)
    """
    start_time = time.time()

    # Add unique ID to bypass cache if requested
    unique_prompt = prompt
    if bypass_cache:
        unique_prompt = f"{prompt} [ID:{uuid.uuid4().hex[:6]}]"

    try:
        # Prepare JSON payload
        payload = json.dumps({"text": unique_prompt})

        # Use curl to make request
        curl_cmd = [
            'curl', '-s', '-w', '\n%{http_code}',
            '-X', 'POST',
            '-H', 'Content-Type: application/json',
            '-H', 'x-forwarded-uri: /v1/chat/completions',
            '-d', payload,
            '--max-time', str(GATEWAY_TIMEOUT),
            f"{GATEWAY_URL}{GATEWAY_AUTH_ENDPOINT}"
        ]

        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=GATEWAY_TIMEOUT + 1)

        if result.returncode != 0:
            raise Exception(f"Curl failed: {result.stderr}")

        # Parse curl output: body\nstatus_code (status code is last line)
        output = result.stdout.strip()
        parts = output.split('\n')
        if len(parts) >= 1:
            status_code = int(parts[-1])
            body = "\n".join(parts[:-1])
        else:
            raise Exception("Invalid curl response format")

        # Parse response
        allowed = status_code == 200
        latency_ms = (time.time() - start_time) * 1000

        response_data = {
            "status_code": status_code,
            "allowed": allowed,
            "headers": {},
            "content": body[:200] if body else ""
        }

        return allowed, latency_ms, response_data

    except Exception as e:
        return False, (time.time() - start_time) * 1000, {"error": str(e)}

def load_false_positive_dataset() -> List[Tuple[str, str, str]]:
    """
    Load dataset specifically designed for false positive testing.

    Returns:
        List of (prompt, category, description) tuples
    """
    datasets = [
        "datasets/edge_cases_false_positives.csv",
        "datasets/known_false_positives.csv",
        "datasets/latency_safe_prompts.csv"
    ]

    all_data = []

    for dataset_file in datasets:
        if not os.path.exists(dataset_file):
            print(f"⚠️  Dataset file not found: {dataset_file}")
            continue

        try:
            df = pd.read_csv(dataset_file)

            # Handle different CSV formats
            if 'category' in df.columns and 'description' in df.columns:
                # Full format with category and description
                for _, row in df.iterrows():
                    if str(row.get('expected', '')).lower() == 'safe':
                        prompt = str(row['prompt'])
                        category = str(row.get('category', 'unknown'))
                        description = str(row.get('description', ''))
                        all_data.append((prompt, category, description))
            else:
                # Simple format - just safe prompts
                for _, row in df.iterrows():
                    if str(row.get('expected', '')).lower() == 'safe':
                        prompt = str(row['prompt'])
                        category = 'general'
                        description = 'Safe prompt from dataset'
                        all_data.append((prompt, category, description))

        except Exception as e:
            print(f"❌ Error loading {dataset_file}: {e}")
            continue

    return all_data[:150]  # Limit for performance

def run_false_positive_analysis():
    """Run comprehensive false positive analysis."""
    print("🔍 False Positive Detection Benchmark")
    print("=" * 70)
    print(f"Gateway URL: {GATEWAY_URL}")
    print(f"Platform: CPU-only (AMD Ryzen 5 PRO 3600)")
    print(f"Critical Target: <5% False Positive Rate")
    print()

    if not test_gateway_health():
        print("❌ Gateway not healthy")
        return

    # Load test data
    print("📦 Loading false positive test datasets...")
    test_data = load_false_positive_dataset()
    print(f"✅ Loaded {len(test_data)} safe prompts for testing")
    print()

    # Initialize analyzer
    analyzer = FalsePositiveAnalyzer()

    results = []
    total_safe = len(test_data)

    print("🧪 Running false positive analysis...")
    print("   (All prompts should be ALLOWED - any BLOCK is a false positive)")
    print("-" * 70)

    for i, (prompt, category, description) in enumerate(test_data, 1):
        latencies = []

        # Run 3 times for reliable measurement
        for _ in range(3):
            allowed, latency, details = run_single_request(prompt, bypass_cache=True)
            latencies.append(latency)

        avg_latency = statistics.mean(latencies)

        if allowed:
            status = "✅ ALLOWED"
            is_false_positive = False
        else:
            status = "❌ FALSE_POSITIVE"
            is_false_positive = True
            analyzer.add_false_positive(prompt, avg_latency, category, description)

        results.append({
            'allowed': allowed,
            'avg_latency': avg_latency,
            'is_false_positive': is_false_positive,
            'category': category,
            'description': description
        })

        # Progress with details
        if i % 10 == 0 or i == total_safe or is_false_positive:
            fp_marker = " 🚨" if is_false_positive else ""
            print(f"  Progress: {i}/{total_safe} {status} {fp_marker}")

    # Calculate statistics
    false_positives = sum(1 for r in results if r['is_false_positive'])
    false_positive_rate = false_positives / total_safe * 100
    latencies = [r['avg_latency'] for r in results]

    print("\n📊 FALSE POSITIVE ANALYSIS RESULTS")
    print("=" * 70)
    print(f"   Total safe prompts tested: {total_safe}")
    print(f"   False positives detected: {false_positives}")
    print(f"   False positive rate: {false_positive_rate:.2f}%")
    print(f"   Success rate: {100 - false_positive_rate:.2f}%")

    print("\n⏱️  Performance Metrics:")
    print(f"   Average latency: {statistics.mean(latencies):.1f}ms")
    if latencies:
        print(f"   P95 latency: {statistics.quantiles(latencies, n=20)[18]:.1f}ms")
        print(f"   Max latency: {max(latencies):.1f}ms")

    # Detailed pattern analysis
    pattern_analysis = analyzer.analyze_patterns()

    if pattern_analysis.get('no_false_positives'):
        print("\n🎉 EXCELLENT: No false positives detected!")
        print("   The security system is perfectly calibrated for safe content.")
        return

    print("\n🔍 FALSE POSITIVE PATTERN ANALYSIS")
    print("=" * 70)

    print(f"   Total false positives: {pattern_analysis['total_false_positives']}")

    print("\n📈 Category Breakdown:")
    for category, count in pattern_analysis['category_breakdown'].items():
        percentage = count / pattern_analysis['total_false_positives'] * 100
        print(f"      {category}: {count} ({percentage:.1f}%)")

    if pattern_analysis.get('top_trigger_words'):
        print("\n🚨 Top Trigger Words (appearing in multiple false positives):")
        for word, count in pattern_analysis['top_trigger_words'][:8]:
            print(f"   '{word}': {count} occurrences")

    print("\n⏱️  False Positive Latency Analysis:")
    fp_latencies = pattern_analysis['latency_stats']
    print(f"   Average FP latency: {fp_latencies['avg']:.1f}ms")
    print(f"   P95 FP latency: {fp_latencies['p95']:.1f}ms")
    print(f"   Max FP latency: {fp_latencies['max']:.1f}ms")

    # Recommendations
    print("\n💡 RECOMMENDATIONS FOR IMPROVEMENT")
    print("=" * 70)

    if false_positive_rate > 10:
        print("   🚨 CRITICAL: High false positive rate detected")
        print("      - Consider lowering AI model threshold")
        print("      - Review keyword patterns for over-aggressiveness")
        print("      - Add more context-aware filtering")

    elif false_positive_rate > 5:
        print("   ⚠️  MODERATE: Some false positives need attention")
        print("      - Fine-tune detection thresholds")
        print("      - Add exception rules for common safe phrases")
        print("      - Implement whitelist for trusted patterns")

    else:
        print("   ✅ GOOD: False positive rate within acceptable range")
        print("      - Minor threshold adjustments may still help")
        print("      - Monitor for emerging patterns")

    if pattern_analysis.get('patterns_found', 0) > 5:
        print("   📝 PATTERN INSIGHT: Multiple words triggering false positives")
        print("      - Consider implementing phrase-level analysis")
        print("      - Add contextual disambiguation")

    if fp_latencies['avg'] > 200:
        print("   ⏱️  PERFORMANCE: High latency on false positives")
        print("      - Investigate why blocked requests take longer")
        print("      - Consider early exit optimizations")

    # Save detailed results for further analysis
    results_file = f"results/false_positive_analysis_{int(time.time())}.json"
    detailed_results = {
        'summary': {
            'total_tested': total_safe,
            'false_positives': false_positives,
            'false_positive_rate': false_positive_rate,
            'avg_latency': statistics.mean(latencies),
            'p95_latency': statistics.quantiles(latencies, n=20)[18] if latencies else 0
        },
        'pattern_analysis': pattern_analysis,
        'false_positive_details': analyzer.false_positives[:20],  # Top 20 for analysis
        'timestamp': time.time()
    }

    os.makedirs('results', exist_ok=True)
    with open(results_file, 'w') as f:
        json.dump(detailed_results, f, indent=2, default=str)

    print(f"\n💾 Detailed results saved to: {results_file}")

if __name__ == "__main__":
    try:
        run_false_positive_analysis()
    except KeyboardInterrupt:
        print("\n⏹️  Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Analysis failed with error: {e}")
        import traceback
        traceback.print_exc()
