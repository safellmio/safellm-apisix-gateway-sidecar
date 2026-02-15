#!/usr/bin/env python3
"""
DatasetBenchmark - Comprehensive Security Testing with Multiple Datasets

Tests GatewayApsix security performance across various datasets focusing on:
- False positive detection (critical for user experience)
- Accuracy across different content types
- Performance consistency
- Dataset-specific analysis

Target: Minimize false positives while maintaining security
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
import csv

sys.path.append(os.getcwd())
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:9080")
GATEWAY_AUTH_ENDPOINT = os.getenv("GATEWAY_AUTH_ENDPOINT", "/v1/guard")
GATEWAY_HEALTH_ENDPOINT = os.getenv("GATEWAY_HEALTH_ENDPOINT", "/health")
GATEWAY_TIMEOUT = int(os.getenv("GATEWAY_TIMEOUT", "10"))

# Dataset configurations
DATASET_CONFIGS = {
    "latency_safe": {
        "file": "GateWayApsix/safellm/tests/datasets/latency_safe_prompts.csv",
        "expected_col": "expected",
        "prompt_col": "prompt",
        "expected_value": "safe",
        "description": "Safe prompts for latency testing"
    },
    "latency_unsafe": {
        "file": "GateWayApsix/safellm/tests/datasets/latency_unsafe_prompts.csv",
        "expected_col": "expected",
        "prompt_col": "prompt",
        "expected_value": "unsafe",
        "description": "Unsafe prompts for latency testing"
    },
    "edge_cases_false_positives": {
        "file": "GateWayApsix/safellm/tests/datasets/edge_cases_false_positives.csv",
        "expected_col": "expected",
        "prompt_col": "prompt",
        "expected_value": "safe",
        "description": "Edge cases prone to false positives"
    },
    "known_false_positives": {
        "file": "GateWayApsix/safellm/tests/datasets/known_false_positives.csv",
        "expected_col": "expected",
        "prompt_col": "prompt",
        "expected_value": "safe",
        "description": "Known false positive cases from past testing"
    },
    "prompt_injections": {
        "file": "GateWayApsix/safellm/tests/datasets/prompt_injections.csv",
        "expected_col": "label",
        "prompt_col": "text",
        "expected_value": 0,  # 0 = safe, 1 = unsafe
        "description": "Prompt injection attacks"
    },
    "toxicity": {
        "file": "GateWayApsix/safellm/tests/datasets/toxicity_prompts.csv",
        "expected_col": None,  # No clear expected column, use threshold
        "prompt_col": "prompt",
        "toxicity_threshold": 0.5,
        "description": "Toxic content detection"
    }
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

def load_dataset(config: Dict) -> List[Tuple[str, bool]]:
    """
    Load dataset and return list of (prompt, expected_safe) tuples.

    Args:
        config: Dataset configuration dictionary

    Returns:
        List of (prompt, expected_safe) tuples
    """
    file_path = config["file"]
    if not os.path.exists(file_path):
        print(f"⚠️  Dataset file not found: {file_path}")
        return []

    try:
        df = pd.read_csv(file_path)

        # Handle different dataset formats
        if config["expected_col"] is None:
            # Toxicity dataset - use threshold
            threshold = config.get("toxicity_threshold", 0.5)
            data = []
            for _, row in df.iterrows():
                prompt = str(row[config["prompt_col"]])
                toxicity_score = float(row.get("toxicity_score", 0))
                expected_safe = toxicity_score < threshold
                data.append((prompt, expected_safe))
        else:
            # Standard format with expected column
            data = []
            for _, row in df.iterrows():
                prompt = str(row[config["prompt_col"]])
                expected_value = row[config["expected_col"]]

                # Handle different expected value formats
                if config["expected_value"] == "safe":
                    expected_safe = expected_value == "safe"
                elif config["expected_value"] == "unsafe":
                    expected_safe = expected_value == "unsafe"
                elif isinstance(config["expected_value"], int):
                    expected_safe = expected_value == config["expected_value"]
                else:
                    expected_safe = str(expected_value) == str(config["expected_value"])

                data.append((prompt, expected_safe))

        return data[:100]  # Limit to 100 samples per dataset for performance

    except Exception as e:
        print(f"❌ Error loading dataset {file_path}: {e}")
        return []

def benchmark_dataset(dataset_name: str, config: Dict) -> Dict:
    """
    Benchmark single dataset performance.

    Args:
        dataset_name: Name of the dataset
        config: Dataset configuration

    Returns:
        Benchmark results dictionary
    """
    print(f"\n🔍 Benchmark: {dataset_name}")
    print(f"   Description: {config['description']}")
    print("=" * 70)

    if not test_gateway_health():
        print("❌ Gateway not healthy")
        return {"error": "Gateway not healthy"}

    # Load dataset
    data = load_dataset(config)
    if not data:
        return {"error": "Failed to load dataset"}

    print(f"   Loaded {len(data)} samples")

    results = []
    false_positives = []
    false_negatives = []

    for i, (prompt, expected_safe) in enumerate(data, 1):
        latencies = []

        # Run 2 times for averaging (reduced for dataset testing)
        for _ in range(2):
            allowed, latency, details = run_single_request(prompt, bypass_cache=True)
            latencies.append(latency)

        avg_latency = statistics.mean(latencies)
        actual_safe = allowed

        # Determine result type
        if expected_safe and actual_safe:
            status = "✅ TRUE_NEGATIVE"
        elif expected_safe and not actual_safe:
            status = "❌ FALSE_POSITIVE"
            false_positives.append((prompt, avg_latency))
        elif not expected_safe and not actual_safe:
            status = "✅ TRUE_POSITIVE"
        else:  # not expected_safe and actual_safe
            status = "❌ FALSE_NEGATIVE"
            false_negatives.append((prompt, avg_latency))

        results.append({
            'avg_latency': avg_latency,
            'status': status,
            'expected_safe': expected_safe,
            'actual_safe': actual_safe
        })

        # Progress indicator
        if i % 10 == 0 or i == len(data):
            print(f"🧪 Sample {i:3}/{len(data)}: {status} | {avg_latency:5.1f}ms | {prompt[:40]}...")

    # Calculate statistics
    lats = [r['avg_latency'] for r in results]
    total_samples = len(results)
    true_negatives = sum(1 for r in results if r['status'] == "✅ TRUE_NEGATIVE")
    true_positives = sum(1 for r in results if r['status'] == "✅ TRUE_POSITIVE")
    false_positives_count = len(false_positives)
    false_negatives_count = len(false_negatives)

    accuracy = (true_negatives + true_positives) / total_samples * 100
    precision = true_positives / (true_positives + false_positives_count) * 100 if (true_positives + false_positives_count) > 0 else 0
    recall = true_positives / (true_positives + false_negatives_count) * 100 if (true_positives + false_negatives_count) > 0 else 0

    print("\n📊 RESULTS:")
    print("=" * 50)
    print(f"   Total samples tested: {total_samples}")
    print(f"   Accuracy: {accuracy:.1f}%")
    print(f"   Precision: {precision:.1f}% (correct unsafe detection)")
    print(f"   Recall: {recall:.1f}% (unsafe detection coverage)")
    print(f"   False Positives: {false_positives_count} ({false_positives_count/total_samples*100:.1f}%)")
    print(f"   False Negatives: {false_negatives_count} ({false_negatives_count/total_samples*100:.1f}%)")
    print(f"   Average Latency: {statistics.mean(lats):.1f}ms")

    if lats:
        print(f"   P95 Latency: {statistics.quantiles(lats, n=20)[18]:.1f}ms")

    if lats:
        print(f"   P95 Latency: {statistics.quantiles(lats, n=20)[18]:.1f}ms")

    # Show top false positives if any
    if false_positives:
        print("\n🚨 Top False Positives:")
        sorted_fp = sorted(false_positives, key=lambda x: x[1], reverse=True)[:3]
        for i, (prompt, latency) in enumerate(sorted_fp, 1):
            print(f"   {i}. {latency:.1f}ms: {prompt[:60]}...")

    return {
        "dataset": dataset_name,
        "total_samples": total_samples,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "false_positives": false_positives_count,
        "false_negatives": false_negatives_count,
        "avg_latency": statistics.mean(lats) if lats else 0,
        "p95_latency": statistics.quantiles(lats, n=20)[18] if lats else 0,
        "false_positive_rate": false_positives_count / total_samples * 100,
        "false_negative_rate": false_negatives_count / total_samples * 100
    }

def run_comprehensive_benchmark():
    """Run comprehensive benchmark across all datasets."""
    print("🚀 DatasetBenchmark - Comprehensive Security Testing")
    print("=" * 70)
    print(f"Gateway URL: {GATEWAY_URL}")
    print(f"Platform: CPU-only (AMD Ryzen 5 PRO 3600)")
    print(f"Focus: False Positive Detection & Accuracy")
    print()

    all_results = []

    for dataset_name, config in DATASET_CONFIGS.items():
        try:
            result = benchmark_dataset(dataset_name, config)
            if "error" not in result:
                all_results.append(result)
        except Exception as e:
            print(f"❌ Error benchmarking {dataset_name}: {e}")
            continue

    # Overall summary
    print("\n" + "=" * 70)
    print("🎯 COMPREHENSIVE RESULTS SUMMARY")
    print("=" * 70)

    if not all_results:
        print("❌ No successful benchmarks")
        return

    # Calculate weighted averages (weighted by sample count)
    total_samples = sum(r["total_samples"] for r in all_results)
    weighted_accuracy = sum(r["accuracy"] * r["total_samples"] for r in all_results) / total_samples
    weighted_false_positive_rate = sum(r["false_positive_rate"] * r["total_samples"] for r in all_results) / total_samples
    weighted_false_negative_rate = sum(r["false_negative_rate"] * r["total_samples"] for r in all_results) / total_samples
    avg_latency = statistics.mean(r["avg_latency"] for r in all_results)

    print("\n🎯 OVERALL PERFORMANCE SUMMARY")
    print("=" * 70)
    print(f"   Total samples tested: {total_samples}")
    print(f"   Weighted accuracy: {weighted_accuracy:.1f}%")
    print(f"   False positive rate: {weighted_false_positive_rate:.1f}%")
    print(f"   False negative rate: {weighted_false_negative_rate:.1f}%")
    print(f"   Average latency: {avg_latency:.1f}ms")

    # Performance assessment
    print("\n📈 ASSESSMENT:")
    if weighted_accuracy >= 95:
        print("   ✅ EXCELLENT: High accuracy across all datasets")
    elif weighted_accuracy >= 90:
        print("   ⚠️ GOOD: Acceptable accuracy, minor improvements needed")
    else:
        print("   ❌ POOR: Significant accuracy issues require attention")

    if weighted_false_positive_rate <= 5:
        print("   ✅ EXCELLENT: Low false positive rate - good user experience")
    elif weighted_false_positive_rate <= 10:
        print("   ⚠️ ACCEPTABLE: Moderate false positive rate")
    else:
        print("   ❌ HIGH: Too many false positives - users will be frustrated")

    if weighted_false_negative_rate <= 5:
        print("   ✅ EXCELLENT: Strong security - few threats missed")
    else:
        print("   ⚠️ MONITOR: Some security threats may be missed")

    # Dataset comparison table
    print("\n📋 DATASET COMPARISON:")
    print("=" * 70)
    print("Dataset                  | Samples | Acc% | FP% | FN% | Lat(ms)")
    print("-" * 70)

    for result in sorted(all_results, key=lambda x: x["false_positive_rate"]):
        dataset = result["dataset"]
        samples = result["total_samples"]
        acc = result["accuracy"]
        fp_rate = result["false_positive_rate"]
        fn_rate = result["false_negative_rate"]
        lat = result["avg_latency"]

        # Color coding for performance
        if fp_rate <= 5:
            fp_indicator = "🟢"
        elif fp_rate <= 10:
            fp_indicator = "🟡"
        else:
            fp_indicator = "🔴"

        if acc >= 95:
            acc_indicator = "🟢"
        elif acc >= 90:
            acc_indicator = "🟡"
        else:
            acc_indicator = "🔴"

        print("<23")

    # Recommendations
    print("\n💡 RECOMMENDATIONS:")
    print("=" * 70)

    recommendations = []

    if weighted_false_positive_rate > 10:
        recommendations.append("🚨 CRITICAL: High false positive rate detected")
        recommendations.append("   • Lower AI model detection threshold")
        recommendations.append("   • Review keyword patterns for over-aggressiveness")
        recommendations.append("   • Add context-aware filtering")

    if weighted_false_negative_rate > 5:
        recommendations.append("⚠️  SECURITY RISK: High false negative rate")
        recommendations.append("   • Increase detection sensitivity")
        recommendations.append("   • Add more comprehensive keyword rules")
        recommendations.append("   • Update AI model training data")

    if avg_latency > 100:
        recommendations.append("⏱️  PERFORMANCE: High latency detected")
        recommendations.append("   • Optimize caching strategy")
        recommendations.append("   • Consider async processing improvements")
        recommendations.append("   • Review AI model inference optimization")

    if weighted_accuracy >= 95:
        recommendations.append("✅ EXCELLENT: System performing well")
        recommendations.append("   • Continue monitoring for emerging threats")
        recommendations.append("   • Consider fine-tuning for edge cases")

    if not recommendations:
        print("   ✅ All metrics within acceptable ranges")
    else:
        for rec in recommendations:
            print(f"   {rec}")

if __name__ == "__main__":
    try:
        run_comprehensive_benchmark()
    except KeyboardInterrupt:
        print("\n⏹️  Benchmark interrupted by user")
    except Exception as e:
        print(f"\n❌ Benchmark failed with error: {e}")
        import traceback
        traceback.print_exc()
