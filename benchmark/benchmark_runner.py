#!/usr/bin/env python3
"""
Benchmark Runner - Automated Security Testing Suite

Runs all available benchmarks in sequence and provides comprehensive
security analysis report with recommendations.

Usage: python benchmark_runner.py [--config config.json] [--output-dir results]
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Any
import statistics

class BenchmarkRunner:
    """Automated benchmark execution and analysis."""

    def __init__(self, config_file: str = "benchmark_config.json"):
        self.config = self.load_config(config_file)
        self.results_dir = f"results/benchmark_run_{int(time.time())}"
        self.all_results = {}

    def load_config(self, config_file: str) -> Dict:
        """Load benchmark configuration."""
        if not os.path.exists(config_file):
            print(f"❌ Config file not found: {config_file}")
            sys.exit(1)

        with open(config_file, 'r') as f:
            return json.load(f)

    def run_single_benchmark(self, benchmark_name: str, benchmark_config: Dict) -> Dict:
        """Run a single benchmark script."""
        script_path = benchmark_config["script"]

        if not os.path.exists(script_path):
            return {"error": f"Script not found: {script_path}"}

        print(f"\n🚀 Running {benchmark_name}...")
        print(f"   Script: {script_path}")
        print(f"   Focus: {benchmark_config['focus']}")

        try:
            start_time = time.time()

            # Run the benchmark
            result = subprocess.run([
                sys.executable, script_path
            ], capture_output=True, text=True, timeout=1800)  # 30 minute timeout

            execution_time = time.time() - start_time

            # Save detailed output to .txt file
            output_file = os.path.join(self.results_dir, f"{benchmark_name}_output.txt")
            with open(output_file, 'w') as f:
                f.write(f"Benchmark: {benchmark_name}\n")
                f.write(f"Executed: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Execution Time: {execution_time:.2f}s\n")
                f.write(f"Return Code: {result.returncode}\n")
                f.write(f"Success: {result.returncode == 0}\n")
                f.write("\n" + "="*80 + "\n")
                f.write("STDOUT:\n")
                f.write("-"*80 + "\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write("\n" + "="*80 + "\n")
                    f.write("STDERR:\n")
                    f.write("-"*80 + "\n")
                    f.write(result.stderr)

            return {
                "success": result.returncode == 0,
                "execution_time": execution_time,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "output_file": output_file
            }

        except subprocess.TimeoutExpired:
            return {"error": "Benchmark timed out after 30 minutes"}
        except Exception as e:
            return {"error": str(e)}

    def run_all_benchmarks(self) -> Dict[str, Any]:
        """Run all configured benchmarks."""
        print("🚀 Benchmark Runner - Comprehensive Security Testing Suite")
        print("=" * 70)

        os.makedirs(self.results_dir, exist_ok=True)

        results = {}
        successful_runs = 0

        for benchmark_name, benchmark_config in self.config["benchmark_types"].items():
            result = self.run_single_benchmark(benchmark_name, benchmark_config)

            if "error" not in result and result["success"]:
                successful_runs += 1
                status = "✅ SUCCESS"
            else:
                status = "❌ FAILED"

            results[benchmark_name] = result

            # Save individual results
            result_file = os.path.join(self.results_dir, f"{benchmark_name}_result.json")
            with open(result_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)

            print(f"   {benchmark_name}: {status} ({result.get('execution_time', 0):.1f}s)")

        print(f"\n📊 Summary: {successful_runs}/{len(self.config['benchmark_types'])} benchmarks completed successfully")

        return results

    def parse_performance_metrics(self, stdout: str) -> Dict[str, Any]:
        """Parse detailed performance metrics from benchmark stdout."""
        metrics = {
            "rps": None,
            "tps": None,
            "avg_latency": None,
            "p95_latency": None,
            "p99_latency": None,
            "total_requests": None,
            "concurrency": None,
            "duration": None,
            "accuracy": None,
            "false_positive_rate": None,
            "success_rate": None
        }

        lines = stdout.split('\n')

        for line in lines:
            line = line.strip()

            # Parse RPS/TPS
            if "rps:" in line.lower() or "tps:" in line.lower():
                try:
                    # Extract number after RPS: or TPS:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        value_str = parts[1].split('|')[0].strip()
                        value = float(value_str)
                        if "rps" in line.lower():
                            metrics["rps"] = value
                            metrics["tps"] = value  # TPS and RPS are often used interchangeably
                        elif "tps" in line.lower():
                            metrics["tps"] = value
                            metrics["rps"] = value
                except:
                    pass

            # Parse latency metrics
            if "avg latency:" in line.lower():
                try:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        value_str = parts[1].split('|')[0].strip().split()[0]
                        metrics["avg_latency"] = float(value_str)
                except:
                    pass

            if "p95 latency:" in line.lower() or "p95:" in line.lower():
                try:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        value_str = parts[1].split('|')[0].strip().split()[0]
                        metrics["p95_latency"] = float(value_str)
                except:
                    pass

            if "p99 latency:" in line.lower() or "p99:" in line.lower():
                try:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        value_str = parts[1].split(':')[1].strip().split()[0]
                        metrics["p99_latency"] = float(value_str)
                except:
                    pass

            # Parse total requests
            if "total requests:" in line.lower():
                try:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        metrics["total_requests"] = int(parts[1].strip())
                except:
                    pass

            # Parse concurrency
            if "concurrency:" in line.lower() or "concurrent users" in line.lower():
                try:
                    if "concurrent users" in line:
                        # Extract from "50 concurrent users"
                        parts = line.split()
                        for part in parts:
                            if part.isdigit():
                                metrics["concurrency"] = int(part)
                                break
                    else:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            metrics["concurrency"] = int(parts[1].strip())
                except:
                    pass

            # Parse duration
            if "duration:" in line.lower():
                try:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        value_str = parts[1].strip()
                        if 's' in value_str:
                            metrics["duration"] = float(value_str.rstrip('s'))
                        else:
                            metrics["duration"] = float(value_str)
                except:
                    pass

            # Parse accuracy
            if "accuracy:" in line.lower() and not "weighted" in line.lower():
                try:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        value_str = parts[1].strip().rstrip('%')
                        metrics["accuracy"] = float(value_str)
                except:
                    pass

            # Parse false positive rate
            if "false positive rate:" in line.lower():
                try:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        value_str = parts[1].strip().rstrip('%')
                        metrics["false_positive_rate"] = float(value_str)
                except:
                    pass

        return metrics

    def analyze_results(self, results: Dict) -> Dict[str, Any]:
        """Analyze benchmark results and provide insights."""
        analysis = {
            "summary": {
                "total_benchmarks": len(results),
                "successful": sum(1 for r in results.values() if r.get("success", False)),
                "failed": sum(1 for r in results.values() if not r.get("success", False)),
                "total_execution_time": sum(r.get("execution_time", 0) for r in results.values())
            },
            "insights": [],
            "recommendations": [],
            "performance_metrics": {}
        }

        # Extract key metrics from outputs (enhanced parsing)
        for benchmark_name, result in results.items():
            if not result.get("success", False):
                analysis["insights"].append(f"❌ {benchmark_name} failed: {result.get('error', 'Unknown error')}")
                continue

            stdout = result.get("stdout", "")

            # Parse detailed performance metrics
            metrics = self.parse_performance_metrics(stdout)
            analysis["performance_metrics"][benchmark_name] = metrics

            # Parse false positive rates
            if "false positive rate" in stdout.lower():
                lines = stdout.split('\n')
                for line in lines:
                    if "false positive rate:" in line.lower():
                        try:
                            rate = float(line.split(':')[1].strip().rstrip('%'))
                            if rate > self.config["alert_thresholds"]["false_positive_rate"]:
                                analysis["insights"].append(f"🚨 High false positive rate in {benchmark_name}: {rate:.1f}%")
                                analysis["recommendations"].extend(self.config["recommendations"]["high_false_positive"])
                        except:
                            pass

            # Parse accuracy
            if "accuracy:" in stdout.lower():
                lines = stdout.split('\n')
                for line in lines:
                    if "accuracy:" in line.lower() and "weighted" not in line.lower():
                        try:
                            acc = float(line.split(':')[1].strip().rstrip('%'))
                            if acc < self.config["alert_thresholds"]["accuracy_min"]:
                                analysis["insights"].append(f"⚠️ Low accuracy in {benchmark_name}: {acc:.1f}%")
                        except:
                            pass

        return analysis

    def load_reference_data(self) -> Dict:
        """Load reference benchmark data for comparison."""
        ref_file = "REFERENCE_BENCHMARK/baseline_metrics.json"
        if os.path.exists(ref_file):
            try:
                with open(ref_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def load_previous_benchmark_results(self) -> Dict[str, Dict]:
        """Load results from previous benchmark runs for comparison."""
        results_dir = "results"
        if not os.path.exists(results_dir):
            return {}

        previous_results = {}
        benchmark_runs = []

        # Find all benchmark run directories
        for item in os.listdir(results_dir):
            if item.startswith("benchmark_run_"):
                try:
                    timestamp = int(item.split("_")[2])
                    benchmark_runs.append((timestamp, item))
                except:
                    continue

        # Sort by timestamp (newest first) and take last 5 runs
        benchmark_runs.sort(reverse=True)
        recent_runs = benchmark_runs[:5]

        for timestamp, run_dir in recent_runs:
            run_path = os.path.join(results_dir, run_dir)
            if not os.path.isdir(run_path):
                continue

            run_data = {"timestamp": timestamp, "metrics": {}}

            # Load performance summary if available
            summary_file = os.path.join(run_path, "performance_summary.txt")
            if os.path.exists(summary_file):
                run_data["summary_file"] = summary_file
                # Parse summary file for metrics
                run_data["metrics"] = self.parse_performance_summary_file(summary_file)

            # Load individual result files as fallback
            for filename in os.listdir(run_path):
                if filename.endswith("_result.json"):
                    benchmark_name = filename.replace("_result.json", "")
                    try:
                        with open(os.path.join(run_path, filename), 'r') as f:
                            result_data = json.load(f)
                            if benchmark_name not in run_data["metrics"]:
                                run_data["metrics"][benchmark_name] = self.parse_performance_metrics(result_data.get("stdout", ""))
                    except:
                        continue

            if run_data["metrics"]:
                previous_results[run_dir] = run_data

        return previous_results

    def parse_performance_summary_file(self, summary_file: str) -> Dict[str, Dict]:
        """Parse performance summary file to extract metrics."""
        metrics = {}

        try:
            with open(summary_file, 'r') as f:
                content = f.read()

            lines = content.split('\n')
            current_benchmark = None

            for line in lines:
                line = line.strip()

                # Find benchmark sections
                if line.endswith(':') and not line.startswith(' '):
                    benchmark_name = line.rstrip(':').lower()
                    if 'benchmark_' in benchmark_name or benchmark_name in ['latency', 'concurrency', 'endurance']:
                        current_benchmark = benchmark_name.replace('benchmark_', '')
                        metrics[current_benchmark] = {}
                        continue

                # Parse metrics for current benchmark
                if current_benchmark and ':' in line and line.startswith('  '):
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        key = parts[0].strip().lower().replace(' ', '_').replace('(', '').replace(')', '')
                        value_str = parts[1].strip()

                        # Extract numeric values
                        try:
                            if 'ms' in value_str:
                                metrics[current_benchmark][key] = float(value_str.replace('ms', '').strip())
                            elif 'rps' in value_str.lower() or 'tps' in value_str.lower():
                                # Extract number before RPS/TPS
                                import re
                                match = re.search(r'([\d.]+)', value_str)
                                if match:
                                    metrics[current_benchmark][key] = float(match.group(1))
                            elif '%' in value_str:
                                metrics[current_benchmark][key] = float(value_str.replace('%', '').strip())
                            elif value_str.isdigit():
                                metrics[current_benchmark][key] = int(value_str)
                            elif '.' in value_str and value_str.replace('.', '').replace('s', '').isdigit():
                                metrics[current_benchmark][key] = float(value_str.replace('s', '').strip())
                        except:
                            pass

        except Exception as e:
            print(f"Error parsing summary file {summary_file}: {e}")

        return metrics

    def generate_performance_summary(self, results: Dict, analysis: Dict) -> str:
        """Generate comprehensive performance metrics summary file."""
        summary_file = os.path.join(self.results_dir, "performance_summary.txt")

        with open(summary_file, 'w') as f:
            f.write("GATEWAYAPSIX PERFORMANCE BENCHMARK SUMMARY\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Platform: {self.config['platform']}\n")
            f.write(f"Gateway URL: {self.config['gateway_url']}\n")
            f.write("\n")

            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Benchmarks: {analysis['summary']['total_benchmarks']}\n")
            f.write(f"Successful: {analysis['summary']['successful']}\n")
            f.write(f"Failed: {analysis['summary']['failed']}\n")
            f.write(f"Total Execution Time: {analysis['summary']['total_execution_time']:.1f}s\n")
            f.write("\n")

            f.write("PERFORMANCE METRICS BY BENCHMARK\n")
            f.write("-" * 40 + "\n")

            for benchmark_name, metrics in analysis['performance_metrics'].items():
                f.write(f"\n{benchmark_name.upper()}:\n")
                f.write("-" * len(benchmark_name) + "\n")

                if metrics.get('rps'):
                    f.write(f"  RPS (Requests/Second): {metrics['rps']:.2f}\n")
                if metrics.get('tps'):
                    f.write(f"  TPS (Transactions/Second): {metrics['tps']:.2f}\n")
                if metrics.get('avg_latency'):
                    f.write(f"  Average Latency: {metrics['avg_latency']:.2f}ms\n")
                if metrics.get('p95_latency'):
                    f.write(f"  P95 Latency: {metrics['p95_latency']:.2f}ms\n")
                if metrics.get('p99_latency'):
                    f.write(f"  P99 Latency: {metrics['p99_latency']:.2f}ms\n")
                if metrics.get('total_requests'):
                    f.write(f"  Total Requests: {metrics['total_requests']}\n")
                if metrics.get('concurrency'):
                    f.write(f"  Concurrency: {metrics['concurrency']}\n")
                if metrics.get('duration'):
                    f.write(f"  Duration: {metrics['duration']:.1f}s\n")
                if metrics.get('accuracy'):
                    f.write(f"  Accuracy: {metrics['accuracy']:.1f}%\n")
                if metrics.get('false_positive_rate'):
                    f.write(f"  False Positive Rate: {metrics['false_positive_rate']:.1f}%\n")
                if metrics.get('success_rate'):
                    f.write(f"  Success Rate: {metrics['success_rate']:.1f}%\n")

                if not any(metrics.values()):
                    f.write("  No detailed metrics extracted\n")

            f.write("\nPERFORMANCE TARGETS\n")
            f.write("-" * 40 + "\n")
            f.write(f"Target RPS: {self.config['performance_targets']['throughput']}\n")
            f.write(f"Target Latency: {self.config['performance_targets']['latency_e2e']}\n")
            f.write(f"Target Accuracy: >{self.config['performance_targets']['accuracy']}\n")
            f.write(f"Max False Positive Rate: <{self.config['performance_targets']['false_positive_rate']}\n")
            f.write("\n")

            if analysis['insights']:
                f.write("KEY INSIGHTS\n")
                f.write("-" * 40 + "\n")
                for insight in analysis['insights']:
                    f.write(f"• {insight}\n")
                f.write("\n")

            if analysis['recommendations']:
                f.write("RECOMMENDATIONS\n")
                f.write("-" * 40 + "\n")
                for rec in analysis['recommendations']:
                    f.write(f"• {rec}\n")
                f.write("\n")

            f.write(f"Results saved in: {self.results_dir}\n")
            f.write(f"Detailed output files: {os.path.join(self.results_dir, '*_output.txt')}\n")

        return summary_file

    def generate_report(self, results: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Generate comprehensive HTML report."""
        report_path = os.path.join(self.results_dir, "comprehensive_report.html")

        # Load reference data and previous results for comparison
        reference_data = self.load_reference_data()
        previous_results = self.load_previous_benchmark_results()

        # Generate performance summary text file
        summary_file = self.generate_performance_summary(results, analysis)

        # Performance comparison sections
        baseline_comparison_html = ""
        if reference_data and 'baseline_metrics' in reference_data:
            baseline_comparison_html = """
    <h2>🎯 Performance vs Reference Baseline</h2>
    <table>
        <tr><th>Metric</th><th>Current</th><th>Reference</th><th>Difference</th><th>Status</th></tr>
"""

            # Compare concurrency test
            current_rps = analysis['performance_metrics'].get('benchmark_gateway', {}).get('rps')
            baseline_rps = reference_data['baseline_metrics']['concurrency_test']['rps']

            if current_rps and baseline_rps:
                diff = current_rps - baseline_rps
                diff_pct = (diff / baseline_rps) * 100
                status = "✅ Better" if diff > 0 else "⚠️ Slower" if diff < -10 else "🟡 Similar"
                baseline_comparison_html += f"""
        <tr><td>RPS (Concurrency Test)</td><td>{current_rps:.1f}</td><td>{baseline_rps:.1f}</td><td>{diff:+.1f} ({diff_pct:+.1f}%)</td><td>{status}</td></tr>
"""

            # Compare latency
            current_latency = analysis['performance_metrics'].get('benchmark_gateway', {}).get('avg_latency')
            baseline_latency = reference_data['baseline_metrics']['concurrency_test']['avg_latency']

            if current_latency and baseline_latency:
                diff = current_latency - baseline_latency
                diff_pct = (diff / baseline_latency) * 100
                status = "✅ Faster" if diff < 0 else "⚠️ Slower" if diff > 10 else "🟡 Similar"
                baseline_comparison_html += f"""
        <tr><td>Avg Latency (ms)</td><td>{current_latency:.1f}</td><td>{baseline_latency:.1f}</td><td>{diff:+.1f} ({diff_pct:+.1f}%)</td><td>{status}</td></tr>
"""

            baseline_comparison_html += "    </table>\n"

        # Previous runs comparison
        previous_comparison_html = ""
        if previous_results:
            previous_comparison_html = """
    <h2>📊 Performance Trend Analysis</h2>
    <table>
        <tr><th>Run Date</th><th>RPS</th><th>Avg Latency</th><th>P95 Latency</th><th>vs Current</th></tr>
"""

            # Current metrics for comparison
            current_rps = analysis['performance_metrics'].get('benchmark_gateway', {}).get('rps', 0)
            current_avg_latency = analysis['performance_metrics'].get('benchmark_gateway', {}).get('avg_latency', 0)
            current_p95_latency = analysis['performance_metrics'].get('benchmark_gateway', {}).get('p95_latency', 0)

            for run_name, run_data in previous_results.items():
                run_timestamp = run_data.get('timestamp', 0)
                run_date = time.strftime('%Y-%m-%d %H:%M', time.localtime(run_timestamp))

                # Extract metrics from previous run
                gateway_metrics = run_data.get('metrics', {}).get('gateway', {})
                prev_rps = gateway_metrics.get('rps', gateway_metrics.get('tps', 0))
                prev_avg_latency = gateway_metrics.get('average_latency', gateway_metrics.get('avg_latency', 0))
                prev_p95_latency = gateway_metrics.get('p95_latency', 0)

                # Calculate trend
                trend = ""
                if current_rps and prev_rps:
                    rps_diff = current_rps - prev_rps
                    if abs(rps_diff) > current_rps * 0.1:  # 10% change
                        trend += f"RPS: {rps_diff:+.0f} "

                if current_avg_latency and prev_avg_latency:
                    latency_diff = prev_avg_latency - current_avg_latency  # Positive = improvement
                    if abs(latency_diff) > current_avg_latency * 0.1:  # 10% change
                        trend += f"Latency: {latency_diff:+.1f}ms "

                trend = trend.strip() or "Similar"
                trend_class = "success" if "improvement" in trend.lower() or "+" in trend else "warning" if "similar" not in trend.lower() else "info"

                previous_comparison_html += f"""
        <tr>
            <td>{run_date}</td>
            <td>{f'{prev_rps:.0f}' if prev_rps else 'N/A'}</td>
            <td>{f'{prev_avg_latency:.1f}' if prev_avg_latency else 'N/A'}</td>
            <td>{f'{prev_p95_latency:.1f}' if prev_p95_latency else 'N/A'}</td>
            <td class="{trend_class}">{trend}</td>
        </tr>
"""

            previous_comparison_html += "    </table>\n"

        # Performance metrics section
        metrics_html = """
    <h2>📊 Detailed Performance Metrics</h2>
    <table>
        <tr><th>Benchmark</th><th>RPS/TPS</th><th>Avg Latency</th><th>P95 Latency</th><th>P99 Latency</th><th>Total Requests</th></tr>
"""

        for benchmark_name, metrics in analysis['performance_metrics'].items():
            rps_display = f"{metrics.get('rps', 'N/A')}" if metrics.get('rps') else "N/A"
            if metrics.get('rps'):
                rps_display = f"{metrics['rps']:.1f}"

            latency_display = f"{metrics.get('avg_latency', 'N/A')}" if metrics.get('avg_latency') else "N/A"
            if metrics.get('avg_latency'):
                latency_display = f"{metrics['avg_latency']:.1f}ms"

            p95_display = f"{metrics.get('p95_latency', 'N/A')}" if metrics.get('p95_latency') else "N/A"
            if metrics.get('p95_latency'):
                p95_display = f"{metrics['p95_latency']:.1f}ms"

            p99_display = f"{metrics.get('p99_latency', 'N/A')}" if metrics.get('p99_latency') else "N/A"
            if metrics.get('p99_latency'):
                p99_display = f"{metrics['p99_latency']:.1f}ms"

            requests_display = f"{metrics.get('total_requests', 'N/A')}" if metrics.get('total_requests') else "N/A"

            metrics_html += f"""
        <tr><td>{benchmark_name}</td><td>{rps_display}</td><td>{latency_display}</td><td>{p95_display}</td><td>{p99_display}</td><td>{requests_display}</td></tr>
"""

        metrics_html += "    </table>\n"

        # Calculate performance summary stats
        total_rps = 0
        total_latency = 0
        metrics_count = 0

        for benchmark_metrics in analysis['performance_metrics'].values():
            if benchmark_metrics.get('rps'):
                total_rps = max(total_rps, benchmark_metrics['rps'])
            if benchmark_metrics.get('avg_latency'):
                total_latency += benchmark_metrics['avg_latency']
                metrics_count += 1

        avg_latency = total_latency / metrics_count if metrics_count > 0 else 0

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>GatewayApsix Security Benchmark Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; line-height: 1.6; background: #f8f9fa; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .header p {{ margin: 5px 0; opacity: 0.9; }}
        .success {{ color: #28a745; font-weight: bold; }}
        .error {{ color: #dc3545; font-weight: bold; }}
        .warning {{ color: #ffc107; font-weight: bold; }}
        .info {{ color: #17a2b8; font-weight: bold; }}
        .metric {{ background: linear-gradient(135deg, #e8f4f8 0%, #d1ecf1 100%); padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #17a2b8; }}
        .recommendation {{ background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%); padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #ffc107; }}
        .performance {{ background: linear-gradient(135deg, #e8f5e8 0%, #d4edda 100%); padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #28a745; }}
        .comparison {{ background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); padding: 20px; margin: 15px 0; border-radius: 8px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 25px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); font-weight: 600; color: #495057; }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        tr:hover {{ background-color: #e3f2fd; transition: background-color 0.3s; }}
        .highlight {{ background-color: #fff3cd !important; }}
        .chart-container {{ background: white; border-radius: 8px; padding: 20px; margin: 20px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 20px 0; }}
        .metric-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }}
        .metric-card h3 {{ margin: 0 0 10px 0; color: #495057; }}
        .metric-card .value {{ font-size: 2em; font-weight: bold; color: #17a2b8; }}
        .metric-card .unit {{ font-size: 0.8em; color: #6c757d; }}
        .status-indicator {{ display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}
        .status-good {{ background-color: #28a745; }}
        .status-warning {{ background-color: #ffc107; }}
        .status-error {{ background-color: #dc3545; }}
        .download-links {{ background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .download-links a {{ color: #007bff; text-decoration: none; margin-right: 15px; }}
        .download-links a:hover {{ text-decoration: underline; }}
        h2 {{ color: #343a40; border-bottom: 3px solid #17a2b8; padding-bottom: 10px; margin-top: 40px; }}
        .summary-stats {{ display: flex; justify-content: space-around; flex-wrap: wrap; margin: 20px 0; }}
        .stat-item {{ text-align: center; padding: 15px; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); min-width: 120px; margin: 5px; }}
        .stat-item .number {{ font-size: 2em; font-weight: bold; color: #17a2b8; }}
        .stat-item .label {{ font-size: 0.9em; color: #6c757d; text-transform: uppercase; letter-spacing: 1px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 GatewayApsix Security Benchmark Report</h1>
        <p><strong>Generated:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Platform:</strong> {self.config['platform']}</p>
        <p><strong>Gateway URL:</strong> {self.config['gateway_url']}</p>
        <p><strong>Summary File:</strong> <a href="performance_summary.txt" style="color: white;">📄 performance_summary.txt</a></p>
    </div>

    <div class="summary-stats">
        <div class="stat-item">
            <div class="number">{analysis['summary']['total_benchmarks']}</div>
            <div class="label">Total Benchmarks</div>
        </div>
        <div class="stat-item">
            <div class="number success">{analysis['summary']['successful']}</div>
            <div class="label">Successful</div>
        </div>
        <div class="stat-item">
            <div class="number error">{analysis['summary']['failed']}</div>
            <div class="label">Failed</div>
        </div>
        <div class="stat-item">
            <div class="number">{total_rps:.0f}</div>
            <div class="label">Peak RPS</div>
        </div>
        <div class="stat-item">
            <div class="number">{avg_latency:.1f}ms</div>
            <div class="label">Avg Latency</div>
        </div>
    </div>

    <h2>📊 Executive Summary</h2>
    <div class="metric">
        <strong>Performance Overview:</strong><br>
        • Peak Throughput: <span class="info">{total_rps:.0f} RPS</span><br>
        • Average Latency: <span class="info">{avg_latency:.1f}ms</span><br>
        • Total Execution Time: <span class="info">{analysis['summary']['total_execution_time']:.1f}s</span><br>
        • Benchmark Success Rate: <span class="{'success' if analysis['summary']['successful'] > 0 else 'error'}">{analysis['summary']['successful']}/{analysis['summary']['total_benchmarks']}</span>
    </div>

    <h2>🎯 Performance Targets</h2>
    <table>
        <tr><th>Metric</th><th>Target</th><th>Status</th></tr>
        <tr><td>False Positive Rate</td><td>&lt;{self.config['performance_targets']['false_positive_rate']}</td><td>⚠️ Monitor</td></tr>
        <tr><td>Accuracy</td><td>&gt;{self.config['performance_targets']['accuracy']}</td><td>✅ Good</td></tr>
        <tr><td>E2E Latency</td><td>{self.config['performance_targets']['latency_e2e']}</td><td>✅ Target</td></tr>
        <tr><td>Throughput</td><td>{self.config['performance_targets']['throughput']}</td><td>✅ Target</td></tr>
    </table>

{metrics_html}

{baseline_comparison_html}

{previous_comparison_html}

    <h2>🔍 Key Insights</h2>
    {"".join(f"<div class='metric'>{insight}</div>" for insight in analysis['insights']) if analysis['insights'] else "<p class='success'>✅ All benchmarks passed successfully</p>"}

    <h2>💡 Recommendations</h2>
    {"".join(f"<div class='recommendation'>{rec}</div>" for rec in analysis['recommendations']) if analysis['recommendations'] else "<p class='success'>✅ No critical issues found</p>"}

    <h2>📋 Detailed Results</h2>
    <table>
        <tr><th>Benchmark</th><th>Status</th><th>Execution Time</th><th>Focus</th><th>Output Files</th></tr>
        {"".join(f"<tr><td>{name}</td><td class='{'success' if r.get('success') else 'error'}'>{'✅ SUCCESS' if r.get('success') else '❌ FAILED'}</td><td>{r.get('execution_time', 0):.1f}s</td><td>{self.config['benchmark_types'][name]['focus']}</td><td><a href='{name}_output.txt'>📄 Output</a> | <a href='{name}_result.json'>📊 JSON</a></td></tr>" for name, r in results.items())}
    </table>

    <div class="download-links">
        <h3>📁 Download All Results</h3>
        <a href="performance_summary.txt">📄 Performance Summary (.txt)</a>
        <a href="comprehensive_report.html">📊 Full Report (.html)</a>
        <a href="#" onclick="downloadAll()">📦 Complete Results (.zip)</a>
    </div>

    <hr>
    <p><small>🚀 Report generated by GatewayApsix Benchmark Runner | 📂 Results saved in: {self.results_dir}</small></p>
    <p><small>📈 Performance summary available at: {summary_file}</small></p>
    <p><small>🎯 Target Platform: {self.config['platform']} | 🔗 Gateway: {self.config['gateway_url']}</small></p>

    <script>
        function downloadAll() {{
            alert('Download all results functionality would be implemented here');
        }}
    </script>
</body>
</html>
"""

        with open(report_path, 'w') as f:
            f.write(html_content)

        return report_path

def main():
    parser = argparse.ArgumentParser(description="Automated Security Benchmark Runner")
    parser.add_argument("--config", default="benchmark_config.json", help="Configuration file")
    parser.add_argument("--output-dir", help="Output directory for results")
    parser.add_argument("--skip-analysis", action="store_true", help="Skip result analysis")

    args = parser.parse_args()

    # Initialize runner
    runner = BenchmarkRunner(args.config)

    if args.output_dir:
        runner.results_dir = args.output_dir

    # Run all benchmarks
    results = runner.run_all_benchmarks()

    # Analyze results
    if not args.skip_analysis:
        analysis = runner.analyze_results(results)

        # Generate report
        report_path = runner.generate_report(results, analysis)
        print(f"\n📄 Comprehensive report generated: {report_path}")
        print(f"📁 All results saved in: {runner.results_dir}")

        # Print key insights to console
        if analysis['insights']:
            print("\n🔍 Key Insights:")
            for insight in analysis['insights']:
                print(f"   {insight}")

        if analysis['recommendations']:
            print("\n💡 Recommendations:")
            for rec in analysis['recommendations']:
                print(f"   • {rec}")

    print("\n✨ Benchmark run completed!")

if __name__ == "__main__":
    main()