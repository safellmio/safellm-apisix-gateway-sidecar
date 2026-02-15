#!/bin/bash

# 🚀 GatewayApsix Benchmark Quick Start
# Quick benchmark launcher

echo "🚀 GatewayApsix Security Benchmark Suite"
echo "========================================"
echo ""

# Validate current working directory
if [ ! -f "benchmark_config.json" ]; then
    echo "❌ Error: Run this script from the benchmark/ directory"
    echo "   cd benchmark && ./quick_start.sh"
    exit 1
fi

# Resolve Python runtime (prefer local venv, fallback to system python)
echo "🔧 Resolving Python runtime..."
if [ -x "../llm_guard_env/bin/python3" ]; then
    PYTHON_BIN="../llm_guard_env/bin/python3"
elif [ -x "../.venv/bin/python3" ]; then
    PYTHON_BIN="../.venv/bin/python3"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
else
    echo "❌ Error: python3 not found. Activate a venv or install python3."
    exit 1
fi

echo "✅ Using: $PYTHON_BIN"
echo ""

# Check if gateway is running
echo "🔍 Checking GatewayApsix status..."
if curl -s http://localhost:8001/health > /dev/null; then
    echo "✅ GatewayApsix is running"
else
    echo "⚠️  GatewayApsix not detected on localhost:8001"
    echo "   Make sure GatewayApsix is running before benchmarks"
fi

echo ""
echo "📊 Starting benchmark suite..."
echo ""

# Run all benchmarks
"$PYTHON_BIN" benchmark_runner.py

echo ""
echo "✨ Benchmark suite completed!"
echo ""
echo "📁 Results saved to: results/benchmark_run_$(date +%s)/"
echo "📄 Check benchmark_report.txt for detailed analysis"
echo ""
echo "🎯 Quick metrics:"
echo "   - False Positive Rate: Should be <5%"
echo "   - Accuracy: Should be >95%"
echo "   - Latency: Should be <100ms"
echo "   - Throughput: Should be >50 RPS"
