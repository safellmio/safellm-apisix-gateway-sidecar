#!/bin/bash

# SafeLLM Gateway Test Runner
# Runs all tests in the correct environment

set -e  # Exit on any error

echo "🚀 Starting SafeLLM Gateway Tests..."

# Verify we are in the correct directory
if [ ! -d "sidecar" ] || [ ! -d "tests" ]; then
    echo "❌ Error: Run this script from GateWayApsix/safellm directory"
    echo "   cd GateWayApsix/safellm && ./run_tests.sh"
    exit 1
fi

# Check if we're in a virtual environment or activate one
if [ -z "$VIRTUAL_ENV" ]; then
    # Try common venv locations in current or parent dir
    if [ -f ".venv/bin/activate" ]; then
        echo "📦 Activating .venv..."
        source .venv/bin/activate
    elif [ -f "venv/bin/activate" ]; then
        echo "📦 Activating venv..."
        source venv/bin/activate
    elif [ -f "../../llm_guard_env/bin/activate" ]; then
        echo "📦 Activating ../../llm_guard_env..."
        source "../../llm_guard_env/bin/activate"
    else
        echo "⚠️  No virtual environment detected. Using system Python."
        echo "   Tip: Create venv with: python -m venv .venv && source .venv/bin/activate"
    fi
else
    echo "📦 Using active virtual environment: $VIRTUAL_ENV"
fi

echo "🧹 Cleaning up stale test processes..."
pkill -9 -f "pytest" || true
pkill -9 -f "execnet" || true

echo "📦 Installing/updating test dependencies..."
pip install -q -r requirements-dev.txt -r sidecar/requirements.txt

# Configure parallel execution based on RAM (approx 4GB per worker for safety)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))
elif [[ "$OSTYPE" == "darwin"* ]]; then
    TOTAL_RAM_BYTES=$(sysctl -n hw.memsize)
    TOTAL_RAM_GB=$((TOTAL_RAM_BYTES / 1024 / 1024 / 1024))
else
    TOTAL_RAM_GB=8 # Safe fallback for other OS
fi
# We reserve 5GB for the OS/Docker and use 4GB per worker
SAFE_WORKERS=$(((TOTAL_RAM_GB - 5) / 4))
# Clamp between 1 and CPU count
CPU_COUNT=$(nproc)
NUM_WORKERS=${NUM_WORKERS:-$SAFE_WORKERS}

if [ "$NUM_WORKERS" -gt "$CPU_COUNT" ]; then
    NUM_WORKERS=$CPU_COUNT
fi
if [ "$NUM_WORKERS" -lt 1 ]; then
    NUM_WORKERS=1
fi

echo "💻 System RAM: ${TOTAL_RAM_GB}GB | CPUs: ${CPU_COUNT}"
echo "⚡ Using $NUM_WORKERS worker(s) for parallel test execution (RAM-optimized)"

# Default values
COVERAGE=false
API_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --coverage)
            COVERAGE=true
            shift
            ;;
        --api-only)
            API_ONLY=true
            shift
            ;;
        --help)
            echo "Usage: ./run_tests.sh [--coverage] [--api-only] [--help]"
            echo "  --coverage: Run with code coverage reporting"
            echo "  --api-only: Run only API-related tests (unit/api and integration/api)"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# IMPORTANT: Run from root to make package discovery work correctly
export PYTHONPATH=$PYTHONPATH:$(pwd)

# Prepare pytest arguments
if [ "$COVERAGE" = true ]; then
    echo "📊 Coverage mode enabled"
    if [ "$API_ONLY" = true ]; then
        echo "🎯 Target: API only"
        COV_ARGS="--cov=sidecar/api --cov-config=.coveragerc_api --cov-report=term-missing --cov-report=html:htmlcov_api"
        TEST_TARGETS="tests/unit/api/ tests/integration/api/"
    else
        echo "🎯 Target: Full project (sidecar)"
        COV_ARGS="--cov=sidecar --cov-report=term-missing --cov-report=html:htmlcov"
        TEST_TARGETS="tests/unit/ tests/integration/ tests/*.py"
    fi
else
    COV_ARGS=""
    if [ "$API_ONLY" = true ]; then
        TEST_TARGETS="tests/unit/api/ tests/integration/api/"
    else
        TEST_TARGETS="tests/unit/ tests/integration/ tests/*.py"
    fi
fi

echo "🧪 Running Unit & Integration tests (parallel)..."
python -m pytest $TEST_TARGETS -v --tb=short -n $NUM_WORKERS --dist worksteal $COV_ARGS

if [ "$API_ONLY" != true ]; then
    echo "🧪 Running E2E tests (sequential due to Docker dependencies)..."
    if [ "$COVERAGE" = true ]; then
        # For full coverage, we also append E2E results
        python -m pytest tests/e2e/ -v --tb=short --cov=sidecar --cov-append --cov-report=term-missing --cov-report=html:htmlcov
    else
        python -m pytest tests/e2e/ -v --tb=short
    fi
fi

echo "✅ All tests completed!"
