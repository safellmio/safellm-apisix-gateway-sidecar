#!/bin/bash

# SafeLLM Gateway Example Data Generator
# Sends real prompts to generate monitoring data
# Uses datasets across categories: safe, injection, toxicity, pii

set -e  # Exit on any error

echo "🚀 SafeLLM Gateway - Example Data Generator"
echo "============================================"

# Verify we are in the correct directory
if [ ! -d "config" ] || [ ! -d "tests" ]; then
    echo "❌ Error: Run this script from GateWayApsix/safellm directory"
    echo "   cd GateWayApsix/safellm && ./example_data.sh"
    exit 1
fi

# Function to send a request
send_request() {
    local prompt="$1"
    local expected_status="$2"
    local category="$3"

    echo "📤 [$category] Sending: '${prompt:0:50}...'"

    # Send via APISIX Gateway (test endpoint /api/post - supports POST)
    response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" \
        -X POST http://localhost:9080/api/post \
        -H "Content-Type: application/json" \
        -d "{\"message\": \"$prompt\"}")

    # Split response body and status
    body=$(echo "$response" | head -n -1)
    status=$(echo "$response" | tail -n 1 | cut -d: -f2)

    if [ "$status" = "200" ]; then
        echo "✅ [$category] ALLOWED - $status"
    else
        echo "❌ [$category] BLOCKED - $status: $body"
    fi

    # Small pause between requests
    sleep 0.5
}

# Function to send a batch of prompts from CSV
send_batch() {
    local csv_file="$1"
    local category="$2"
    local max_requests="${3:-10}"

    if [ ! -f "$csv_file" ]; then
        echo "⚠️  Warning: Dataset file not found: $csv_file"
        return
    fi

    echo ""
    echo "📊 Processing $category dataset ($csv_file)"
    echo "============================================"

    # Skip header and send the first N prompts
    tail -n +2 "$csv_file" | head -n "$max_requests" | while IFS=',' read -r text label; do
        # Remove surrounding quotes if present
        text=$(echo "$text" | sed 's/^"//' | sed 's/"$//')
        # Escape special characters for JSON
        text=$(echo "$text" | sed 's/"/\\"/g' | sed 's/\t/ /g')

        if [ "$label" = "1" ]; then
            expected="BLOCKED"
        else
            expected="ALLOWED"
        fi

        send_request "$text" "$expected" "$category"
    done
}

echo ""
echo "🎯 Starting data generation..."
echo ""

# 1. SAFE PROMPTS - should pass
send_batch "tests/datasets/latency_safe_prompts.csv" "SAFE" 15

# 2. INJECTION ATTACKS - should be blocked
send_batch "tests/datasets/prompt_injections.csv" "INJECTION" 12

# 3. TOXIC CONTENT - may be blocked depending on configuration
send_batch "tests/datasets/toxicity_prompts.csv" "TOXICITY" 8

# 4. EDGE CASES - mieszane wyniki
send_batch "tests/datasets/edge_cases_false_positives.csv" "EDGE_CASES" 10

# 5. ADDITIONAL INJECTIONS
send_batch "tests/datasets/alert_adversarial_prompts.csv" "ADVERSARIAL" 8

echo ""
echo "🎉 Data generation completed!"
echo ""
echo "📊 Check results:"
echo "   - Sidecar logs: docker logs sidecar-oss"
echo "   - Metrics: curl http://localhost:8001/metrics"
echo ""
echo "🔍 Look for:"
echo "   - shadow_would_block entries (Shadow Mode)"
echo "   - safellm_requests_total metrics"
echo "   - Layer detection reasons in logs"
