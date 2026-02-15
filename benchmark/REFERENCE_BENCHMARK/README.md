# REFERENCE_BENCHMARK

This folder contains baseline performance metrics and comparison data for GatewayApsix benchmark runs.

## Files

- `baseline_metrics.json` - Baseline performance expectations and target metrics
- `README.md` - This documentation

## Baseline Metrics Overview

### Performance Targets
- **Minimum RPS**: 50 requests per second
- **Maximum P95 Latency**: 100ms
- **Maximum P99 Latency**: 200ms
- **Minimum Accuracy**: 95%
- **Maximum False Positive Rate**: 5%

### Expected Performance (Baseline)
- **Concurrency Test (50 users)**: ~100 RPS, ~25ms avg latency
- **Endurance Test (60s)**: ~80 RPS sustained, ~30ms avg latency
- **Dataset Accuracy**: 95-99% across different test categories

### System Requirements
- CPU: 4+ cores (6 recommended)
- RAM: 8GB+ (12GB recommended)
- OS: Linux
- Python: 3.8+

## Usage

Benchmarks automatically compare against these reference metrics to show:
- Performance improvements/degradations
- Whether targets are being met
- Regression detection

The comparison appears in the comprehensive HTML report under the "Performance Comparison" section.