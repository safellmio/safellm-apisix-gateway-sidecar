# Benchmark Suite

This directory contains optional benchmark tools and datasets for validating security detection quality and runtime performance.

## What is included
- `datasetBenchmark.py`: dataset-based security benchmark.
- `BENCHMARK_DETECTION.py`: false-positive focused analysis.
- `benchmark_gateway.py`: latency/throughput checks through gateway routes.
- `benchmark_large_payload.py`: payload size and memory-protection checks.
- `benchmark_runner.py`: convenience runner for grouped benchmark execution.
- `datasets/`: curated CSV datasets used by benchmark scripts.

## Quick start
```bash
cd benchmark
python benchmark_runner.py
```

## Notes
- Benchmarks are optional and not required to run the core OSS gateway.
- Generated outputs should stay local (`benchmark/results/`, `results/`) and are ignored by git.
- Keep benchmark docs and outputs in English for public OSS consistency.
