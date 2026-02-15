# Test Suite (OSS)

This folder contains unit, integration, and E2E tests for the OSS SafeLLM sidecar.

## Structure

- `unit/` — unit tests for core logic and layers
- `integration/` — integration tests for API and pipeline behavior
- `e2e/` — end-to-end tests (some require Docker)
- `datasets/` — prompt datasets used by tests and benchmarks

## Running Tests

```bash
# All tests (OSS)
./run_tests.sh

# Unit tests only
python run_tests.py --type unit

# Integration tests only
python run_tests.py --type integration

# E2E tests without Docker
python run_tests.py --type e2e-no-docker
```

## Notes

- OSS build does not include enterprise-only components.
- If a test requires Docker services, start the OSS stack first:
  `docker compose up -d --build`
