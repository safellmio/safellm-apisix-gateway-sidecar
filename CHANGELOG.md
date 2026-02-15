# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [2.0.0] - 2026-02-15

### Added
- Hardened Docker E2E isolation with dynamic Compose project names, label-based container lookup, and dynamic APISIX port discovery.
- Streaming request body limit protection in `/auth` to prevent memory blow-ups on oversized/chunked payloads.

### Changed
- Release metadata bumped to `2.0.0` across package, chart, sidecar runtime, and release compose artifacts.
- `run_tests.sh` now installs both dev and runtime dependencies to prevent import-time failures in CI/test hosts.

## [0.8.0] - 2026-01-31

### Added
- OSS-only Docker Compose stack for APISIX + SafeLLM + Redis.
- Public README tailored to OSS usage and quickstart.
- Community health files (SECURITY, CONTRIBUTING, CODE_OF_CONDUCT).

### Changed
- Metadata aligned to OSS branding and Apache 2.0 license.
- Removed enterprise-only code, configs, and tests from OSS repo.
