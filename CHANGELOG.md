# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

## [2.1.1] - 2026-03-01

### Added
- Plugin-based MCP server under `sidecar/mcp` with JSON-RPC stdio runtime (`python -m sidecar.mcp`) and three built-in tools:
  - `safellm.guard_decide` (full input guard pipeline decision),
  - `safellm.pii_scan` (PII layer scan),
  - `safellm.dlp_scan` (output DLP scan with `block|anonymize|log` mode support).
- MCP unit-test suite in `tests/unit/mcp/` covering registry behavior, plugin input validation/execution, and JSON-RPC server handling.
- New `examples/mcp-reference` Docker bundle with `docker-compose.yml`, `.env.example`, and `smoke-test.sh` for HTTP+MCP validation.
- Docker E2E coverage for MCP stdio execution inside sidecar containers (`test_mcp_stdio_tools_in_container`).

### Fixed
- Resolved MCP bootstrap circular-import risk by moving `get_pii_layer` lookup to lazy import inside plugin execution path.
- Routed MCP mode logs to `stderr` so `stdout` remains valid JSON-RPC output for MCP clients.
- Added JSON-RPC notification handling (`notifications/initialized` and `notifications/*`) with no response emission.
- Hardened MCP internal error responses to avoid leaking exception internals to clients.
- Improved MCP reference smoke test portability and stderr/stdout separation.

## [2.1.0] - 2026-02-22

### Added
- Sequential fallback in `run_tests.sh` when parallel xdist workers crash, improving CI stability on constrained environments.
- New `examples/apisix-reference` deployment bundle (standalone APISIX + SafeLLM + Redis + upstream + smoke test script) for quick first-time APISIX evaluation.

### Fixed
- Masked sensitive PII values in metadata and logs, with an explicit debug gate for controlled raw-value diagnostics.
- Restricted `/auth` to `POST` and hardened management/auth key verification paths.
- Fixed DLP normalization/offset handling so anonymization is applied consistently on the analyzed text.
- Added locking for audit statistics updates to prevent lost increments under concurrency.
- Increased request ID length to reduce collision risk in high-throughput log correlation.
- Replaced deprecated UTC datetime usage with timezone-aware timestamps.
- Moved Redis secret handling to `SecretStr` and unified Redis config to a single validated settings source.
- Improved regex safety validation for custom PII patterns to reduce catastrophic backtracking risk.
- Corrected confidence-threshold filtering logic so low-confidence entities are not incorrectly accepted.

### Changed
- Release metadata bumped to `2.1.0` across package/runtime (`VERSION`, `pyproject.toml`, `sidecar/app.py`), Helm chart, release compose, and Docker usage docs.

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
