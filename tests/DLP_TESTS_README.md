# DLP (Data Loss Prevention) Test Suite

Comprehensive test suite for DLP functionality covering all aspects of output scanning for PII/sensitive data.

## Test Files Overview

### Core Unit Tests
- **`unit/layers/test_dlp.py`** - Core DLP scanner functionality
  - Prometheus metrics recording
  - Settings validation (DLP_MAX_OUTPUT_LENGTH, DLP_BLOCK_MESSAGE)
  - All DLP modes (block, anonymize, log)
  - PII detection accuracy
  - Error handling and fail-open behavior
  - Thread safety and concurrency
  - Health checks

### Integration Tests
- **`integration/api/test_dlp_api.py`** - Full API integration
  - `/v1/scan/output` endpoint
  - `/v1/scan/output/health` endpoint
  - Request/response validation
  - Error handling
  - Performance under load
  - Concurrent requests

### Performance & Benchmarks
- **`test_dlp_performance.py`** - Performance testing
  - Latency measurements for different text sizes
  - Throughput under concurrent load
  - Memory usage patterns
  - CPU utilization
  - Comparative benchmarks

### Scenario & Edge Cases
- **`test_dlp_scenarios.py`** - Comprehensive scenarios
  - Multilingual and Unicode support
  - Various PII format variations
  - LLM response format handling
  - False positive/negative analysis
  - Configuration edge cases
  - Boundary conditions

## Key Test Scenarios for Cheaper Model

Based on the requirements, focus on these critical scenarios:

### 1. DLP Metrics Recording
**Files:** `unit/layers/test_dlp.py`
```bash
pytest tests/unit/layers/test_dlp.py::TestDLPMetrics -v
```

**Tests:**
- ✅ `test_metrics_recorded_on_clean_scan`
- ✅ `test_metrics_recorded_on_pii_detected_block_mode`
- ✅ `test_metrics_recorded_on_pii_detected_anonymize_mode`
- ✅ `test_metrics_recorded_on_pii_detected_log_mode`
- ✅ `test_metrics_recorded_multiple_entities`
- ✅ `test_metrics_disabled_when_not_available`

**Expected:** Prometheus metrics are properly recorded:
- `safellm_dlp_scans_total{mode="block",result="clean"}`
- `safellm_dlp_scan_duration_seconds{mode="block"}`
- `safellm_dlp_pii_detected_total{entity_type="EMAIL_ADDRESS"}`

### 2. DLP_BLOCK_MESSAGE Setting Usage
**Files:** `unit/layers/test_dlp.py`, `integration/api/test_dlp_api.py`
```bash
pytest tests/unit/layers/test_dlp.py::TestDLPSettings -v
pytest tests/integration/api/test_dlp_api.py::TestDLPSettingsIntegration -v
```

**Tests:**
- ✅ `test_custom_block_message_from_settings`
- ✅ `test_custom_block_message_override`
- ✅ `test_fallback_block_message_on_settings_error`
- ✅ `test_custom_block_message_from_settings`

**Expected:** Custom block message from `DLP_BLOCK_MESSAGE` setting is used instead of hardcoded strings.

### 3. DLP_MAX_OUTPUT_LENGTH Validation
**Files:** `integration/api/test_dlp_api.py`
```bash
pytest tests/integration/api/test_dlp_api.py::TestDLPValidation -v
```

**Tests:**
- ✅ `test_scan_output_text_too_long`
- ✅ `test_dlp_max_output_length_integration`

**Expected:** API rejects requests exceeding `DLP_MAX_OUTPUT_LENGTH` (default: 500,000 chars).

## Quick Test Commands

### Run All DLP Tests
```bash
# All DLP tests
pytest tests/ -k "dlp" -v

# Unit tests only
pytest tests/unit/layers/test_dlp.py -v

# Integration tests only
pytest tests/integration/api/test_dlp_api.py -v

# Performance tests
pytest tests/test_dlp_performance.py -v

# Scenario tests
pytest tests/test_dlp_scenarios.py -v
```

### Run Critical Scenarios Only
```bash
# Focus on the three key requirements
pytest tests/unit/layers/test_dlp.py::TestDLPMetrics -v
pytest tests/unit/layers/test_dlp.py::TestDLPSettings -v
pytest tests/integration/api/test_dlp_api.py::TestDLPValidation -v
```

### Run with Coverage
```bash
pytest tests/unit/layers/test_dlp.py tests/integration/api/test_dlp_api.py \
       --cov=safellm.sidecar.layers.dlp --cov=safellm.sidecar.api.dlp \
       --cov-report=html
```

## Test Data & Fixtures

### PII Test Cases
The tests use comprehensive PII examples:
- **EMAIL_ADDRESS**: `john.doe@example.com`, `user@domain.pl`
- **PHONE_NUMBER**: `+1-555-123-4567`, `+48 123-456-789`
- **CREDIT_CARD**: `4111-1111-1111-1111`, `3782-822463-10005`
- **IBAN_CODE**: `DE89370400440532013000`
- **IP_ADDRESS**: `192.168.1.100`
- **US_SSN**: `123-45-6789`
- **CRYPTO**: `1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2`

### Performance Benchmarks
- **Clean text**: < 10ms average latency
- **PII detection**: < 50ms average latency
- **Large text (100KB)**: < 500ms latency
- **Concurrent throughput**: > 10 requests/second
- **Memory usage**: Stable, < 50MB per request

## Test Architecture

### Unit Tests (`test_dlp.py`)
- Mock external dependencies (Prometheus, settings)
- Test individual components in isolation
- Fast execution, high coverage
- Focus on business logic

### Integration Tests (`test_dlp_api.py`)
- Test full API endpoints with HTTP client
- End-to-end request/response flow
- Settings integration
- Error handling at API level

### Performance Tests (`test_dlp_performance.py`)
- Real performance measurements
- Load testing scenarios
- Resource usage monitoring
- Benchmark comparisons

### Scenario Tests (`test_dlp_scenarios.py`)
- Real-world edge cases
- Multilingual support
- Various PII formats
- Configuration boundaries

## Dependencies

### Required for All Tests
```bash
pip install pytest pytest-asyncio httpx pydantic
```

### Required for Performance Tests
```bash
pip install psutil
```

### Required for Full DLP Functionality
```bash
pip install presidio-analyzer presidio-anonymizer
```

## Running Tests in CI/CD

### Basic Test Run
```yaml
- name: Run DLP Tests
  run: |
    cd GateWayApsix/safellm
    python -m pytest tests/unit/layers/test_dlp.py tests/integration/api/test_dlp_api.py -v
```

### Performance Regression Check
```yaml
- name: Performance Tests
  run: |
    cd GateWayApsix/safellm
    python -m pytest tests/test_dlp_performance.py::TestDLPPerformanceMetrics::test_scan_latency_clean_text -v
    # Check that latency is within acceptable bounds
```

## Troubleshooting

### Common Issues

1. **Presidio Not Installed**
   ```
   ModuleNotFoundError: No module named 'presidio_analyzer'
   ```
   **Solution:** Install Presidio or mock it in tests
   ```bash
   pip install presidio-analyzer
   # OR run with mocks: pytest tests/unit/layers/test_dlp.py::TestDLPErrorHandling::test_fail_open_on_presidio_unavailable
   ```

2. **Metrics Not Available**
   ```
   Tests fail when Prometheus is not configured
   ```
   **Solution:** Tests automatically handle missing metrics (fail gracefully)

3. **Performance Test Variations**
   ```
   Performance tests may vary between runs
   ```
   **Solution:** Use statistical thresholds, run multiple iterations

### Debug Mode
```bash
# Run with detailed output
pytest tests/unit/layers/test_dlp.py -v -s --tb=long

# Run specific failing test
pytest tests/unit/layers/test_dlp.py::TestDLPMetrics::test_metrics_recorded_on_clean_scan -v -s
```

## Coverage Goals

- **Unit Tests**: > 90% coverage of `layers/dlp.py`
- **Integration Tests**: > 95% coverage of `api/dlp.py`
- **Performance Tests**: Key latency and throughput metrics
- **Scenario Tests**: Edge cases and real-world usage patterns

## Future Enhancements

- Add property-based testing with Hypothesis
- Integration with actual Prometheus instance
- Load testing with Locust or similar tools
- Fuzz testing for input validation
- Cross-platform performance comparison