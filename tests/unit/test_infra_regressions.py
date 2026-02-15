"""Regression tests for OSS infra bugs (REV-001, REV-004)."""

from pathlib import Path

import yaml


def _repo_root() -> Path:
    return Path(__file__).parent.parent.parent


def test_http_logger_shared_dict_present_in_config():
    config_path = _repo_root() / "config" / "config.yaml"
    assert config_path.exists(), "config.yaml not found"

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    shared_dicts = (
        config.get("nginx_config", {})
        .get("http", {})
        .get("custom_lua_shared_dict", {})
    )
    assert isinstance(shared_dicts, dict), "custom_lua_shared_dict should be a YAML map"
    assert "http-logger" in shared_dicts, "http-logger shared dict is required"


def test_audit_route_uses_http_logger_plugin():
    apisix_path = _repo_root() / "config" / "apisix.yaml"
    assert apisix_path.exists(), "apisix.yaml not found"

    with open(apisix_path, "r") as f:
        apisix = yaml.safe_load(f)

    routes = apisix.get("routes", [])
    audit_route = next(
        (route for route in routes if route.get("id") == "route_protected_dlp_audit"),
        None,
    )
    assert audit_route is not None, "route_protected_dlp_audit should exist"
    assert "http-logger" in audit_route.get("plugins", {}), \
        "route_protected_dlp_audit should configure http-logger"


def test_oss_readiness_probe_targets_guard_health():
    values_path = _repo_root() / "helm" / "safellm-oss" / "values.yaml"
    assert values_path.exists(), "helm/safellm-oss/values.yaml not found"

    with open(values_path, "r") as f:
        values = yaml.safe_load(f)

    liveness = values["livenessProbe"]["httpGet"]["path"]
    readiness = values["readinessProbe"]["httpGet"]["path"]

    assert liveness == "/health", "liveness should stay on /health"
    assert readiness == "/v1/guard/health", "readiness should use guard health"
