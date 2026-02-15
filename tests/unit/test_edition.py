"""
Tests for edition management - OSS-only build behavior.
"""
import os
from unittest.mock import patch

import pytest

from sidecar.edition import (
    EDITION, FEATURES, is_feature_available, get_edition,
    get_available_features, get_edition_info
)


class TestEditionManagement:
    """Test OSS-only edition behavior."""

    def test_default_edition_is_oss(self):
        """Default edition should always be OSS."""
        assert EDITION == "oss"

    def test_env_var_enterprise_is_ignored(self):
        """Enterprise env var should be ignored in OSS build."""
        with patch.dict(os.environ, {"SAFELLM_EDITION": "enterprise"}):
            import importlib
            import sidecar.edition
            importlib.reload(sidecar.edition)
            assert sidecar.edition.EDITION == "oss"

    def test_get_edition_returns_oss(self):
        """get_edition returns oss."""
        assert get_edition() == "oss"

    def test_oss_feature_matrix(self):
        """OSS edition feature availability."""
        assert is_feature_available("pii_fast_regex") is True
        assert is_feature_available("dlp_audit_mode") is True
        assert is_feature_available("prometheus_metrics") is True

        assert is_feature_available("pii_gliner") is False
        assert is_feature_available("ai_guard") is False
        assert is_feature_available("distributed_coalescer") is False
        assert is_feature_available("redis_sentinel") is False
        assert is_feature_available("dlp_block_mode") is False
        assert is_feature_available("audit_logs") is False

    def test_unknown_feature_returns_false(self):
        """Unknown features return False."""
        assert is_feature_available("unknown_feature") is False
        assert is_feature_available("") is False

    def test_get_available_features_oss(self):
        """get_available_features returns OSS-only features."""
        available = get_available_features()
        expected = ["pii_fast_regex", "dlp_audit_mode", "prometheus_metrics"]
        assert set(available) == set(expected)

    def test_get_edition_info_structure(self):
        """get_edition_info returns correct structure."""
        info = get_edition_info()
        assert info["edition"] == "oss"
        assert isinstance(info["features"], list)
        assert isinstance(info["all_features"], dict)

    def test_features_dict_has_only_oss(self):
        """FEATURES should only include oss in OSS build."""
        assert set(FEATURES.keys()) == {"oss"}
