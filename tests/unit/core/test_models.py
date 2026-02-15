"""Unit tests for core models."""
import pytest

from sidecar.models import Decision


class TestDecision:
    """Test the Decision dataclass."""

    def test_decision_allowed(self):
        """Test allowed decision returns correct status code."""
        decision = Decision(allowed=True, reason="clean")
        assert decision.allowed is True
        assert decision.reason == "clean"
        assert decision.status_code == 200

    def test_decision_denied(self):
        """Test denied decision returns correct status code."""
        decision = Decision(allowed=False, reason="blocked: hack")
        assert decision.allowed is False
        assert decision.reason == "blocked: hack"
        assert decision.status_code == 403

    def test_decision_equality(self):
        """Test decision equality comparison."""
        d1 = Decision(allowed=True, reason="clean")
        d2 = Decision(allowed=True, reason="clean")
        d3 = Decision(allowed=False, reason="blocked")

        assert d1 == d2
        assert d1 != d3

    def test_decision_slots(self):
        """Test that Decision uses __slots__ for memory efficiency."""
        decision = Decision(allowed=True, reason="test")

        # Should not have __dict__
        assert not hasattr(decision, '__dict__')

        # Should have __slots__
        assert hasattr(Decision, '__slots__')

    @pytest.mark.parametrize("allowed,expected_status", [
        (True, 200),
        (False, 403),
    ])
    def test_decision_status_codes(self, allowed, expected_status):
        """Test all possible status codes."""
        decision = Decision(allowed=allowed, reason="test")
        assert decision.status_code == expected_status