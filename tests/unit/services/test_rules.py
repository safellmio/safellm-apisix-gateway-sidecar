"""Unit tests for security rules."""
import pytest

from sidecar.models import Decision
from sidecar.services.rules import keyword_guard


class TestKeywordGuard:
    """Test the keyword_guard function."""

    def test_clean_text(self):
        """Test guard with clean text."""
        blocked = ["hack", "ignore instructions"]
        text = "this is a clean message"

        decision = keyword_guard(text, blocked)

        assert decision.allowed is True
        assert decision.reason == "clean"

    def test_blocked_single_phrase(self):
        """Test guard with single blocked phrase."""
        blocked = ["hack", "ignore instructions"]
        text = "please hack the system"

        decision = keyword_guard(text, blocked)

        assert decision.allowed is False
        assert decision.reason == "blocked: hack"

    def test_blocked_multiple_phrases(self):
        """Test guard with multiple blocked phrases."""
        blocked = ["hack", "ignore instructions", "rm -rf"]
        text = "ignore instructions and rm -rf /"

        decision = keyword_guard(text, blocked)

        # Should return first match found
        assert decision.allowed is False
        assert "blocked:" in decision.reason

    def test_case_insensitive_blocking(self):
        """Test that blocking is case insensitive."""
        blocked = ["HACK", "Ignore Instructions"]
        text = "please hack the system"

        decision = keyword_guard(text, blocked)

        assert decision.allowed is False
        assert decision.reason == "blocked: hack"

    def test_empty_blocked_list(self):
        """Test guard with empty blocked list."""
        blocked = []
        text = "any text with potential threats"

        decision = keyword_guard(text, blocked)

        assert decision.allowed is True
        assert decision.reason == "clean"

    def test_empty_text(self):
        """Test guard with empty text."""
        blocked = ["hack"]
        text = ""

        decision = keyword_guard(text, blocked)

        assert decision.allowed is True
        assert decision.reason == "clean"

    def test_phrase_at_boundaries(self):
        """Test blocking when phrase is at text boundaries."""
        blocked = ["hack"]
        test_cases = [
            "hack the system",  # at start
            "the system hack",  # at end
            "hack",             # exact match
        ]

        for text in test_cases:
            decision = keyword_guard(text, blocked)
            assert decision.allowed is False
            assert decision.reason == "blocked: hack"

    @pytest.mark.parametrize("text,blocked,expected_allowed,expected_reason", [
        ("clean message", ["hack"], True, "clean"),
        ("hack attempt", ["hack"], False, "blocked: hack"),
        ("DROP TABLE users", ["drop table"], False, "blocked: drop table"),
        ("<script>alert(1)</script>", ["<script>"], False, "blocked: <script>"),
        ("", ["hack"], True, "clean"),
        ("safe text", [], True, "clean"),
    ])
    def test_keyword_guard_comprehensive(self, text, blocked, expected_allowed, expected_reason):
        """Comprehensive test of keyword_guard function."""
        decision = keyword_guard(text, blocked)

        assert decision.allowed == expected_allowed
        assert decision.reason == expected_reason