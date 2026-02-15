#!/usr/bin/env python3
"""Test runner script for SafeLLM."""
import subprocess
import sys
import argparse
from pathlib import Path


def run_command(cmd, description):
    """Run a command and return success status."""
    print(f"\n🔍 Running: {description}")
    print(f"📝 Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, cwd=Path(__file__).parent)
        if result.returncode == 0:
            print(f"✅ {description} - PASSED")
            return True
        else:
            print(f"❌ {description} - FAILED")
            return False
    except Exception as e:
        print(f"❌ {description} - ERROR: {e}")
        return False


def main():
    """Main test runner."""
    parser = argparse.ArgumentParser(description="SafeLLM Test Runner")
    parser.add_argument(
        "--type",
        choices=["unit", "integration", "e2e", "e2e-no-docker", "http-limits", "concurrency", "failure-modes", "security", "comprehensive", "all"],
        default="all",
        help="Type of tests to run (e2e includes Docker tests, e2e-no-docker excludes them)"
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Generate coverage report"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    print("🚀 SafeLLM Test Suite")
    print("=" * 50)

    # Base pytest command
    base_cmd = [sys.executable, "-m", "pytest"]

    if args.verbose:
        base_cmd.append("-v")

    if args.coverage:
        base_cmd.extend([
            "--cov=sidecar/api",
            "--cov-report=term-missing",
            "--cov-report=html:htmlcov_api"
        ])

    success = True

    # Run tests based on type
    if args.type in ["unit", "all"]:
        cmd = base_cmd + ["-m", "unit"]
        success &= run_command(cmd, "Unit Tests")

    if args.type in ["integration", "all"]:
        cmd = base_cmd + ["-m", "integration"]
        success &= run_command(cmd, "Integration Tests")

    if args.type in ["http-limits", "all"]:
        cmd = base_cmd + ["tests/e2e/test_http_limits.py"]
        success &= run_command(cmd, "HTTP Limits Tests")

    if args.type in ["concurrency", "all"]:
        cmd = base_cmd + ["tests/e2e/test_concurrency_scaling.py"]
        success &= run_command(cmd, "Concurrency & Scaling Tests")

    if args.type in ["failure-modes", "all"]:
        cmd = base_cmd + ["tests/e2e/test_failure_modes.py"]
        success &= run_command(cmd, "Failure Modes Tests")

    if args.type in ["security", "all"]:
        cmd = base_cmd + ["tests/integration/test_end_to_end_flow.py"]
        success &= run_command(cmd, "Security Integration Tests")

    if args.type == "e2e-no-docker":
        # Run all E2E tests except Docker-dependent ones
        test_files = [
            "tests/e2e/test_http_limits.py",
            "tests/e2e/test_concurrency_scaling.py",
            "tests/e2e/test_failure_modes.py",
            "tests/integration/test_end_to_end_flow.py"
        ]

        for test_file in test_files:
            cmd = base_cmd + [test_file]
            test_name = test_file.split("/")[-1].replace(".py", "").replace("test_", "").replace("_", " ").title()
            success &= run_command(cmd, f"{test_name} Tests")

    if args.type == "comprehensive":
        cmd = base_cmd + ["tests/comprehensive_security_test.py"]
        success &= run_command(cmd, "Comprehensive Security Tests")

    if args.type == "e2e":
        print("\n⚠️  Full E2E tests require Docker services to be running!")
        print("   Run: docker compose up -d")
        print("   Then run: python run_tests.py --type e2e")
        print("   For tests without Docker, use: --type e2e-no-docker")

        cmd = base_cmd + ["-m", "e2e"]
        success &= run_command(cmd, "Full End-to-End Tests (with Docker)")

    print("\n" + "=" * 50)
    if success:
        print("🎉 All tests passed!")
        return 0
    else:
        print("💥 Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
