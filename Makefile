# SafeLLM Development Makefile

.PHONY: help test test-unit test-integration test-e2e test-all coverage lint format clean docker-up docker-down install install-dev

# Default target
help:
	@echo "SafeLLM Development Commands:"
	@echo ""
	@echo "Testing:"
	@echo "  test-unit         Run unit tests"
	@echo "  test-integration  Run integration tests"
	@echo "  test-e2e          Run end-to-end tests (requires Docker)"
	@echo "  test-all          Run all tests"
	@echo "  coverage          Run tests with coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint              Run linting (flake8)"
	@echo "  format            Format code (black + isort)"
	@echo ""
	@echo "Docker:"
	@echo "  docker-up         Start Docker services"
	@echo "  docker-down       Stop Docker services"
	@echo ""
	@echo "Installation:"
	@echo "  install           Install production dependencies"
	@echo "  install-dev       Install development dependencies"
	@echo ""
	@echo "Utilities:"
	@echo "  clean             Clean up temporary files"

# Testing targets
test-unit:
	pytest -m unit -v

test-integration:
	pytest -m integration -v

test-e2e: docker-up
	@echo "Waiting for services to start..."
	@sleep 10
	pytest -m e2e -v --tb=short

test-all: test-unit test-integration test-e2e

coverage:
	pytest --cov=sidecar --cov-report=term-missing --cov-report=html:htmlcov --cov-fail-under=80

coverage-api:
	pytest --cov=sidecar/api --cov-report=term-missing --cov-report=html:htmlcov_api

# Code quality
lint:
	flake8 sidecar tests
	mypy sidecar

format:
	black sidecar tests
	isort sidecar tests

# Docker targets
docker-up:
	docker compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 5

docker-down:
	docker compose down

# Installation
install:
	pip install -e .

install-dev:
	pip install -e . && pip install -r requirements-dev.txt

# Cleanup
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .coverage htmlcov .pytest_cache
	rm -rf test_env/ *_env/

# Quick development setup
setup: install-dev docker-up
	@echo "Development environment ready!"
	@echo "Run 'make test-unit' to verify setup"
