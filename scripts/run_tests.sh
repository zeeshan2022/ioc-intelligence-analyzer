#!/usr/bin/env bash
set -e
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
pytest -v --cov=app --cov-report=term-missing
