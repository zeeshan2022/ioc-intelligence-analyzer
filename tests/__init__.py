"""Test suite for ioc-intelligence-analyzer.

Layout
------
* ``tests/unit``        - isolated unit tests (no network, no filesystem deps)
* ``tests/integration`` - full-pipeline tests with mocked HTTP transport

All tests are hermetic: **no test ever performs a real network call.** The
``no_network`` autouse fixture in ``conftest.py`` enforces this at runtime by
patching the socket layer.
"""
