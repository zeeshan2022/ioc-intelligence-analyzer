"""Unit tests for configuration, secrets management and structured logging."""

from __future__ import annotations

import json
import logging

import pytest

from app.core.config import AppConfig, ConnectorSettings, _redact, validate_env_var_name
from app.core.logging import JsonFormatter, RedactingFormatter, redact, setup_logging

pytestmark = pytest.mark.unit


class TestAppConfig:
    def test_from_env_reads_keys(self, monkeypatch) -> None:
        monkeypatch.setenv("VT_API_KEY", "vt-123")
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "aidb-456")
        monkeypatch.setenv("GREYNOISE_API_KEY", "gn-789")
        config = AppConfig.from_env()
        assert config.vt_api_key == "vt-123"
        assert config.abuseipdb_api_key == "aidb-456"
        assert config.greynoise_api_key == "gn-789"
        assert config.has_any_provider_key() is True

    def test_empty_string_env_treated_as_unset(self, monkeypatch) -> None:
        monkeypatch.setenv("VT_API_KEY", "")
        assert AppConfig.from_env().vt_api_key is None
        assert AppConfig.from_env().has_any_provider_key() is False

    def test_invalid_log_level_falls_back_to_info(self, monkeypatch) -> None:
        monkeypatch.setenv("IOC_LOG_LEVEL", "NOT-A-LEVEL")
        assert AppConfig.from_env().log_level == "INFO"

    def test_numeric_tuning_parsing(self, monkeypatch) -> None:
        monkeypatch.setenv("IOC_TIMEOUT_SECONDS", "8.5")
        monkeypatch.setenv("IOC_MAX_RETRIES", "5")
        monkeypatch.setenv("IOC_BACKOFF_FACTOR", "0.1")
        config = AppConfig.from_env()
        assert config.connectors.timeout_seconds == 8.5
        assert config.connectors.max_retries == 5
        assert config.connectors.backoff_factor == pytest.approx(0.1)

    def test_negative_timeouts_rejected(self, monkeypatch) -> None:
        monkeypatch.setenv("IOC_TIMEOUT_SECONDS", "-5")
        assert AppConfig.from_env().connectors.timeout_seconds == 15.0

    def test_offline_flag_parsing(self, monkeypatch) -> None:
        monkeypatch.setenv("IOC_OFFLINE", "yes")
        assert AppConfig.from_env().offline_mode is True

    def test_config_is_frozen(self) -> None:
        config = AppConfig()
        with pytest.raises(Exception):
            config.offline_mode = True  # type: ignore[misc]

    def test_repr_never_leaks_secrets(self) -> None:
        config = AppConfig(vt_api_key="ABCDEF123456789")
        assert "ABCDEF123456789" not in repr(config)

    def test_redact_helpers(self) -> None:
        assert _redact(None) == "<unset>"
        assert _redact("") == "<unset>"
        assert _redact("ab") == "****"
        masked = _redact("abcdefghijklmnop")
        assert masked.startswith("ab") and masked.endswith("op") and "*" in masked

    def test_env_name_validator(self) -> None:
        assert validate_env_var_name("VT_API_KEY")
        assert not validate_env_var_name("lower_case")
        assert not validate_env_var_name("1INVALID")

    def test_dotenv_file_loading(self, tmp_path, monkeypatch) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("VT_API_KEY=from-dotenv-file\nIOC_LOG_LEVEL=DEBUG\n", encoding="utf-8")
        monkeypatch.delenv("VT_API_KEY", raising=False)
        config = AppConfig.from_env(env_file=env_file)
        assert config.vt_api_key == "from-dotenv-file"
        assert config.log_level == "DEBUG"


class TestLogging:
    def test_setup_is_idempotent(self) -> None:
        import app.core.logging as logging_module

        logging_module._CONFIGURED = False
        logging.getLogger("ioc_analyzer").handlers.clear()
        setup_logging(level="INFO")
        first = len(logging.getLogger("ioc_analyzer").handlers)
        setup_logging(level="INFO")
        assert len(logging.getLogger("ioc_analyzer").handlers) == first
        logging_module._CONFIGURED = False
        logging.getLogger("ioc_analyzer").handlers.clear()

    def test_json_formatter_output_shape(self) -> None:
        record = logging.LogRecord(
            name="ioc.test", level=logging.INFO, pathname=__file__, lineno=1,
            msg="analysis complete for %s", args=("8.8.8.8",), exc_info=None,
        )
        payload = json.loads(JsonFormatter().format(record))
        assert payload["logger"] == "ioc.test"
        assert payload["level"] == "INFO"
        assert "8.8.8.8" in payload["message"]
        assert "timestamp" in payload

    def test_redacting_formatter_masks_api_keys(self) -> None:
        record = logging.LogRecord(
            name="ioc.test", level=logging.ERROR, pathname=__file__, lineno=1,
            msg="request failed x-apikey: SUPERSECRETVTTOKEN123", args=None, exc_info=None,
        )
        formatted = RedactingFormatter("%(message)s").format(record)
        assert "SUPERSECRETVTTOKEN123" not in formatted

    def test_redact_function_patterns(self) -> None:
        assert "MYABUSEKEY" not in redact("Key: MYABUSEKEY123456")
        assert "hunter0" not in redact("password=hunter0")
        assert "Bearer abcdef" not in redact("Authorization: Bearer abcdef123456")
        # Ordinary analyst text passes through untouched.
        assert redact("analysed 8.8.8.8 with 3 providers") == "analysed 8.8.8.8 with 3 providers"

    def test_rotating_file_handler_created(self, tmp_path) -> None:
        import app.core.logging as logging_module

        log_file = tmp_path / "logs" / "app.log"
        logging_module._CONFIGURED = False
        logging.getLogger("ioc_analyzer").handlers.clear()
        setup_logging(level="INFO", log_file=log_file)
        logger = logging.getLogger("ioc_analyzer")
        from logging.handlers import RotatingFileHandler

        assert any(isinstance(h, RotatingFileHandler) for h in logger.handlers)
        logging_module._CONFIGURED = False
        logger.handlers.clear()


class TestConnectorSettings:
    def test_defaults_are_conservative(self) -> None:
        settings = ConnectorSettings()
        assert 1 <= settings.timeout_seconds <= 60
        assert 1 <= settings.max_retries <= 10
        assert settings.backoff_factor > 0
