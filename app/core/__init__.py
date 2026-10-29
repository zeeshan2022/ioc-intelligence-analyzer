"""Core domain layer: configuration, logging, models and the IOC validator.

This package has no dependency on any delivery mechanism (CLI/API/UI), which
keeps the domain reusable across Release 1 (CLI) and later releases (FastAPI,
Streamlit).
"""

from app.core.ioc import IOCType, ValidatedIOC, validate_ioc, validate_many
from app.core.models import (
    AnalysisResult,
    EnrichmentResult,
    ProviderStatus,
    RiskAssessment,
    RiskLevel,
)

__all__ = [
    "AnalysisResult",
    "EnrichmentResult",
    "IOCType",
    "ProviderStatus",
    "RiskAssessment",
    "RiskLevel",
    "ValidatedIOC",
    "validate_ioc",
    "validate_many",
]
