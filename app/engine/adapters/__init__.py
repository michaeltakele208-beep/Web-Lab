"""Scenario-specific offensive testing adapters package."""

from app.engine.adapters.base import AdapterResult, BaseScenarioAdapter
from app.engine.adapters.headers_adapter import SecurityHeadersAdapter
from app.engine.adapters.idor_adapter import IDORAdapter
from app.engine.adapters.registry import ADAPTER_REGISTRY, get_adapter, get_supported_scenarios
from app.engine.adapters.sqli_adapter import SQLInjectionAdapter
from app.engine.adapters.xss_adapter import XSSAdapter

__all__ = [
    "ADAPTER_REGISTRY",
    "AdapterResult",
    "BaseScenarioAdapter",
    "IDORAdapter",
    "SQLInjectionAdapter",
    "SecurityHeadersAdapter",
    "XSSAdapter",
    "get_adapter",
    "get_supported_scenarios",
]
