"""Explicit scenario adapter allowlist and lookup registry."""

from app.engine.adapters.base import BaseScenarioAdapter
from app.engine.adapters.headers_adapter import SecurityHeadersAdapter
from app.engine.adapters.idor_adapter import IDORAdapter
from app.engine.adapters.sqli_adapter import SQLInjectionAdapter
from app.engine.adapters.xss_adapter import XSSAdapter

# Explicit allowlist of supported scenario adapters (strictly prevents dynamic code imports)
ADAPTER_REGISTRY: dict[str, type[BaseScenarioAdapter]] = {
    SQLInjectionAdapter.scenario_id: SQLInjectionAdapter,
    XSSAdapter.scenario_id: XSSAdapter,
    IDORAdapter.scenario_id: IDORAdapter,
    SecurityHeadersAdapter.scenario_id: SecurityHeadersAdapter,
}


def get_adapter(scenario_id: str) -> BaseScenarioAdapter | None:
    """Instantiate and return the scenario adapter matching the scenario ID."""
    adapter_cls = ADAPTER_REGISTRY.get(scenario_id)
    if adapter_cls:
        return adapter_cls()
    return None


def get_supported_scenarios() -> list[str]:
    """Return list of supported scenario identifiers."""
    return list(ADAPTER_REGISTRY.keys())
