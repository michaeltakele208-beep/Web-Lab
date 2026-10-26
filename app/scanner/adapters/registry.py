"""Registry of approved security scanner adapters (Phase 6)."""

from app.scanner.adapters.bandit_adapter import BanditAdapter
from app.scanner.adapters.base import BaseScannerAdapter
from app.scanner.adapters.pip_audit_adapter import PipAuditAdapter
from app.scanner.adapters.zap_adapter import ZapAdapter
from app.scanner.semantics import ScannerType

# Explicit allowlist of authorized scanner adapters
_SCANNER_REGISTRY: dict[ScannerType, type[BaseScannerAdapter]] = {
    ScannerType.BANDIT: BanditAdapter,
    ScannerType.PIP_AUDIT: PipAuditAdapter,
    ScannerType.ZAP: ZapAdapter,
}


def get_scanner_adapter(scanner_type: str | ScannerType) -> BaseScannerAdapter:
    """Resolve and instantiate a registered scanner adapter."""
    try:
        resolved_type = ScannerType(scanner_type)
    except ValueError:
        raise ValueError(
            f"Scanner '{scanner_type}' is not in the approved scanner allowlist."
        ) from None

    adapter_cls = _SCANNER_REGISTRY.get(resolved_type)
    if not adapter_cls:
        raise ValueError(f"No adapter implementation registered for scanner '{scanner_type}'.")

    return adapter_cls()


def get_all_scanners() -> list[dict]:
    """Retrieve availability and version details for all registered scanners."""
    results = []
    for s_type in ScannerType:
        adapter = get_scanner_adapter(s_type)
        is_avail, version, reason = adapter.detect_availability()
        results.append(
            {
                "scanner_type": s_type.value,
                "is_available": is_avail,
                "version": version,
                "unavailable_reason": reason,
            }
        )
    return results
