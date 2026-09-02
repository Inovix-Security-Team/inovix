from cli.models.diagnostics import DiagnosticStatus
from cli.services.diagnostics import DiagnosticsService


def _status_symbol(status: DiagnosticStatus) -> str:
    if status == DiagnosticStatus.PASS:
        return "[OK]"

    if status == DiagnosticStatus.WARN:
        return "[WARN]"

    return "[FAIL]"


def run_doctor() -> int:
    print()
    print("=" * 55)
    print("                    INOVIX")
    print("               SYSTEM DIAGNOSTICS")
    print("=" * 55)

    service = DiagnosticsService()
    results = service.run()

    for result in results:
        symbol = _status_symbol(result.status)

        print(
            f"{symbol} {result.name:<25} {result.message}"
        )

        if result.details:
            print(f"      Reason: {result.details}")

    has_failures = any(
        result.status == DiagnosticStatus.FAIL
        for result in results
    )

    has_warnings = any(
        result.status == DiagnosticStatus.WARN
        for result in results
    )

    print("-" * 55)

    if has_failures:
        overall_status = "NOT READY"
    else:
        overall_status = "READY"

    if has_warnings and not has_failures:
        mode = "OFFLINE / DEGRADED"
    else:
        mode = "ONLINE"

    print(f"Overall Status: {overall_status}")
    print(f"Mode: {mode}")
    print("-" * 55)

    return 1 if has_failures else 0