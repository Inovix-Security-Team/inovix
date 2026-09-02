from unittest.mock import patch

from cli.models.diagnostics import DiagnosticStatus
from cli.services.diagnostics import DiagnosticsService


def test_python_check():
    service = DiagnosticsService()

    result = service.check_python()

    assert result.status in (
        DiagnosticStatus.PASS,
        DiagnosticStatus.WARN,
    )


def test_dependency_installed():
    service = DiagnosticsService()

    result = service.check_dependency("pytest")

    assert result.status == DiagnosticStatus.PASS


def test_dependency_missing():
    service = DiagnosticsService()

    result = service.check_dependency(
        "package_that_does_not_exist_12345"
    )

    assert result.status == DiagnosticStatus.FAIL


def test_import_available():
    service = DiagnosticsService()

    result = service.check_import(
        "Python",
        "sys",
    )

    assert result.status == DiagnosticStatus.PASS


def test_import_unavailable():
    service = DiagnosticsService()

    result = service.check_import(
        "Fake Module",
        "module_that_does_not_exist_12345",
    )

    assert result.status == DiagnosticStatus.FAIL


def test_directory_available(tmp_path):
    service = DiagnosticsService()

    result = service.check_directory(
        "Test Directory",
        tmp_path,
    )

    assert result.status == DiagnosticStatus.PASS


def test_directory_missing(tmp_path):
    service = DiagnosticsService()

    missing_path = tmp_path / "does_not_exist"

    result = service.check_directory(
        "Test Directory",
        missing_path,
    )

    assert result.status == DiagnosticStatus.FAIL


def test_network_available():
    service = DiagnosticsService()

    with patch(
        "cli.services.diagnostics.socket.create_connection"
    ) as mock_connection:

        mock_connection.return_value.close.return_value = None

        result = service.check_network()

        assert result.status == DiagnosticStatus.PASS


def test_network_unavailable():
    service = DiagnosticsService()

    with patch(
        "cli.services.diagnostics.socket.create_connection"
    ) as mock_connection:

        mock_connection.side_effect = OSError(
            "Network unavailable"
        )

        result = service.check_network()

        assert result.status == DiagnosticStatus.WARN


def test_storage_available(tmp_path):
    service = DiagnosticsService()

    result = service.check_storage(tmp_path)

    assert result.status == DiagnosticStatus.PASS


def test_storage_missing(tmp_path):
    service = DiagnosticsService()

    missing_path = tmp_path / "storage"

    result = service.check_storage(missing_path)

    assert result.status == DiagnosticStatus.WARN


def test_run():
    service = DiagnosticsService()

    with patch(
        "cli.services.diagnostics.socket.create_connection"
    ) as mock_connection:

        mock_connection.return_value.close.return_value = None

        results = service.run()

    assert isinstance(results, list)
    assert len(results) > 0

    for result in results:
        assert result.status in (
            DiagnosticStatus.PASS,
            DiagnosticStatus.WARN,
            DiagnosticStatus.FAIL,
        )