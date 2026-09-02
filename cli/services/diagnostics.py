import importlib
import importlib.metadata
import os
import socket
import sys
from pathlib import Path

from cli.models.diagnostics import DiagnosticResult, DiagnosticStatus


class DiagnosticsService:

    def check_python(self):
        version = sys.version.split()[0]

        if sys.version_info >= (3, 10):
            return DiagnosticResult(
                name="Python",
                status=DiagnosticStatus.PASS,
                message=f"Python {version}",
            )

        return DiagnosticResult(
            name="Python",
            status=DiagnosticStatus.WARN,
            message=f"Python {version} may be unsupported",
        )

    def check_dependency(self, package_name):
        try:
            version = importlib.metadata.version(package_name)

            return DiagnosticResult(
                name=f"Dependency: {package_name}",
                status=DiagnosticStatus.PASS,
                message=f"installed ({version})",
            )

        except importlib.metadata.PackageNotFoundError:
            return DiagnosticResult(
                name=f"Dependency: {package_name}",
                status=DiagnosticStatus.FAIL,
                message="NOT INSTALLED",
            )

    def check_import(self, name, module_name):
        try:
            importlib.import_module(module_name)

            return DiagnosticResult(
                name=name,
                status=DiagnosticStatus.PASS,
                message="AVAILABLE",
            )

        except Exception as exc:
            return DiagnosticResult(
                name=name,
                status=DiagnosticStatus.FAIL,
                message="UNAVAILABLE",
                details=str(exc),
            )

    def check_directory(self, name, path):
        if not path.exists():
            return DiagnosticResult(
                name=name,
                status=DiagnosticStatus.FAIL,
                message="NOT FOUND",
            )

        if not path.is_dir():
            return DiagnosticResult(
                name=name,
                status=DiagnosticStatus.FAIL,
                message="NOT A DIRECTORY",
            )

        if not os.access(path, os.R_OK):
            return DiagnosticResult(
                name=name,
                status=DiagnosticStatus.FAIL,
                message="NOT READABLE",
            )

        return DiagnosticResult(
            name=name,
            status=DiagnosticStatus.PASS,
            message="AVAILABLE",
        )

    def check_network(self, timeout=2.0):
        try:
            connection = socket.create_connection(
                ("example.com", 443),
                timeout=timeout,
            )

            connection.close()

            return DiagnosticResult(
                name="Internet",
                status=DiagnosticStatus.PASS,
                message="ONLINE",
            )

        except OSError:
            return DiagnosticResult(
                name="Internet",
                status=DiagnosticStatus.WARN,
                message="OFFLINE",
            )

    def check_storage(self, path):
        if not path.exists():
            return DiagnosticResult(
                name="Local Storage",
                status=DiagnosticStatus.WARN,
                message="NOT CONFIGURED",
            )

        if not os.access(path, os.R_OK | os.W_OK):
            return DiagnosticResult(
                name="Local Storage",
                status=DiagnosticStatus.FAIL,
                message="NOT ACCESSIBLE",
            )

        return DiagnosticResult(
            name="Local Storage",
            status=DiagnosticStatus.PASS,
            message="AVAILABLE",
        )

    def run(self):
        results = []

        results.append(self.check_python())

        # Temporary dependency check
        results.append(self.check_dependency("pytest"))

        project_root = Path(__file__).resolve().parents[2]

        directories = {
            "CLI": project_root / "cli",
            "Tests": project_root / "tests",
        }

        for name, path in directories.items():
            results.append(
                self.check_directory(name, path)
            )

        results.append(self.check_network())

        storage_path = project_root / "storage"

        results.append(
            self.check_storage(storage_path)
        )

        return results