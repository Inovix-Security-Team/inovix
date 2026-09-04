from abc import ABC, abstractmethod

from security_engine.monitoring_events import MonitoringEvent


class Collector(ABC):
    """Base interface for all monitoring collectors."""

    def __init__(self) -> None:
        self._running = False

    @abstractmethod
    def collect(self) -> list[MonitoringEvent]:
        """Collect and return standardized monitoring events."""

    def start(self) -> None:
        """Mark the collector as running."""

        self._running = True

    def stop(self) -> None:
        """Mark the collector as stopped."""

        self._running = False

    def status(self) -> str:
        """Return the current collector status."""

        return "RUNNING" if self._running else "STOPPED"