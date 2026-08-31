import psutil

from security_engine.collectors.base import Collector
from security_engine.monitoring_events import MonitoringEvent


class ProcessCollector(Collector):
    """Collect basic information about running processes."""

    def collect(self) -> list[MonitoringEvent]:
        """Collect running process information as standardized events."""

        events = []

        try:
            processes = psutil.process_iter(
                [
                    "pid",
                    "name",
                    "username",
                    "ppid",
                    "create_time",
                    "memory_percent",
                ]
            )

            for proc in processes:
                try:
                    events.append(
                        MonitoringEvent(
                            event_type="process",
                            source="process_monitor",
                            data={
                                "pid": proc.info["pid"],
                                "name": proc.info["name"] or "unknown",
                                "username": proc.info["username"],
                                "cpu_percent": proc.cpu_percent(
                                    interval=None
                                ),
                                "memory_percent": (
                                    proc.info["memory_percent"] or 0.0
                                ),
                                "parent_pid": proc.info["ppid"],
                                "create_time": (
                                    proc.info["create_time"]
                                ),
                            },
                        )
                    )

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                ):
                    continue

        except (
            psutil.AccessDenied,
            OSError,
        ):
            return []

        return events