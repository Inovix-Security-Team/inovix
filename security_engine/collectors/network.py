import psutil

from security_engine.collectors.base import Collector
from security_engine.monitoring_events import MonitoringEvent


class NetworkCollector(Collector):
    """Collect basic network connection telemetry."""

    def collect(self) -> list[MonitoringEvent]:
        """Collect currently available network connections."""

        events = []

        try:
            connections = psutil.net_connections(kind="inet")

        except (psutil.AccessDenied, OSError):
            return events

        for connection in connections:
            try:
                local_address = (
                    f"{connection.laddr.ip}:{connection.laddr.port}"
                    if connection.laddr
                    else None
                )

                remote_address = (
                    f"{connection.raddr.ip}:{connection.raddr.port}"
                    if connection.raddr
                    else None
                )

                event = MonitoringEvent(
                    event_type="network",
                    source="network_monitor",
                    data={
                        "local_address": local_address,
                        "remote_address": remote_address,
                        "status": connection.status,
                        "pid": connection.pid,
                    },
                )

                events.append(event)

            except (AttributeError, OSError):
                continue

        return events