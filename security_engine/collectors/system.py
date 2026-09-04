import platform
import socket
import time

import psutil

from security_engine.collectors.base import Collector
from security_engine.monitoring_events import MonitoringEvent


class SystemCollector(Collector):
    """Collect basic system telemetry."""

    def collect(self) -> MonitoringEvent:
        """Collect current system information."""

        return MonitoringEvent(
            event_type="system",
            source="system_monitor",
            data={
                "cpu_percent": psutil.cpu_percent(interval=None),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage("/").percent,
                "uptime_seconds": int(
                    time.time() - psutil.boot_time()
                ),
                "hostname": socket.gethostname(),
                "os": platform.system(),
            },
        )