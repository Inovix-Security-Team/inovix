import platform
import socket
import time
import psutil

_STARTED = time.time()

def snapshot() -> dict:
    net = psutil.net_io_counters()
    return {
        "cpu": psutil.cpu_percent(interval=None),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage("/").percent,
        "net_in": net.bytes_recv,
        "net_out": net.bytes_sent,
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "uptime": int(time.time() - _STARTED),
        "processes": len(psutil.pids()),
    }
