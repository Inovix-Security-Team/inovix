import psutil

def snapshot(limit: int = 15) -> list[dict]:
    rows = []
    for proc in psutil.process_iter(["pid", "name", "memory_percent"]):
        try:
            rows.append({
                "pid": proc.info["pid"],
                "name": proc.info["name"] or "unknown",
                "memory": proc.info["memory_percent"] or 0,
                "cpu": proc.cpu_percent(interval=None),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(rows, key=lambda x: x["cpu"], reverse=True)[:limit]
