import psutil

def snapshot() -> dict:
    connections = []
    try:
        for c in psutil.net_connections(kind="inet"):
            remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            connections.append({"pid": c.pid, "local": local, "remote": remote, "status": c.status})
    except (psutil.AccessDenied, OSError):
        pass
    return {"count": len(connections), "connections": connections[:30]}
